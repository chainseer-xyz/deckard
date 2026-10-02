package sets

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check/dns/takeover"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/refdata"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// upstream replays the recorded fixtures for every real source URL.
type upstream struct {
	mu     sync.Mutex
	bodies map[string]string // "host/path" -> body
	etags  map[string]string
	hits   map[string]int
	down   bool
	srv    *httptest.Server
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{bodies: map[string]string{}, etags: map[string]string{}, hits: map[string]int{}}
	sc := "../../scope/testdata/"
	u.bodies["www.cloudflare.com/ips-v4"] = read(t, sc+"cloudflare-ips-v4.txt")
	u.bodies["www.cloudflare.com/ips-v6"] = read(t, sc+"cloudflare-ips-v6.txt")
	u.bodies["ip-ranges.amazonaws.com/ip-ranges.json"] = read(t, sc+"aws-ip-ranges.json")
	u.bodies["api.fastly.com/public-ip-list"] = read(t, sc+"fastly-public-ip-list.json")
	u.bodies["api.github.com/meta"] = read(t, sc+"github-meta.json")
	u.bodies["raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"] =
		read(t, "../../check/dns/takeover/testdata/community_fingerprints.json")
	for k := range u.bodies {
		u.etags[k] = `"v1"`
	}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		defer u.mu.Unlock()
		key := r.Host + r.URL.Path
		u.hits[key]++
		if u.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		body, ok := u.bodies[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if et := u.etags[key]; et != "" {
			if r.Header.Get("If-None-Match") == et {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", et)
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) set(key, body, etag string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.bodies[key], u.etags[key] = body, etag
}

// client sends every request to the fake upstream, keeping the Host header so
// it can tell the sources apart.
func (u *upstream) client() *http.Client {
	target, _ := url.Parse(u.srv.URL)
	base := u.srv.Client().Transport.(*http.Transport).Clone()
	return &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		r2 := r.Clone(r.Context())
		r2.Host = r.URL.Host
		r2.URL.Host = target.Host
		return base.RoundTrip(r2)
	})}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type rec struct {
	mu      sync.Mutex
	results []string
}

func (r *rec) ObserveRefdata(d, res string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = append(r.results, d+":"+res)
}
func (r *rec) SetRefdataState(string, int, time.Time) {}

// Fixtures are far smaller than the real embedded snapshots, so give the
// shrink guard a fixture-sized baseline.
func init() {
	embeddedTakeoverSourced = func() int { return 20 }
	embeddedSharedSourced = func() int { return 40 }
}

func setup(t *testing.T, u *upstream, dir string) (*refdata.Manager, *scope.Guard, *rec) {
	t.Helper()
	g, err := scope.NewGuard(config.ScopeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	rc := &rec{}
	m, err := Build(Config{
		Dir: dir, Takeover: true, Shared: true, Guard: g, Client: u.client(), Rec: rc,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Backoff: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	return m, g, rc
}

func outcomes(res []refdata.Result) string {
	var s []string
	for _, r := range res {
		s = append(s, r.Dataset+"="+r.Outcome)
	}
	return strings.Join(s, ",")
}

func TestFullRefreshFlowAndPersistence(t *testing.T) {
	u := newUpstream(t)
	dir := t.TempDir()
	m, g, _ := setup(t, u, dir)

	// Before refresh: S3 range is not shared; the community-only provider is unknown.
	const s3ip = "45.45.45.9"
	if got := g.Classify(model.KindIP, s3ip); got != model.ScopeExternal {
		t.Fatalf("precondition: %s", got)
	}
	// Simulate an older binary whose embedded data lacks the community entries.
	takeover.SetFingerprints(takeover.Curated())
	if takeover.MatchCNAME(takeover.Fingerprints(), "x.agilecrm.com") != nil {
		t.Fatal("precondition: agilecrm unknown before refresh")
	}

	res, err := m.RefreshAll(t.Context())
	if err != nil || outcomes(res) != "takeover_fingerprints=ok,shared_ranges=ok" {
		t.Fatalf("res=%s err=%v", outcomes(res), err)
	}
	if got := g.Classify(model.KindIP, s3ip); got != model.ScopeShared {
		t.Errorf("refreshed S3 range: %s", got)
	}
	if got := g.Classify(model.KindIP, "35.180.1.1"); got != model.ScopeExternal {
		t.Errorf("EC2 address must stay external/ownable: %s", got)
	}
	if fp := takeover.MatchCNAME(takeover.Fingerprints(), "x.agilecrm.com"); fp == nil || fp.Provider != "Agile CRM" {
		t.Errorf("refreshed provider not live: %+v", fp)
	}
	// Curated entries keep their default_cert lists and win on conflicts.
	if fp := takeover.MatchCNAME(takeover.Fingerprints(), "d1.cloudfront.net"); fp == nil || len(fp.DefaultCert) == 0 {
		t.Errorf("curated CloudFront entry lost: %+v", fp)
	}
	for _, name := range Names {
		if _, err := os.Stat(filepath.Join(dir, name+".json")); err != nil {
			t.Errorf("not persisted: %v", err)
		}
	}

	// Second refresh: every source answers 304.
	res, err = m.RefreshAll(t.Context())
	if err != nil || outcomes(res) != "takeover_fingerprints=unchanged,shared_ranges=unchanged" {
		t.Fatalf("res=%s err=%v", outcomes(res), err)
	}

	// Restart while offline: persisted data is applied before any network.
	u.mu.Lock()
	u.down = true
	u.mu.Unlock()
	m2, g2, _ := setup(t, u, dir)
	if got := g2.Classify(model.KindIP, s3ip); got != model.ScopeShared {
		t.Errorf("persisted ranges not applied at startup: %s", got)
	}
	res, err = m2.RefreshAll(t.Context())
	if err == nil || outcomes(res) != "takeover_fingerprints=error,shared_ranges=error" {
		t.Fatalf("offline: res=%s err=%v", outcomes(res), err)
	}
	if got := g2.Classify(model.KindIP, s3ip); got != model.ScopeShared {
		t.Errorf("failed refresh must keep data: %s", got)
	}
}

func TestOfflineFallsBackToEmbedded(t *testing.T) {
	u := newUpstream(t)
	u.down = true
	_, g, _ := setup(t, u, t.TempDir())
	if got := g.Classify(model.KindIP, "104.16.0.1"); got != model.ScopeShared {
		t.Errorf("embedded ranges: %s", got)
	}
	if takeover.MatchCNAME(takeover.Fingerprints(), "x.github.io") == nil {
		t.Error("embedded fingerprints unavailable")
	}
}

func TestPoisonedAndTruncatedDocumentsRejected(t *testing.T) {
	u := newUpstream(t)
	m, g, _ := setup(t, u, t.TempDir())
	if res, err := m.RefreshAll(t.Context()); err != nil {
		t.Fatalf("%s %v", outcomes(res), err)
	}
	const s3ip = "45.45.45.9"

	comm := "raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
	trunc := `[{"service":"Only One","status":"Vulnerable","cname":["only.example.net"],"fingerprint":"a long enough fingerprint"}]`
	u.set(comm, trunc, `"v2"`)
	u.set("ip-ranges.amazonaws.com/ip-ranges.json", `{"prefixes":[{"ip_prefix":"35.180.0.0/16","service":"EC2"}]}`, `"v2"`)
	u.set("api.fastly.com/public-ip-list", `<html>oops</html>`, `"v2"`)

	res, err := m.RefreshAll(t.Context())
	if err != nil {
		t.Fatalf("rejections are not job errors: %v", err)
	}
	if outcomes(res) != "takeover_fingerprints=rejected,shared_ranges=rejected" {
		t.Fatalf("res=%s", outcomes(res))
	}
	if got := g.Classify(model.KindIP, s3ip); got != model.ScopeShared {
		t.Errorf("good ranges lost to a poisoned download: %s", got)
	}
	if got := g.Classify(model.KindIP, "35.180.1.1"); got != model.ScopeExternal {
		t.Errorf("EC2 range poisoned in as shared: %s", got)
	}
	if takeover.MatchCNAME(takeover.Fingerprints(), "x.agilecrm.com") == nil {
		t.Error("fingerprints lost to a truncated download")
	}
}

func TestEmptyAndGarbageDocumentsRejected(t *testing.T) {
	for name, body := range map[string]string{"empty list": "[]", "invalid json": "{[", "html": "<html>", "empty body": ""} {
		t.Run(name, func(t *testing.T) {
			u := newUpstream(t)
			u.set("raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json", body, `"x"`)
			m, _, _ := setup(t, u, t.TempDir())
			res, _ := m.RefreshAll(t.Context())
			if !strings.Contains(outcomes(res), "takeover_fingerprints=rejected") {
				t.Fatalf("res=%s", outcomes(res))
			}
		})
	}
}

func TestBuildValidation(t *testing.T) {
	if _, err := Build(Config{Shared: true}); err == nil {
		t.Error("shared without guard must error")
	}
	m, err := Build(Config{})
	if err != nil || len(m.Names()) != 0 {
		t.Errorf("nothing enabled: %v %v", m, err)
	}
	m, err = Build(Config{Takeover: true})
	if err != nil || len(m.Names()) != 1 {
		t.Errorf("%v %v", m, err)
	}
}
