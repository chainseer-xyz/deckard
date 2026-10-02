package cloudflare

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

const testToken = "fake-test-token"

// fake replays fixtures. routes maps an API path to one fixture per page.
type fake struct {
	t      *testing.T
	routes map[string][]string
	// failures: path -> remaining forced responses (status, optional Retry-After)
	mu       sync.Mutex
	forced   map[string][]forced
	hits     map[string]int
	authSeen []string
}

type forced struct {
	status int
	retry  string
	file   string
	body   string
}

func newFake(t *testing.T, routes map[string][]string) (*fake, *Source, *bytes.Buffer) {
	t.Helper()
	f := &fake{t: t, routes: routes, forced: map[string][]forced{}, hits: map[string]int{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	logs := &bytes.Buffer{}
	lg := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s, err := New(config.SourceConfig{Name: "cf-test", Type: "cloudflare", Token: testToken, BaseURL: srv.URL + "/client/v4"},
		nil, lg, WithRetry(3, time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	return f, s, logs
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	f.mu.Lock()
	f.hits[path]++
	f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
	if q := f.forced[path]; len(q) > 0 {
		fc := q[0]
		f.forced[path] = q[1:]
		f.mu.Unlock()
		if fc.retry != "" {
			w.Header().Set("Retry-After", fc.retry)
		}
		w.WriteHeader(fc.status)
		switch {
		case fc.body != "":
			_, _ = w.Write([]byte(fc.body))
		case fc.file != "":
			_, _ = w.Write(f.fixture(fc.file))
		}
		return
	}
	f.mu.Unlock()
	pages, ok := f.routes[path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(f.fixture("forbidden.json"))
		return
	}
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		page, _ = strconv.Atoi(p)
	}
	if page < 1 || page > len(pages) {
		_, _ = w.Write(f.fixture("empty.json"))
		return
	}
	_, _ = w.Write(f.fixture(pages[page-1]))
}

func (f *fake) fixture(name string) []byte {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

var coreRoutes = map[string][]string{
	"/zones":                      {"zones_p1.json", "zones_p2.json"},
	"/zones/zone0001/dns_records": {"dns_zone0001_p1.json", "dns_zone0001_p2.json"},
	"/zones/zone0002/dns_records": {"dns_zone0002.json"},
}

func fullRoutes() map[string][]string {
	m := map[string][]string{}
	for k, v := range coreRoutes {
		m[k] = v
	}
	m["/zones/zone0001/load_balancers"] = []string{"lb_zone0001.json"}
	m["/accounts/acct0001/load_balancers/pools"] = []string{"pools_acct0001.json"}
	m["/accounts/acct0001/cfd_tunnel"] = []string{"tunnels_acct0001.json"}
	m["/zones/zone0001/spectrum/apps"] = []string{"spectrum_zone0001.json"}
	return m
}

func findAsset(d *source.Discovery, kind model.AssetKind, key string) *model.AssetInput {
	for i := range d.Assets {
		if d.Assets[i].Kind == kind && d.Assets[i].Key == key {
			return &d.Assets[i]
		}
	}
	return nil
}

func hasRel(d *source.Discovery, fk model.AssetKind, fkey string, tk model.AssetKind, tkey string, t model.RelationType) bool {
	want := model.RelationInput{FromKind: fk, FromKey: fkey, ToKind: tk, ToKey: tkey, Type: t}
	for _, r := range d.Relations {
		if r == want {
			return true
		}
	}
	return false
}

func mustAsset(t *testing.T, d *source.Discovery, kind model.AssetKind, key string) *model.AssetInput {
	t.Helper()
	a := findAsset(d, kind, key)
	if a == nil {
		t.Fatalf("missing %s asset %q", kind, key)
	}
	return a
}

func discover(t *testing.T, routes map[string][]string) (*source.Discovery, *fake, *bytes.Buffer) {
	t.Helper()
	f, s, logs := newFake(t, routes)
	d, err := s.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return d, f, logs
}

func TestDiscoverCore(t *testing.T) {
	d, f, _ := discover(t, coreRoutes)

	if len(d.Zones) != 2 || d.Zones[0].Name != "example.com" || d.Zones[1].Name != "example.net" {
		t.Fatalf("zones (pagination across pages): %+v", d.Zones)
	}
	if f.hits["/zones"] != 2 || f.hits["/zones/zone0001/dns_records"] != 2 {
		t.Fatalf("expected both pages fetched: %v", f.hits)
	}
	for _, a := range f.authSeen {
		if a != "Bearer "+testToken {
			t.Fatalf("bad auth header %q", a)
		}
	}
	mustAsset(t, d, model.KindZone, "example.com")
	mustAsset(t, d, model.KindZone, "example.net")

	t.Run("proxied record keeps origin IP as origin, not exposure", func(t *testing.T) {
		www := mustAsset(t, d, model.KindHostname, "www.example.com") // lowercased
		if www.Zone != "example.com" || www.Source != "cf-test" {
			t.Fatalf("%+v", www)
		}
		if www.Attrs["proxied"] != true || www.Attrs["origin_ip"] != "192.0.2.10" {
			t.Fatalf("attrs %+v", www.Attrs)
		}
		if types := www.Attrs["record_types"].([]string); strings.Join(types, ",") != "A,AAAA" {
			t.Fatalf("types %v", types)
		}
		ip := mustAsset(t, d, model.KindIP, "192.0.2.10")
		if ip.Attrs["origin"] != true || ip.Attrs["proxied"] != true {
			t.Fatalf("ip attrs %+v", ip.Attrs)
		}
		if mustAsset(t, d, model.KindIP, "2001:db8::10").Attrs["origin"] != true {
			t.Fatal("aaaa origin")
		}
		if !hasRel(d, model.KindHostname, "www.example.com", model.KindIP, "192.0.2.10", model.RelResolvesTo) ||
			!hasRel(d, model.KindHostname, "www.example.com", model.KindCloudResource, ProxyKey, model.RelProxiedBy) ||
			!hasRel(d, model.KindHostname, "www.example.com", model.KindZone, "example.com", model.RelInZone) {
			t.Fatal("missing relations")
		}
		mustAsset(t, d, model.KindCloudResource, ProxyKey)
	})

	t.Run("unproxied record is directly exposed", func(t *testing.T) {
		h := mustAsset(t, d, model.KindHostname, "direct.example.com")
		if h.Attrs["proxied"] != false || h.Attrs["origin_ip"] != nil || h.Attrs["ttl"] != 300 {
			t.Fatalf("attrs %+v", h.Attrs)
		}
		ip := mustAsset(t, d, model.KindIP, "198.51.100.7")
		// shared with proxied app.example.net: both flags are recorded.
		if ip.Attrs["exposed"] != true || ip.Attrs["origin"] != true || ip.Attrs["proxied"] != false {
			t.Fatalf("ip attrs %+v", ip.Attrs)
		}
		if hasRel(d, model.KindHostname, "direct.example.com", model.KindCloudResource, ProxyKey, model.RelProxiedBy) {
			t.Fatal("unproxied record must not be proxied_by")
		}
	})

	t.Run("wildcard", func(t *testing.T) {
		w := mustAsset(t, d, model.KindHostname, "*.wild.example.com")
		if w.Attrs["wildcard"] != true {
			t.Fatalf("%+v", w.Attrs)
		}
		if mustAsset(t, d, model.KindHostname, "direct.example.com").Attrs["wildcard"] != nil {
			t.Fatal("non-wildcard flagged")
		}
	})

	t.Run("cname to external, trailing dot stripped", func(t *testing.T) {
		mustAsset(t, d, model.KindHostname, "blog.example.com")
		tgt := mustAsset(t, d, model.KindHostname, "hosted.example.net")
		if tgt.Zone != "" {
			t.Fatalf("external target zone = %q", tgt.Zone)
		}
		if !hasRel(d, model.KindHostname, "blog.example.com", model.KindHostname, "hosted.example.net", model.RelCNAMETo) {
			t.Fatal("missing cname_to")
		}
	})

	t.Run("mx apex hostname", func(t *testing.T) {
		h := mustAsset(t, d, model.KindHostname, "example.net")
		if h.Zone != "example.net" || h.Attrs["record_types"].([]string)[0] != "MX" {
			t.Fatalf("%+v", h)
		}
	})

	// Optional endpoints absent (404) were skipped, not failures.
}

func TestDiscoverFeatures(t *testing.T) {
	d, _, _ := discover(t, fullRoutes())
	if d.Partial || len(d.PartialReasons) != 0 {
		t.Errorf("fully successful sync marked partial: %v", d.PartialReasons)
	}

	t.Run("lb pool origins", func(t *testing.T) {
		lb := mustAsset(t, d, model.KindHostname, "lb.example.com")
		if lb.Attrs["load_balancer"] != true || lb.Zone != "example.com" {
			t.Fatalf("%+v", lb)
		}
		for _, k := range []string{"192.0.2.50", "2001:db8::50"} {
			if mustAsset(t, d, model.KindIP, k).Attrs["origin"] != true || !hasRel(d, model.KindIP, k, model.KindHostname, "lb.example.com", model.RelOriginOf) {
				t.Fatalf("origin %s", k)
			}
		}
		if !hasRel(d, model.KindHostname, "origin.example.org", model.KindHostname, "lb.example.com", model.RelOriginOf) {
			t.Fatal("hostname origin")
		}
		// unreferenced pool: asset kept, no LB relation.
		mustAsset(t, d, model.KindIP, "203.0.113.77")
		for _, r := range d.Relations {
			if r.FromKey == "203.0.113.77" && r.Type == model.RelOriginOf {
				t.Fatal("unreferenced pool must not be origin_of anything")
			}
		}
	})

	t.Run("tunnel", func(t *testing.T) {
		tn := mustAsset(t, d, model.KindCloudResource, "cloudflare:tunnel:tun00001")
		if tn.Attrs["name"] != "edge-tunnel" {
			t.Fatalf("%+v", tn.Attrs)
		}
	})

	t.Run("spectrum", func(t *testing.T) {
		svc := mustAsset(t, d, model.KindService, "ssh.example.com:22/tcp")
		if svc.Attrs["spectrum"] != true {
			t.Fatalf("%+v", svc.Attrs)
		}
		if !hasRel(d, model.KindIP, "192.0.2.60", model.KindService, "ssh.example.com:22/tcp", model.RelOriginOf) ||
			!hasRel(d, model.KindHostname, "ssh.example.com", model.KindService, "ssh.example.com:22/tcp", model.RelExposes) {
			t.Fatal("spectrum relations")
		}
	})
}

func TestOptionalFeaturesSkippedGracefully(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		status int
		body   string
	}{
		{"spectrum 403", "/zones/zone0001/spectrum/apps", 403, "forbidden.json"},
		{"lb 403", "/zones/zone0001/load_balancers", 403, "forbidden.json"},
		{"pools 403", "/accounts/acct0001/load_balancers/pools", 403, "forbidden.json"},
		{"tunnels 403", "/accounts/acct0001/cfd_tunnel", 403, "forbidden.json"},
		{"spectrum 404", "/zones/zone0001/spectrum/apps", 404, "forbidden.json"},
		{"lb not enabled", "/zones/zone0001/load_balancers", 400, "notenabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, s, logs := newFake(t, fullRoutes())
			fc := forced{status: tc.status, file: tc.body}
			if tc.body == "notenabled" {
				fc = forced{status: 400, body: `{"success":false,"errors":[{"code":1,"message":"Load balancing is not enabled for this zone"}],"result":null}`}
			}
			f.forced[tc.path] = []forced{fc, fc, fc, fc, fc}
			d, err := s.Discover(context.Background())
			if err != nil {
				t.Fatalf("must skip gracefully: %v", err)
			}
			mustAsset(t, d, model.KindHostname, "www.example.com")
			// 403 (token lacks permission) leaves a gap; 404/not enabled means the
			// feature is absent, so there is nothing to miss.
			if wantPartial := tc.status == 403; d.Partial != wantPartial || wantPartial != (len(d.PartialReasons) == 1) {
				t.Errorf("Partial=%v reasons=%v, want partial=%v", d.Partial, d.PartialReasons, wantPartial)
			}
			if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "skipped") {
				t.Fatalf("expected warning log: %s", logs)
			}
		})
	}
}

func TestRequiredFailuresAreHardErrors(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		status int
	}{
		{"zones 500", "/zones", 500},
		{"dns 500", "/zones/zone0002/dns_records", 502},
		{"dns 403", "/zones/zone0001/dns_records", 403},
		{"zones 401", "/zones", 401},
		{"spectrum 500", "/zones/zone0001/spectrum/apps", 500},
		{"pools 503", "/accounts/acct0001/load_balancers/pools", 503},
		{"tunnels 500", "/accounts/acct0001/cfd_tunnel", 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, s, _ := newFake(t, fullRoutes())
			var q []forced
			for i := 0; i < 10; i++ {
				q = append(q, forced{status: tc.status, file: "servererr.json"})
			}
			f.forced[tc.path] = q
			d, err := s.Discover(context.Background())
			if err == nil || d != nil {
				t.Fatalf("want error and nil discovery, got %v / %v", err, d)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Fatal("token leaked in error")
			}
		})
	}
}

func TestRetryOn429And5xx(t *testing.T) {
	f, s, _ := newFake(t, coreRoutes)
	f.forced["/zones"] = []forced{{status: 429, retry: "0", file: "servererr.json"}, {status: 503, file: "servererr.json"}}
	d, err := s.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Zones) != 2 {
		t.Fatalf("zones %v", d.Zones)
	}
	if f.hits["/zones"] != 4 { // 2 failures + 2 pages
		t.Fatalf("hits %d", f.hits["/zones"])
	}
}

func TestRetriesExhausted(t *testing.T) {
	f, s, _ := newFake(t, coreRoutes)
	q := make([]forced, 20)
	for i := range q {
		q[i] = forced{status: 429, retry: "0", file: "servererr.json"}
	}
	f.forced["/zones"] = q
	if _, err := s.Discover(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if f.hits["/zones"] != 4 { // 1 + 3 retries
		t.Fatalf("hits %d", f.hits["/zones"])
	}
}

func TestTokenNeverInErrorsOrLogs(t *testing.T) {
	f, s, logs := newFake(t, fullRoutes())
	// A hostile server echoes the token back in its error message.
	body := `{"success":false,"errors":[{"code":9,"message":"bad token ` + testToken + `"}],"result":null}`
	f.forced["/zones"] = []forced{{status: 500, body: body}, {status: 500, body: body}, {status: 500, body: body}, {status: 500, body: body}}
	_, err := s.Discover(context.Background())
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("token in error: %v", err)
	}
	// And on a successful run with a 403 skip, logs are clean too.
	f2, s2, logs2 := newFake(t, fullRoutes())
	f2.forced["/zones/zone0001/spectrum/apps"] = []forced{{status: 403, body: `{"success":false,"errors":[{"code":1,"message":"nope ` + testToken + `"}]}`}}
	if _, err := s2.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{logs.String(), logs2.String()} {
		if strings.Contains(l, testToken) {
			t.Fatalf("token in logs: %s", l)
		}
	}
}

func TestContextCancel(t *testing.T) {
	_, s, _ := newFake(t, coreRoutes)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d, err := s.Discover(ctx)
	if err == nil || d != nil {
		t.Fatalf("want ctx error, got %v %v", err, d)
	}

	// Cancel during a retry backoff.
	f, s2, _ := newFake(t, coreRoutes)
	s2.c.backoff = time.Hour
	f.forced["/zones"] = []forced{{status: 500, body: "{}"}}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	start := time.Now()
	if _, err := s2.Discover(ctx2); err == nil {
		t.Fatal("want error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("cancel not honoured during backoff")
	}
}

func TestAccountFilter(t *testing.T) {
	var gotAcct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/zones") {
			gotAcct = r.URL.Query().Get("account.id")
		}
		_, _ = w.Write([]byte(`{"success":true,"result":[],"result_info":{"page":1,"total_pages":1}}`))
	}))
	defer srv.Close()
	s, err := New(config.SourceConfig{Name: "x", Token: "t", AccountID: "acctXYZ", BaseURL: srv.URL}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAcct != "acctXYZ" {
		t.Fatalf("account filter %q", gotAcct)
	}
}

func TestNewTokenResolution(t *testing.T) {
	if _, err := New(config.SourceConfig{Name: "x"}, nil, nil); err == nil {
		t.Fatal("want missing token error")
	}
	s, err := New(config.SourceConfig{Name: "x", TokenEnv: "CF_T"}, func(k string) string {
		if k == "CF_T" {
			return "from-env"
		}
		return ""
	}, nil)
	if err != nil || s.c.token != "from-env" || s.c.base != DefaultBaseURL {
		t.Fatalf("%v %+v", err, s)
	}
	if s.Name() != "x" || s.Type() != "cloudflare" {
		t.Fatal("identity")
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0}, {"2", 2 * time.Second}, {"-5", 0}, {"junk", 0},
		{now.Add(10 * time.Second).Format(http.TimeFormat), 10 * time.Second},
		{now.Add(-10 * time.Second).Format(http.TimeFormat), 0},
	}
	for _, c := range cases {
		if got := parseRetryAfter(c.in, now); got != c.want {
			t.Errorf("%q: got %v want %v", c.in, got, c.want)
		}
	}
}
