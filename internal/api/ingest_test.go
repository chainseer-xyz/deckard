package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type ingestEnv struct {
	*env
	reg *prometheus.Registry
}

func ingestCfg() config.IngestConfig {
	return config.IngestConfig{Enabled: true, RateLimit: "1000/s", Burst: 1000, MaxConcurrent: 4, Timeout: time.Minute,
		Tools: map[string]config.IngestToolConfig{"prowler": {}, "owned-tool": {Owned: true}, "tiny": {MaxFindings: 1}}}
}

func newIngestEnv(t *testing.T, mutate ...func(*api.Deps)) *ingestEnv {
	t.Helper()
	reg := prometheus.NewRegistry()
	var e *env
	e = newEnv(t, append([]func(*api.Deps){func(d *api.Deps) {
		d.Ingest = ingestCfg()
		d.Registry = reg
		// The real processor over the fakestore: the API test exercises the
		// whole server-side path. resolve_after = 2.
		d.Ingester = finding.NewProcessor(d.Store, finding.ProcessorConfig{ResolveAfter: 2}, nil,
			finding.WithClock(func() time.Time { return e.clock.Now() }))
	}}, mutate...)...)
	return &ingestEnv{env: e, reg: reg}
}

type ifind = map[string]any

func body(tool, scope string, complete bool, observed time.Time, findings ...ifind) string {
	if findings == nil {
		findings = []ifind{}
	}
	b, _ := json.Marshal(map[string]any{"tool": tool, "scope": scope, "complete": complete,
		"observed_at": observed.UTC().Format(time.RFC3339Nano), "findings": findings})
	return string(b)
}

func bucket(key string) ifind {
	return ifind{"key": key, "asset": ifind{"kind": "cloud_resource", "key": "arn:aws:s3:::" + key},
		"title": "Bucket " + key + " is public", "description": "Public read is granted.", "severity": "high", "tags": []string{"prowler", "s3"},
		"evidence": ifind{"region": "us-west-2"}}
}

const scopeA = "aws:123456789012:us-west-2"

func (e *ingestEnv) post(b string, hdr ...string) (resp, ingest.Response) {
	e.t.Helper()
	r := e.do("POST", "/api/v1/ingest", b, hdr...)
	var out ingest.Response
	if r.Code == http.StatusOK {
		r.json(e.t, &out)
	}
	return r, out
}

func (e *ingestEnv) ingested() []model.Finding {
	e.t.Helper()
	fs, _, err := e.store.ListFindings(context.Background(), store.FindingFilter{Check: "ext.prowler"})
	if err != nil {
		e.t.Fatal(err)
	}
	return fs
}

func (e *ingestEnv) count(tool, result string) float64 {
	e.t.Helper()
	mfs, err := e.reg.Gather()
	if err != nil {
		e.t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "deckard_ingest_requests_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["tool"] == tool && labels["result"] == result {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func TestIngestAppliesARun(t *testing.T) {
	e := newIngestEnv(t)
	r, out := e.post(body("prowler", scopeA, true, t0, bucket("a"), bucket("b")))
	if r.Code != http.StatusOK {
		t.Fatalf("status %d: %s", r.Code, r.Body)
	}
	want := ingest.Response{Accepted: 2, Opened: 2, Complete: true, Rejected: []ingest.Rejection{}}
	if fmt.Sprint(out) != fmt.Sprint(want) {
		t.Fatalf("response %+v, want %+v", out, want)
	}
	fs := e.ingested()
	if len(fs) != 2 {
		t.Fatalf("findings = %d", len(fs))
	}
	f := fs[0]
	if f.Check != "ext.prowler" || f.Source != "ingest:prowler" || f.IngestScope != scopeA || f.Status != model.StatusOpen ||
		f.Fingerprint != model.Fingerprint("ext.prowler", scopeA, f.Title[len("Bucket "):len("Bucket ")+1]) {
		t.Fatalf("finding %+v", f)
	}
	a, err := e.store.GetAssetByKey(context.Background(), model.KindCloudResource, "arn:aws:s3:::a")
	if err != nil || a.Source != "ingest:prowler" || a.Scope != model.ScopeExternal {
		t.Fatalf("asset %+v err %v", a, err)
	}
	if got := e.count("prowler", "ok"); got != 1 {
		t.Fatalf("ok counter = %v", got)
	}
	// The finding is served by the regular API with its ingest scope.
	g := e.get(fmt.Sprintf("/api/v1/findings/%d", f.ID))
	if g.Code != http.StatusOK || !strings.Contains(g.Body.String(), `"ingest_scope":"`+scopeA+`"`) {
		t.Fatalf("GET finding: %d %s", g.Code, g.Body)
	}
}

func TestIngestOwnedToolCreatesOwnedAssets(t *testing.T) {
	e := newIngestEnv(t)
	if r, _ := e.post(body("owned-tool", "k8s:prod", true, t0, bucket("a"))); r.Code != http.StatusOK {
		t.Fatalf("status %d: %s", r.Code, r.Body)
	}
	a, _ := e.store.GetAssetByKey(context.Background(), model.KindCloudResource, "arn:aws:s3:::a")
	if a == nil || a.Scope != model.ScopeOwned || a.Source != "ingest:owned-tool" {
		t.Fatalf("asset %+v", a)
	}
}

func TestIngestReconcilesCompleteRunsOnly(t *testing.T) {
	e := newIngestEnv(t)
	base := t0.Add(-time.Hour) // observed_at may not be ahead of the server clock
	e.post(body("prowler", scopeA, true, base, bucket("a"), bucket("b")))
	// Incomplete runs never resolve anything, however many.
	for i := 1; i <= 4; i++ {
		_, out := e.post(body("prowler", scopeA, false, base.Add(time.Duration(i)*time.Minute), bucket("a")))
		if out.ResolvedPending != 0 || out.Resolved != 0 || out.Complete {
			t.Fatalf("incomplete run %d: %+v", i, out)
		}
	}
	_, out := e.post(body("prowler", scopeA, true, base.Add(10*time.Minute), bucket("a")))
	if out.ResolvedPending != 1 || out.Resolved != 0 || out.Refreshed != 1 || !out.Complete {
		t.Fatalf("first complete miss: %+v", out)
	}
	_, out = e.post(body("prowler", scopeA, true, base.Add(11*time.Minute), bucket("a")))
	if out.Resolved != 1 || !out.Complete {
		t.Fatalf("second complete miss: %+v", out)
	}
	_, out = e.post(body("prowler", scopeA, true, base.Add(12*time.Minute), bucket("a"), bucket("b")))
	if out.Reopened != 1 || out.Refreshed != 1 || out.Opened != 0 {
		t.Fatalf("seen again: %+v", out)
	}
}

func TestIngestReplayIsANoOp(t *testing.T) {
	e := newIngestEnv(t)
	e.post(body("prowler", scopeA, true, t0, bucket("a"), bucket("b")))
	run := body("prowler", scopeA, true, t0.Add(time.Minute), bucket("a"))
	if _, out := e.post(run); out.ResolvedPending != 1 {
		t.Fatalf("first delivery %+v", out)
	}
	for i := 0; i < 3; i++ {
		r, out := e.post(run)
		if r.Code != http.StatusOK || !out.Replay || out.ResolvedPending != 0 || out.Resolved != 0 || out.Accepted != 0 {
			t.Fatalf("replay %d: %d %+v", i, r.Code, out)
		}
	}
	for _, f := range e.ingested() {
		if f.Status != model.StatusOpen {
			t.Fatalf("replays resolved %s", f.Title)
		}
	}
	if got := e.count("prowler", "replay"); got != 3 {
		t.Fatalf("replay counter = %v", got)
	}
}

func TestIngestRejectedRefDowngradesTheRun(t *testing.T) {
	e := newIngestEnv(t)
	e.seed() // www.example.com (owned), api.example.com (shared)
	e.post(body("prowler", scopeA, true, t0, bucket("a"), bucket("b")))
	ref := func(kind, key string) ifind {
		return ifind{"key": "ref-" + key, "asset": ifind{"ref": ifind{"kind": kind, "key": key}}, "title": "t", "description": "d", "severity": "low"}
	}
	r, out := e.post(body("prowler", scopeA, true, t0.Add(time.Minute), bucket("a"),
		ref("hostname", "www.example.com"), ref("hostname", "api.example.com"), ref("hostname", "nope.example.com")))
	if r.Code != http.StatusOK {
		t.Fatalf("status %d %s", r.Code, r.Body)
	}
	if out.Complete || out.Note == "" || out.ResolvedPending != 0 || out.Accepted != 2 || len(out.Rejected) != 2 ||
		out.Rejected[0].Index != 2 || out.Rejected[1].Index != 3 {
		t.Fatalf("response %+v", out)
	}
	if got := e.count("prowler", "partial"); got != 1 {
		t.Fatalf("partial counter = %v", got)
	}
	h, _ := e.store.GetAssetByKey(context.Background(), model.KindHostname, "www.example.com")
	found := false
	for _, f := range e.ingested() {
		if f.AssetID == h.ID && f.Source == "ingest:prowler" {
			found = true
		}
	}
	if !found {
		t.Fatal("finding on the referenced owned asset missing")
	}
}

func TestIngestRejectsInvalidRequestsWholeAndAtomically(t *testing.T) {
	e := newIngestEnv(t)
	bad := bucket("b")
	bad["severity"] = "urgent"
	probable := bucket("c")
	probable["asset"] = ifind{"kind": "hostname", "key": "www.example.com"}
	cases := []struct {
		name, body string
		want       int
		code       string
	}{
		{"invalid item among valid ones", body("prowler", scopeA, true, t0, bucket("a"), bad), 422, "invalid_request"},
		{"hostname asset creation", body("prowler", scopeA, true, t0, probable), 422, "invalid_request"},
		{"bad tool", body("Prowler", scopeA, true, t0), 422, "invalid_request"},
		{"too many for the tool", body("tiny", scopeA, true, t0, bucket("a"), bucket("b")), 422, "invalid_request"},
		{"duplicate keys", body("prowler", scopeA, true, t0, bucket("a"), bucket("a")), 422, "invalid_request"},
		{"future run", body("prowler", scopeA, true, t0.Add(time.Hour)), 422, "invalid_request"},
		{"missing findings", `{"tool":"prowler","scope":"s","complete":true,"observed_at":"2026-10-02T12:00:00Z"}`, 422, "invalid_request"},
		{"unknown field", `{"tool":"prowler","scope":"s","findings":[],"observed_at":"2026-10-02T12:00:00Z","bogus":1}`, 400, "invalid_body"},
		{"trailing data", body("prowler", scopeA, true, t0) + "{}", 400, "invalid_body"},
		{"not json", "tool=prowler", 400, "invalid_body"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := e.post(tc.body)
			if r.Code != tc.want || r.errCode(t) != tc.code {
				t.Fatalf("status %d code %s: %s", r.Code, r.errCode(t), r.Body)
			}
			if tc.want == 422 {
				var er ingest.ErrorResponse
				r.json(t, &er)
				if len(er.Rejected) == 0 || !strings.Contains(er.Error.Message, "nothing was changed") {
					t.Fatalf("422 body %s", r.Body)
				}
			}
		})
	}
	if fs := e.ingested(); len(fs) != 0 {
		t.Fatalf("rejected requests stored %d findings", len(fs))
	}
	if as, _, _ := e.store.ListAssets(context.Background(), store.AssetFilter{IncludeRemoved: true}); len(as) != 0 {
		t.Fatalf("rejected requests created %d assets", len(as))
	}
	if got := e.count("prowler", "rejected"); got != 5 {
		t.Fatalf("rejected counter = %v", got)
	}
	if got := e.count("invalid", "rejected"); got != 1 {
		t.Fatalf("invalid-tool counter = %v", got)
	}
	if got := e.count("unknown", "invalid"); got != 3 {
		t.Fatalf("unparseable counter = %v", got)
	}
}

func TestIngestTransportErrors(t *testing.T) {
	e := newIngestEnv(t)
	if r, _ := e.post(body("prowler", scopeA, true, t0), "Content-Type", "text/plain"); r.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain = %d", r.Code)
	}
	if r := e.do("POST", "/api/v1/ingest", ""); r.Code != http.StatusUnsupportedMediaType && r.Code != http.StatusBadRequest {
		t.Fatalf("empty body = %d", r.Code)
	}
	if r := e.do("POST", "/api/v1/ingest", "", "Content-Type", "application/json"); r.Code != http.StatusBadRequest {
		t.Fatalf("empty json body = %d", r.Code)
	}
	if r, _ := e.post(body("prowler", scopeA, true, t0) + strings.Repeat(" ", ingest.MaxBodyBytes)); r.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized = %d", r.Code)
	}
	// A body far above the generic 64 KiB API cap but under 10 MiB is fine.
	var fs []ifind
	for i := 0; i < 1500; i++ {
		f := bucket(fmt.Sprintf("k%04d", i))
		f["description"] = strings.Repeat("d", 400)
		fs = append(fs, f)
	}
	big := body("prowler", scopeA, true, t0, fs...)
	if len(big) < 512<<10 {
		t.Fatalf("test body only %d bytes", len(big))
	}
	if r, out := e.post(big); r.Code != http.StatusOK || out.Opened != 1500 {
		t.Fatalf("large body = %d %+v", r.Code, out)
	}
	if r := e.do("POST", "/api/v1/ingest?x=1", body("prowler", scopeA, true, t0)); r.Code != http.StatusBadRequest {
		t.Fatalf("query param = %d", r.Code)
	}
}

func TestIngestRequiresAuthAndCanBeDisabled(t *testing.T) {
	e := newIngestEnv(t)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/v1/ingest", strings.NewReader(body("prowler", scopeA, true, t0)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d", rec.Code)
	}
	off := newIngestEnv(t, func(d *api.Deps) { d.Ingest.Enabled = false })
	if r, _ := off.post(body("prowler", scopeA, true, t0, bucket("a"))); r.Code != http.StatusForbidden || r.errCode(t) != "ingest_disabled" {
		t.Fatalf("disabled = %d %s", r.Code, r.Body)
	}
	if fs := off.ingested(); len(fs) != 0 {
		t.Fatal("disabled ingest stored findings")
	}
	none := newIngestEnv(t, func(d *api.Deps) { d.Ingester = nil })
	if r, _ := none.post(body("prowler", scopeA, true, t0)); r.Code != http.StatusNotImplemented {
		t.Fatalf("no ingester = %d", r.Code)
	}
}

func TestIngestEnforcesCSRFForCookieSessions(t *testing.T) {
	e := newIngestEnv(t, func(d *api.Deps) { d.Authenticator = cookieAuth{csrf: "csrf-ok"} })
	if r, _ := e.post(body("prowler", scopeA, true, t0, bucket("a")), "Cookie", "s=ok"); r.Code != http.StatusForbidden || r.errCode(t) != "csrf" {
		t.Fatalf("no csrf = %d %s", r.Code, r.Body)
	}
	if r, _ := e.post(body("prowler", scopeA, true, t0, bucket("a")), "Cookie", "s=ok", "X-CSRF-Token", "csrf-ok"); r.Code != http.StatusOK {
		t.Fatalf("with csrf = %d %s", r.Code, r.Body)
	}
}

func TestIngestRateLimitsPerIdentity(t *testing.T) {
	e := newIngestEnv(t, func(d *api.Deps) { d.Ingest.RateLimit, d.Ingest.Burst = "1/h", 2 })
	for i := 0; i < 2; i++ {
		if r, _ := e.post(body("prowler", scopeA, false, t0.Add(time.Duration(i)*time.Second))); r.Code != http.StatusOK {
			t.Fatalf("request %d = %d", i, r.Code)
		}
	}
	r, _ := e.post(body("prowler", scopeA, false, t0.Add(time.Minute)))
	if r.Code != http.StatusTooManyRequests || r.Header().Get("Retry-After") != "3600" {
		t.Fatalf("third = %d retry-after %q", r.Code, r.Header().Get("Retry-After"))
	}
	e.clock.mu.Lock()
	e.clock.t = e.clock.t.Add(time.Hour)
	e.clock.mu.Unlock()
	if r, _ := e.post(body("prowler", scopeA, false, t0.Add(2*time.Minute))); r.Code != http.StatusOK {
		t.Fatalf("after an hour = %d", r.Code)
	}
}

type blockingIngester struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingIngester) Ingest(context.Context, store.IngestInput) (store.IngestResult, error) {
	b.started <- struct{}{}
	<-b.release
	return store.IngestResult{}, nil
}

func TestIngestBoundsConcurrency(t *testing.T) {
	bi := &blockingIngester{started: make(chan struct{}, 1), release: make(chan struct{})}
	e := newIngestEnv(t, func(d *api.Deps) { d.Ingest.MaxConcurrent, d.Ingester = 1, bi })
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.post(body("prowler", scopeA, false, t0))
	}()
	<-bi.started
	if r, _ := e.post(body("prowler", "other", false, t0)); r.Code != http.StatusTooManyRequests || r.errCode(t) != "busy" {
		t.Fatalf("second concurrent = %d %s", r.Code, r.Body)
	}
	close(bi.release)
	wg.Wait()
}

func TestIngestToolLabelIsBounded(t *testing.T) {
	e := newIngestEnv(t)
	for i := 0; i < 40; i++ {
		e.post(body(fmt.Sprintf("tool-%02d", i), "s", false, t0))
	}
	if got := e.count("tool-00", "ok"); got != 1 {
		t.Fatalf("first unlisted tool counter = %v", got)
	}
	if got := e.count("other", "ok"); got != 8 {
		t.Fatalf("overflow counter = %v, want 8 (40 tools - 32 labels)", got)
	}
	if n := testutil.CollectAndCount(e.reg, "deckard_ingest_requests_total"); n > 32+1+3*5 {
		t.Fatalf("%d series", n)
	}
}
