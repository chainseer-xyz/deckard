package engine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/inventory/expand"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type fakeExpander struct {
	mu   sync.Mutex
	reqs []ExpandRequest
	res  ExpandResult
	err  error
}

func (f *fakeExpander) Expand(_ context.Context, req ExpandRequest) (ExpandResult, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	return f.res, f.err
}

func (f *fakeExpander) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func zoneAsset(id int64, key string) model.Asset {
	return model.Asset{ID: id, Kind: model.KindZone, Key: key, Source: "cf", Zone: key, Scope: model.ScopeOwned}
}

func expCfg(ct, dns bool) func(*testCfg) {
	return func(c *testCfg) {
		c.Expansion.CTLogs, c.Expansion.DNSBruteforce, c.Expansion.Interval = ct, dns, 6*time.Hour
	}
}

func cand(zone, origin string, names ...string) []expand.Candidate {
	var out []expand.Candidate
	for _, n := range names {
		out = append(out, expand.Candidate{Name: n, Zone: zone, Origin: origin})
	}
	return out
}

func TestScheduleExpansionOwnedZonesOnly(t *testing.T) {
	owned := zoneAsset(1, "example.com")
	shared := zoneAsset(2, "cdn.example.net")
	removed := zoneAsset(3, "gone.example.com")
	now := time.Now()
	removed.RemovedAt = &now
	host := hostAsset(4, "a.example.com")
	h := newHarness(expCfg(true, false), []model.Asset{owned, shared, removed, host})
	h.g.classes["cdn.example.net"] = model.ScopeExternal
	h.r.Expander = &fakeExpander{}

	n, err := h.r.scheduleExpansion(context.Background(), true)
	if err != nil || n != 1 || len(h.q.zones) != 1 || h.q.zones[0] != 1 {
		t.Fatalf("n=%d err=%v zones=%v", n, err, h.q.zones)
	}
	// Unique per zone: a second tick queues nothing.
	if n, _ := h.r.scheduleExpansion(context.Background(), true); n != 0 {
		t.Fatalf("duplicate expansion queued: %d", n)
	}
}

func TestScheduleExpansionDisabled(t *testing.T) {
	z := zoneAsset(1, "example.com")
	for name, cfg := range map[string]func(*testCfg){
		"both flags off": expCfg(false, false),
		"zero interval": func(c *testCfg) {
			c.Expansion.CTLogs = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(cfg, []model.Asset{z})
			h.r.Expander = &fakeExpander{}
			if n, err := h.r.scheduleExpansion(context.Background(), false); n != 0 || err != nil {
				t.Fatalf("n=%d err=%v", n, err)
			}
		})
	}
	h := newHarness(expCfg(true, true), []model.Asset{z}) // no Expander wired
	if n, _ := h.r.scheduleExpansion(context.Background(), false); n != 0 {
		t.Fatal("expansion scheduled without an Expander")
	}
	// Passive tier disabled for the zone: no DNS traffic at all.
	h = newHarness(func(c *testCfg) { expCfg(true, true)(c); c.Profiles.Passive.Enabled = false }, []model.Asset{z})
	h.r.Expander = &fakeExpander{}
	if n, _ := h.r.scheduleExpansion(context.Background(), false); n != 0 {
		t.Fatal("expansion scheduled with passive tier disabled")
	}
}

func TestRunExpandAddsCandidatesAndQueuesScans(t *testing.T) {
	z := zoneAsset(1, "example.com")
	newHost := hostAsset(10, "www.example.com")
	pc := passiveCheck("dns.x")
	fx := &fakeExpander{res: ExpandResult{
		CT:  cand("example.com", "ct", "www.example.com", "www.example.com"),
		DNS: cand("example.com", "dns_bruteforce", "mail.example.com"),
	}}
	h := newHarness(expCfg(true, true), []model.Asset{z, newHost}, pc)
	h.r.Expander = fx
	h.inv.discDiff = store.InventoryDiff{Added: []model.Asset{newHost}}

	if err := h.r.runExpand(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.inv.discOrig, ","); got != "expansion:ct,expansion:dns" {
		t.Fatalf("origins %q", got)
	}
	ct := h.inv.discAsset[0]
	if len(ct) != 1 || ct[0].Key != "www.example.com" || ct[0].Kind != model.KindHostname || ct[0].Zone != "example.com" {
		t.Fatalf("ct inputs (deduped): %+v", ct)
	}
	if got := strings.Join(h.q.keys(), ","); got != "10|passive|dns.x" {
		t.Fatalf("immediate scans: %q", got)
	}
	req := fx.reqs[0]
	if req.Zone != "example.com" || !req.CT || !req.DNS || req.RatePerSec != 100 {
		t.Fatalf("request: %+v", req)
	}
	if h.g.tiers[0] != model.TierPassive || h.g.gotCls[0] != model.ScopeOwned {
		t.Fatalf("resolver must be passive/owned, got %v %v", h.g.tiers, h.g.gotCls)
	}
}

func TestRunExpandHonoursFlagsAndScope(t *testing.T) {
	z := zoneAsset(1, "example.com")
	ct := cand("example.com", "ct", "a.example.com")
	t.Run("ct only", func(t *testing.T) {
		fx := &fakeExpander{res: ExpandResult{CT: ct}}
		h := newHarness(expCfg(true, false), []model.Asset{z})
		h.r.Expander = fx
		_ = h.r.runExpand(context.Background(), 1)
		if r := fx.reqs[0]; !r.CT || r.DNS {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("dns only", func(t *testing.T) {
		fx := &fakeExpander{}
		h := newHarness(expCfg(false, true), []model.Asset{z})
		h.r.Expander = fx
		_ = h.r.runExpand(context.Background(), 1)
		if r := fx.reqs[0]; r.CT || !r.DNS {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("both off", func(t *testing.T) {
		fx := &fakeExpander{}
		h := newHarness(expCfg(false, false), []model.Asset{z})
		h.r.Expander = fx
		_ = h.r.runExpand(context.Background(), 1)
		if fx.calls() != 0 {
			t.Fatal("expander called with expansion disabled")
		}
	})
	for _, class := range []model.ScopeClass{model.ScopeShared, model.ScopeExternal, model.ScopeExcluded} {
		t.Run("never expands "+string(class), func(t *testing.T) {
			fx := &fakeExpander{res: ExpandResult{CT: ct}}
			h := newHarness(expCfg(true, true), []model.Asset{z})
			h.g.classes["example.com"] = class // stored class says owned; fresh class wins
			h.r.Expander = fx
			if err := h.r.runExpand(context.Background(), 1); err != nil {
				t.Fatal(err)
			}
			if fx.calls() != 0 || h.g.built.Load() != 0 || len(h.inv.discOrig) != 0 {
				t.Fatal("expansion ran for a non-owned zone")
			}
		})
	}
	t.Run("not a zone / removed / missing", func(t *testing.T) {
		host := hostAsset(2, "a.example.com")
		gone := zoneAsset(3, "gone.com")
		now := time.Now()
		gone.RemovedAt = &now
		fx := &fakeExpander{}
		h := newHarness(expCfg(true, true), []model.Asset{host, gone})
		h.r.Expander = fx
		for _, id := range []int64{2, 3, 404} {
			if err := h.r.runExpand(context.Background(), id); err != nil {
				t.Fatal(err)
			}
		}
		if fx.calls() != 0 {
			t.Fatal("expander called")
		}
	})
}

func TestRunExpandFailureKeepsPartialAndReturnsError(t *testing.T) {
	z := zoneAsset(1, "example.com")
	fx := &fakeExpander{
		res: ExpandResult{DNS: cand("example.com", "dns_bruteforce", "mail.example.com")},
		err: errors.New("ct example.com: status 503"),
	}
	h := newHarness(expCfg(true, true), []model.Asset{z})
	h.r.Expander = fx
	err := h.r.runExpand(context.Background(), 1)
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("error must be returned for retry: %v", err)
	}
	if len(h.inv.discOrig) != 1 || h.inv.discOrig[0] != "expansion:dns" {
		t.Fatalf("partial result must still be added: %v", h.inv.discOrig)
	}
	if len(h.st.runs()) != 0 || len(h.q.keys()) != 0 {
		t.Fatal("expansion failure must not touch scans or remove anything")
	}
	// An inventory failure is also returned (and does not panic).
	h.inv.discErr = errors.New("db down")
	if err := h.r.runExpand(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("inventory error: %v", err)
	}
}

func TestRunOnceExpandsAndScansNewAssets(t *testing.T) {
	z := zoneAsset(1, "example.com")
	n := hostAsset(2, "www.example.com")
	pc := passiveCheck("p.other")
	pc.applies = func(a model.Asset) bool { return a.Kind == model.KindHostname }
	e, h := newTestEngine(t, expCfg(true, false), []model.Asset{z}, pc)
	fx := &fakeExpander{res: ExpandResult{CT: cand("example.com", "ct", "www.example.com")}}
	e.r.Expander = fx
	h.inv.discDiff = store.InventoryDiff{Added: []model.Asset{n}}
	h.inv.onDiscovered = func() {
		h.st.mu.Lock()
		h.st.assets[n.ID] = n
		h.st.mu.Unlock()
	}
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.calls() != 1 {
		t.Fatalf("expander calls: %d", fx.calls())
	}
	if pc.calls.Load() != 1 {
		t.Fatalf("new asset scanned %d times in the same pass", pc.calls.Load())
	}
	// A failing expander does not fail the other work of the pass, but is reported.
	e2, h2 := newTestEngine(t, expCfg(true, false), []model.Asset{z, n}, pc)
	e2.r.Expander = &fakeExpander{err: errors.New("crt.sh down")}
	err := e2.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "crt.sh down") {
		t.Fatalf("err: %v", err)
	}
	if len(h2.st.runs()) == 0 {
		t.Fatal("scans must still run when expansion fails")
	}
}

// ---- DefaultExpander (wildcard handling) ----

type fakeResolver struct {
	hosts    map[string][]string
	wildcard []string // answer for any name under zone not in hosts
	zone     string
	err      error
	lookups  int
	mu       sync.Mutex
}

func (f *fakeResolver) LookupHost(_ context.Context, h string) ([]string, error) {
	f.mu.Lock()
	f.lookups++
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if a, ok := f.hosts[h]; ok {
		return a, nil
	}
	if f.wildcard != nil && strings.HasSuffix(h, "."+f.zone) {
		return f.wildcard, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
}
func (f *fakeResolver) LookupCNAME(context.Context, string) (string, error) { return "", nil }
func (f *fakeResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (f *fakeResolver) LookupNS(context.Context, string) ([]string, error)  { return nil, nil }

var _ check.Resolver = (*fakeResolver)(nil)

type fakeCT struct {
	names []string
	err   error
	calls int
}

func (f *fakeCT) Names(context.Context, string) ([]string, error) {
	f.calls++
	return f.names, f.err
}

func names(c []expand.Candidate) string {
	var s []string
	for _, x := range c {
		s = append(s, x.Name)
	}
	return strings.Join(s, ",")
}

func TestDefaultExpanderWildcardFiltering(t *testing.T) {
	ctx := context.Background()
	ctNames := []string{"www.example.com", "junk1.example.com", "junk2.example.com"}

	t.Run("wildcard zone: only names that differ from the wildcard are kept", func(t *testing.T) {
		r := &fakeResolver{zone: "example.com", wildcard: []string{"192.0.2.1"},
			hosts: map[string][]string{"www.example.com": {"192.0.2.50"}, "mail.example.com": {"192.0.2.60"}}}
		x := &DefaultExpander{CT: &fakeCT{names: ctNames}, Words: []string{"mail", "nothing"}}
		res, err := x.Expand(ctx, ExpandRequest{Zone: "example.com", CT: true, DNS: true, Resolver: r, RatePerSec: 1000})
		if err != nil {
			t.Fatal(err)
		}
		if names(res.CT) != "www.example.com" {
			t.Fatalf("ct: %q", names(res.CT))
		}
		if names(res.DNS) != "mail.example.com" {
			t.Fatalf("dns: %q", names(res.DNS))
		}
	})
	t.Run("plain zone: all CT names pass", func(t *testing.T) {
		r := &fakeResolver{zone: "example.com"}
		x := &DefaultExpander{CT: &fakeCT{names: ctNames}}
		res, err := x.Expand(ctx, ExpandRequest{Zone: "example.com", CT: true, Resolver: r})
		if err != nil || len(res.CT) != 3 {
			t.Fatalf("%v %v", res, err)
		}
	})
	t.Run("wildcard probe failing adds nothing from CT", func(t *testing.T) {
		r := &fakeResolver{err: errors.New("servfail")}
		x := &DefaultExpander{CT: &fakeCT{names: ctNames}}
		res, err := x.Expand(ctx, ExpandRequest{Zone: "example.com", CT: true, Resolver: r})
		if err == nil || len(res.CT) != 0 {
			t.Fatalf("must not flood on unknown wildcard state: %v %v", res, err)
		}
	})
	t.Run("ct failure still lets dns run, error reported", func(t *testing.T) {
		r := &fakeResolver{zone: "example.com", hosts: map[string][]string{"www.example.com": {"192.0.2.9"}}}
		x := &DefaultExpander{CT: &fakeCT{err: errors.New("status 429")}, Words: []string{"www"}}
		res, err := x.Expand(ctx, ExpandRequest{Zone: "example.com", CT: true, DNS: true, Resolver: r, RatePerSec: 1000})
		if err == nil || !strings.Contains(err.Error(), "429") {
			t.Fatalf("err: %v", err)
		}
		if names(res.DNS) != "www.example.com" {
			t.Fatalf("dns: %q", names(res.DNS))
		}
	})
	t.Run("flags off: no CT query, no lookups", func(t *testing.T) {
		r := &fakeResolver{zone: "example.com"}
		ct := &fakeCT{names: ctNames}
		x := &DefaultExpander{CT: ct, Words: []string{"www"}}
		res, err := x.Expand(ctx, ExpandRequest{Zone: "example.com", Resolver: r})
		if err != nil || ct.calls != 0 || r.lookups != 0 || len(res.CT)+len(res.DNS) != 0 {
			t.Fatalf("calls=%d lookups=%d", ct.calls, r.lookups)
		}
	})
}

func TestPoliteTransportHonoursRetryAfter(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("User-Agent") == "" {
			t.Error("missing User-Agent")
		}
		if hits == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`[{"common_name":"www.example.com","name_value":"www.example.com"}]`))
	}))
	defer srv.Close()
	var slept []time.Duration
	pt := &politeTransport{base: http.DefaultTransport, maxWait: 5 * time.Second,
		sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }}
	ct := expand.NewCT(expand.WithCTBaseURL(srv.URL), expand.WithCTHTTPClient(&http.Client{Transport: pt}),
		expand.WithCTUserAgent("deckard-test"), expand.WithCTRetries(2, time.Millisecond))
	got, err := ct.Names(context.Background(), "example.com")
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if len(slept) != 1 || slept[0] != 5*time.Second { // 7s capped to maxWait
		t.Fatalf("slept %v", slept)
	}
	if retryAfter("") != 0 || retryAfter("3") != 3*time.Second || retryAfter("junk") != 0 {
		t.Fatal("retryAfter parsing")
	}
}
