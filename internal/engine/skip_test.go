package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/exposed"
	netcheck "github.com/chainseer-xyz/deckard/internal/check/net"
	"github.com/chainseer-xyz/deckard/internal/check/tlsconfig"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// skipGuard is a fakeGuard that also implements destinationVetter.
type skipGuard struct {
	*fakeGuard
	reasons map[string]string // host -> reason
	asked   []string          // tier|host
}

func (g *skipGuard) DestinationSkip(_ context.Context, tier model.Tier, host string) (string, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.asked = append(g.asked, string(tier)+"|"+host)
	if r := g.reasons[host]; r != "" {
		return r, host + " resolves to shared address(es) 104.16.1.1"
	}
	return "", ""
}

func newSkipHarness(cfg func(*testCfg), assets []model.Asset, reasons map[string]string, checks ...check.Check) (*harness, *skipGuard) {
	h := newHarness(cfg, assets, checks...)
	g := &skipGuard{fakeGuard: h.g, reasons: reasons}
	h.r.Guard = g
	return h, g
}

// A check whose owned name resolves to shared infrastructure is skipped
// before anything is built: no Run, no network handle, no findings
// processing, no error metric; one skipped scan run per check, counted as a
// skip.
func TestRunScanDestinationSkipNeverRunsTheCheck(t *testing.T) {
	a := urlAsset(1, "https://app.example.com/")
	c1 := &fakeCheck{name: "http.exposed", tier: model.TierActive}
	c2 := &fakeCheck{name: "cve.nuclei", tier: model.TierActive}
	h, g := newSkipHarness(nil, []model.Asset{a}, map[string]string{"app.example.com": scope.SkipSharedDestination}, c1, c2)

	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierActive}); err != nil {
		t.Fatal(err)
	}
	if c1.calls.Load()+c2.calls.Load() != 0 {
		t.Fatal("a skipped check ran")
	}
	if n := h.g.built.Load(); n != 0 {
		t.Fatalf("%d network handles built for a skipped check", n)
	}
	if len(h.proc.calls) != 0 {
		t.Fatal("a skip reached the finding processor: it could resolve findings it never observed")
	}
	if len(h.inv.replCalls()) != 0 {
		t.Fatal("a skip reached the inventory: it could garbage-collect derived assets")
	}
	if len(h.rec.scans) != 0 {
		t.Fatalf("a skip was counted as a run/error: %+v", h.rec.scans)
	}
	if want := []string{"http.exposed|active|shared_destination", "cve.nuclei|active|shared_destination"}; strings.Join(h.rec.skips, ",") != strings.Join(want, ",") {
		t.Fatalf("skips = %v, want %v", h.rec.skips, want)
	}
	runs := h.st.runs()
	if len(runs) != 2 {
		t.Fatalf("runs = %+v", runs)
	}
	for _, r := range runs {
		if !strings.HasPrefix(r.Error, store.UnownedDestinationSkip) || !strings.Contains(r.Error, "app.example.com") || r.Findings != 0 {
			t.Errorf("run = %+v", r)
		}
	}
	if len(g.asked) != 1 || g.asked[0] != "active|app.example.com" {
		t.Fatalf("one lookup per scan job expected, got %v", g.asked)
	}
}

// The passive tier may probe shared destinations by owned hostname, so it is
// never asked; an owned destination runs normally.
func TestRunScanDestinationSkipOnlyForActiveTiersAndUnownedDestinations(t *testing.T) {
	a := hostAsset(1, "app.example.com")
	b := hostAsset(2, "own.example.com")
	pc := passiveCheck("dns.x")
	ac := &fakeCheck{name: "tls.config", tier: model.TierActive}
	h, g := newSkipHarness(nil, []model.Asset{a, b}, map[string]string{"app.example.com": scope.SkipSharedDestination}, pc, ac)
	ctx := context.Background()
	if err := h.r.runScan(ctx, scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}
	if pc.calls.Load() != 1 || len(g.asked) != 0 {
		t.Fatalf("passive: calls=%d asked=%v", pc.calls.Load(), g.asked)
	}
	if err := h.r.runScan(ctx, scanJob{AssetID: 2, Tier: model.TierActive}); err != nil {
		t.Fatal(err)
	}
	if ac.calls.Load() != 1 || len(h.rec.skips) != 0 {
		t.Fatalf("owned destination: calls=%d skips=%v", ac.calls.Load(), h.rec.skips)
	}
}

// A destination skip settles scheduling: it is not retried every
// scheduling.error_retry like a failure, only after the normal interval.
func TestScheduleTierDestinationSkipWaitsTheFullInterval(t *testing.T) {
	a := urlAsset(1, "https://app.example.com/")
	chk := &fakeCheck{name: "http.exposed", tier: model.TierActive}
	h, _ := newSkipHarness(func(c *testCfg) {
		c.Profiles.Active.Interval = 6 * time.Hour
		c.Scheduling.ErrorRetry = 10 * time.Minute
	}, []model.Asset{a}, map[string]string{"app.example.com": scope.SkipSharedDestination}, chk)
	ctx := context.Background()
	if err := h.r.runScan(ctx, scanJob{AssetID: 1, Tier: model.TierActive}); err != nil {
		t.Fatal(err)
	}
	h.r.last = map[ScanKey]store.ScanLast{} // only what the store says
	h.now = h.now.Add(15 * time.Minute)
	if n, _ := h.r.scheduleTier(ctx, model.TierActive); n != 0 {
		t.Fatalf("skipped 15m ago: queued %d, want 0 (a skip is not a failure to retry)", n)
	}
	h.now = h.now.Add(6 * time.Hour)
	if n, _ := h.r.scheduleTier(ctx, model.TierActive); n != 1 {
		t.Fatalf("skipped over 6h ago: queued %d, want 1", n)
	}
}

// ---- real guard, real checks, real store and processor ----

type mapResolver map[string][]string

func (m mapResolver) LookupHost(_ context.Context, h string) ([]string, error) {
	if a, ok := m[strings.TrimSuffix(strings.ToLower(h), ".")]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
}
func (mapResolver) LookupCNAME(context.Context, string) (string, error) { return "", errors.New("n/a") }
func (mapResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errors.New("n/a")
}
func (mapResolver) LookupNS(context.Context, string) ([]string, error) { return nil, errors.New("n/a") }

// countingDialer records every connection that got past the guard.
type countingDialer struct {
	mu    sync.Mutex
	calls []string
}

func (d *countingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, network+"|"+address)
	d.mu.Unlock()
	return nil, errors.New("test dialer: refused")
}

type countingNuclei struct{ n atomic.Int64 }

func (r *countingNuclei) Run(context.Context, string, []string) ([]byte, error) {
	r.n.Add(1)
	return nil, nil
}

// SAFETY: for every check the skip affects, an open finding stays open across
// repeated skipped runs (resolve_after=1, so a single clean run would resolve
// it), nothing is dialled, nuclei never starts, and no error is recorded.
func TestDestinationSkipLeavesOpenFindingsOpen(t *testing.T) {
	st, _ := migratedDB(t)
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	dialer := &countingDialer{}
	g, err := scope.NewGuard(config.ScopeConfig{}, scope.WithLogger(quiet), scope.WithDialer(dialer),
		scope.WithResolver(mapResolver{
			"app.example.com":  {"104.16.1.1", "104.16.1.2"}, // Cloudflare edge: skipped before the dial
			"loop.example.com": {"127.0.0.1"},                // anomaly: not skipped, refused at the dial
		}))
	if err != nil {
		t.Fatal(err)
	}
	g.SetZones([]string{"example.com"})

	runner := &countingNuclei{}
	nc := config.NucleiConfig{Enabled: true, Binary: "nuclei", ScanMode: "tech", SeverityMin: "low", TemplatesDir: t.TempDir()}
	checks := []check.Check{
		exposed.Checks(nil)[0],
		tlsconfig.Checks(nil)[0],
		nuclei.New(nc, g.VerifyOwnedTarget, runner, false, nil),
	}
	cfg := baseCfg()
	proc := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 1, StableAfter: 1}, quiet)
	rec := newFakeRec()
	r := newRunner(Deps{Config: cfg, Store: st, Guard: g, Inventory: &dbInventory{st, g}, Findings: proc, Recorder: rec, Checks: checks, Logger: quiet})

	diff, err := st.ApplySnapshot(ctx, "cf", []store.AssetUpsert{
		{AssetInput: model.AssetInput{Kind: model.KindURL, Key: "https://app.example.com/", Source: "cf", Zone: "example.com"}, Scope: model.ScopeOwned},
		{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: "app.example.com", Source: "cf", Zone: "example.com", Attrs: map[string]any{"tls": true}}, Scope: model.ScopeOwned},
	}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]model.Asset{}
	for _, a := range diff.Added {
		byKey[a.Key] = a
	}
	cases := []struct {
		check string
		asset model.Asset
	}{
		{"http.exposed", byKey["https://app.example.com/"]},
		{"cve.nuclei", byKey["https://app.example.com/"]},
		{"tls.config", byKey["app.example.com"]},
	}
	for _, tc := range cases {
		if tc.asset.ID == 0 {
			t.Fatalf("asset for %s not stored: %+v", tc.check, diff.Added)
		}
		seed := &check.Result{Findings: []model.FindingInput{{Check: tc.check, Key: "seeded", Severity: model.SeverityHigh, Title: "seeded " + tc.check}}}
		if _, err := proc.Process(ctx, tc.asset, tc.check, seed); err != nil {
			t.Fatal(err)
		}
	}

	for pass := 0; pass < 3; pass++ {
		for _, id := range []int64{byKey["https://app.example.com/"].ID, byKey["app.example.com"].ID} {
			if err := r.runScan(ctx, scanJob{AssetID: id, Tier: model.TierActive}); err != nil {
				t.Fatalf("pass %d: %v", pass, err)
			}
		}
	}

	for _, tc := range cases {
		t.Run(tc.check, func(t *testing.T) {
			fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: tc.asset.ID, Check: tc.check})
			if err != nil {
				t.Fatal(err)
			}
			if len(fs) != 1 || fs[0].Status != model.StatusOpen {
				t.Fatalf("findings = %+v, want the seeded one still open", fs)
			}
		})
	}
	if n := runner.n.Load(); n != 0 {
		t.Errorf("nuclei started %d times for a shared destination", n)
	}
	if len(dialer.calls) != 0 {
		t.Errorf("connections reached the dialer: %v", dialer.calls)
	}
	if len(rec.scans) != 0 {
		t.Errorf("skips recorded as runs/errors: %+v", rec.scans)
	}
	if len(rec.skips) != 3*len(cases) {
		t.Errorf("skips = %v, want %d", rec.skips, 3*len(cases))
	}
	runs, err := st.ListScans(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		if !strings.HasPrefix(run.Error, store.UnownedDestinationSkip) {
			t.Errorf("run %s on %d: error %q, want an unowned-destination skip", run.Check, run.AssetID, run.Error)
		}
	}
}

// The stored scope can lag while a refreshed shared-range list is being
// applied. The runner must classify the actual IP again before selecting any
// active check, including checks that operate on service assets backed by that
// IP.
func TestSharedIPAndServiceNeverReachActiveChecks(t *testing.T) {
	st, _ := migratedDB(t)
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	dialer := &countingDialer{}
	g, err := scope.NewGuard(config.ScopeConfig{}, scope.WithLogger(quiet), scope.WithDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	g.SetSharedRanges([]netip.Prefix{
		netip.MustParsePrefix("216.239.32.0/19"),
		netip.MustParsePrefix("2001:4860:4802::/48"),
	})
	runner := &countingNuclei{}
	nc := config.NucleiConfig{Enabled: true, Binary: "nuclei", ScanMode: "tech", SeverityMin: "low", TemplatesDir: t.TempDir()}
	checks := append(netcheck.Checks(nil), tlsconfig.Checks(nil)...)
	checks = append(checks,
		nuclei.New(nc, g.VerifyOwnedTarget, runner, false, nil),
		nuclei.New(nc, g.VerifyOwnedTarget, runner, true, nil),
	)
	proc := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 1, StableAfter: 1}, quiet)
	r := newRunner(Deps{Config: baseCfg(), Store: st, Guard: g, Inventory: &dbInventory{st, g}, Findings: proc,
		Recorder: newFakeRec(), Checks: checks, Logger: quiet})
	diff, err := st.ApplySnapshot(ctx, "cf", []store.AssetUpsert{
		{AssetInput: model.AssetInput{Kind: model.KindIP, Key: "216.239.32.21", Source: "cf"}, Scope: model.ScopeOwned},
		{AssetInput: model.AssetInput{Kind: model.KindService, Key: "216.239.32.21:443/tcp", Source: "cf", Attrs: map[string]any{"ip": "216.239.32.21", "port": 443, "tls": true}}, Scope: model.ScopeOwned},
	}, nil, time.Now())
	if err != nil || len(diff.Added) != 2 {
		t.Fatalf("seed assets: %v %+v", err, diff)
	}
	for _, a := range diff.Added {
		if err := r.runScan(ctx, scanJob{AssetID: a.ID, Tier: model.TierActive}); err != nil {
			t.Fatal(err)
		}
	}
	if len(dialer.calls) != 0 || runner.n.Load() != 0 {
		t.Fatalf("shared addresses reached active clients: dials=%v nuclei=%d", dialer.calls, runner.n.Load())
	}
	if got := g.Classify(model.KindService, "216.239.32.21:443/tcp"); got != model.ScopeShared {
		t.Fatalf("service scope = %s, want shared", got)
	}
}

// Backstop for what the pre-dial skip deliberately leaves to the guard (an
// anomalous answer such as loopback): tls.config reads every refused
// handshake as "version not offered", so without the refusal tracker its run
// looks clean and resolves the finding. A run with guard refusals is partial.
func TestGuardRefusedDialsNeverResolveFindings(t *testing.T) {
	st, _ := migratedDB(t)
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	dialer := &countingDialer{}
	g, err := scope.NewGuard(config.ScopeConfig{}, scope.WithLogger(quiet), scope.WithDialer(dialer),
		scope.WithResolver(mapResolver{"loop.example.com": {"127.0.0.1"}}))
	if err != nil {
		t.Fatal(err)
	}
	g.SetZones([]string{"example.com"})
	if reason, _ := g.DestinationSkip(ctx, model.TierActive, "loop.example.com"); reason != "" {
		t.Fatalf("precondition: loopback must not be a routine skip, got %q", reason)
	}
	proc := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 1, StableAfter: 1}, quiet)
	r := newRunner(Deps{Config: baseCfg(), Store: st, Guard: g, Inventory: &dbInventory{st, g}, Findings: proc,
		Recorder: newFakeRec(), Checks: tlsconfig.Checks(nil), Logger: quiet})
	diff, err := st.ApplySnapshot(ctx, "cf", []store.AssetUpsert{
		{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: "loop.example.com", Source: "cf", Zone: "example.com", Attrs: map[string]any{"tls": true}}, Scope: model.ScopeOwned},
	}, nil, time.Now())
	if err != nil || len(diff.Added) != 1 {
		t.Fatalf("seed asset: %v %+v", err, diff)
	}
	a := diff.Added[0]
	seed := &check.Result{Findings: []model.FindingInput{{Check: "tls.config", Key: "seeded", Severity: model.SeverityHigh, Title: "legacy TLS"}}}
	if _, err := proc.Process(ctx, a, "tls.config", seed); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := r.runScan(ctx, scanJob{AssetID: a.ID, Tier: model.TierActive}); err != nil {
			t.Fatal(err)
		}
	}
	fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: a.ID, Check: "tls.config"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Status != model.StatusOpen || fs[0].MissedRuns != 0 {
		t.Fatalf("findings = %+v, want the seeded one open with no misses", fs)
	}
	if len(dialer.calls) != 0 {
		t.Fatalf("loopback reached the dialer: %v", dialer.calls)
	}
}
