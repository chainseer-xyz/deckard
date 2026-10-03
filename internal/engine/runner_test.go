package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func hostAsset(id int64, key string) model.Asset {
	return model.Asset{ID: id, Kind: model.KindHostname, Key: key, Source: "cf", Zone: "example.com", Scope: model.ScopeOwned}
}

func passiveCheck(name string) *fakeCheck { return &fakeCheck{name: name, tier: model.TierPassive} }

// TestRunScanNeverProbesOutOfScope is the safety invariant: whatever the
// stored class says, a target the Guard classifies out of scope for the tier
// (or whose profile is off) never reaches Check.Run, no network handle is
// built, and a skipped ScanRun is recorded.
func TestRunScanNeverProbesOutOfScope(t *testing.T) {
	tests := []struct {
		name  string
		asset model.Asset
		class model.ScopeClass
		tier  model.Tier
	}{
		{"shared ip passive", model.Asset{ID: 1, Kind: model.KindIP, Key: "104.16.0.1"}, model.ScopeShared, model.TierPassive},
		{"shared service active", model.Asset{ID: 1, Kind: model.KindService, Key: "104.16.0.1:443/tcp"}, model.ScopeShared, model.TierActive},
		{"shared hostname active", hostAsset(1, "a.example.com"), model.ScopeShared, model.TierActive},
		{"shared hostname intrusive", hostAsset(1, "a.example.com"), model.ScopeShared, model.TierIntrusive},
		{"external service passive", model.Asset{ID: 1, Kind: model.KindService, Key: "198.51.100.9:80/tcp"}, model.ScopeExternal, model.TierPassive},
		{"external hostname active", hostAsset(1, "a.example.com"), model.ScopeExternal, model.TierActive},
		{"excluded hostname passive", hostAsset(1, "a.example.com"), model.ScopeExcluded, model.TierPassive},
		{"excluded ip active", model.Asset{ID: 1, Kind: model.KindIP, Key: "198.51.100.5"}, model.ScopeExcluded, model.TierActive},
		{"owned but intrusive disabled", hostAsset(1, "a.example.com"), model.ScopeOwned, model.TierIntrusive},
		{"unknown class", hostAsset(1, "a.example.com"), model.ScopeClass("weird"), model.TierPassive},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.asset
			a.Scope = model.ScopeOwned // stale stored class must be ignored
			chk := &fakeCheck{name: "c.test", tier: tc.tier}
			h := newHarness(nil, []model.Asset{a}, chk)
			h.g.classes[a.Key] = tc.class

			if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: tc.tier}); err != nil {
				t.Fatalf("runScan: %v", err)
			}
			if n := chk.calls.Load(); n != 0 {
				t.Fatalf("Check.Run called %d times for refused target", n)
			}
			if n := h.g.built.Load(); n != 0 {
				t.Fatalf("%d network handles built for refused target", n)
			}
			if len(h.proc.calls) != 0 {
				t.Fatal("findings processed for refused target")
			}
			runs := h.st.runs()
			if len(runs) != 1 || !strings.HasPrefix(runs[0].Error, SkippedPrefix) {
				t.Fatalf("want one skipped ScanRun, got %+v", runs)
			}
			if len(h.rec.scans) != 0 {
				t.Fatal("refused scan counted as a check run")
			}
		})
	}
}

func TestRunScanAllowsHostnameProbeOfSharedAndRemovedIsSkipped(t *testing.T) {
	chk := passiveCheck("c.test")
	a := hostAsset(1, "a.example.com")
	h := newHarness(nil, []model.Asset{a}, chk)
	h.g.classes[a.Key] = model.ScopeShared // passive by owned hostname is allowed
	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}
	if chk.calls.Load() != 1 {
		t.Fatal("hostname-based passive probe of shared asset should run")
	}
	if got := h.g.gotCls[0]; got != model.ScopeShared {
		t.Fatalf("guard handles built with class %q, want fresh class shared", got)
	}

	now := h.now
	r := hostAsset(2, "gone.example.com")
	r.RemovedAt = &now
	h2 := newHarness(nil, []model.Asset{r}, passiveCheck("c.test"))
	_ = h2.r.runScan(context.Background(), scanJob{AssetID: 2, Tier: model.TierPassive})
	if h2.r.checks[0].(*fakeCheck).calls.Load() != 0 {
		t.Fatal("removed asset was scanned")
	}
}

func TestRunScanHappyPath(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	other := model.Asset{ID: 2, Kind: model.KindIP, Key: "203.0.113.1"}
	chk := &fakeCheck{name: "dns.test", tier: model.TierPassive,
		run: func(context.Context, check.Target) (*check.Result, error) {
			return &check.Result{Findings: []model.FindingInput{{Check: "dns.test", Key: "k"}}}, nil
		}}
	h := newHarness(func(c *testCfg) {
		c.Checks = map[string]map[string]any{"dns.test": {"warn_days": 3}}
	}, []model.Asset{a, other}, chk)
	h.st.edges[1] = []store.Edge{{Other: other, Type: model.RelResolvesTo, Outbound: true}}
	h.st.baselines[ScanKey{1, "dns.test"}] = &store.Baseline{AssetID: 1, Check: "dns.test", Data: map[string]any{"x": 1}}

	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}
	if len(chk.targets) != 1 {
		t.Fatalf("calls: %d", len(chk.targets))
	}
	tg := chk.targets[0]
	if tg.Asset.ID != 1 || len(tg.Neighbours) != 1 || tg.Neighbours[0].Asset.ID != 2 || !tg.Neighbours[0].Outbound ||
		tg.Neighbours[0].Relation != model.RelResolvesTo {
		t.Fatalf("target: %+v", tg)
	}
	if tg.Baseline["dns.test"]["x"] != 1 || tg.Config["warn_days"] != 3 || tg.HTTP == nil {
		t.Fatalf("target baseline/config/http: %+v", tg)
	}
	if len(h.proc.calls) != 1 || h.proc.calls[0].check != "dns.test" || h.proc.calls[0].asset.ID != 1 {
		t.Fatalf("process calls: %+v", h.proc.calls)
	}
	runs := h.st.runs()
	if len(runs) != 1 || runs[0].Error != "" || runs[0].Findings != 1 || runs[0].Tier != "passive" || runs[0].Check != "dns.test" {
		t.Fatalf("scan runs: %+v", runs)
	}
	if len(h.rec.scans) != 1 || h.rec.scans[0].err != nil || h.rec.scans[0].tier != "passive" {
		t.Fatalf("metrics: %+v", h.rec.scans)
	}
}

func TestRunScanOnlyRunsRequestedCheckAndTier(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	p1, p2 := passiveCheck("p.one"), passiveCheck("p.two")
	act := &fakeCheck{name: "a.one", tier: model.TierActive}
	notApplicable := &fakeCheck{name: "p.zone", tier: model.TierPassive, applies: func(a model.Asset) bool { return a.Kind == model.KindZone }}
	h := newHarness(nil, []model.Asset{a}, p1, p2, act, notApplicable)

	_ = h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive, Check: "p.two"})
	if p1.calls.Load() != 0 || p2.calls.Load() != 1 || act.calls.Load() != 0 {
		t.Fatalf("named check: p1=%d p2=%d act=%d", p1.calls.Load(), p2.calls.Load(), act.calls.Load())
	}
	_ = h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive})
	if p1.calls.Load() != 1 || p2.calls.Load() != 2 || act.calls.Load() != 0 || notApplicable.calls.Load() != 0 {
		t.Fatalf("tier run: p1=%d p2=%d act=%d na=%d", p1.calls.Load(), p2.calls.Load(), act.calls.Load(), notApplicable.calls.Load())
	}
}

func TestRunScanMissingAssetAndStoreFailure(t *testing.T) {
	h := newHarness(nil, nil, passiveCheck("c"))
	if err := h.r.runScan(context.Background(), scanJob{AssetID: 99, Tier: model.TierPassive}); err != nil {
		t.Fatalf("missing asset must not retry: %v", err)
	}
	boom := errors.New("db down")
	h.st.failGet = boom
	if err := h.r.runScan(context.Background(), scanJob{AssetID: 99, Tier: model.TierPassive}); !errors.Is(err, boom) {
		t.Fatalf("store failure must surface for retry, got %v", err)
	}
}

func TestRunScanPanicIsRecordedAsError(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	bad := &fakeCheck{name: "bad", tier: model.TierPassive,
		run: func(context.Context, check.Target) (*check.Result, error) { panic("kaboom") }}
	good := passiveCheck("good")
	h := newHarness(nil, []model.Asset{a}, bad, good)
	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatalf("panic leaked as job error: %v", err)
	}
	if good.calls.Load() != 1 {
		t.Fatal("check after the panicking one did not run")
	}
	var badRun *store.ScanRun
	for _, r := range h.st.runs() {
		if r.Check == "bad" {
			r := r
			badRun = &r
		}
	}
	if badRun == nil || !strings.Contains(badRun.Error, "panicked") || !strings.Contains(badRun.Error, "kaboom") {
		t.Fatalf("panic not recorded: %+v", badRun)
	}
	for _, c := range h.proc.calls {
		if c.check == "bad" {
			t.Fatal("panicked check's result was processed (would resolve findings)")
		}
	}
}

func TestRunScanTimeout(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	slow := &fakeCheck{name: "slow", tier: model.TierPassive,
		run: func(ctx context.Context, _ check.Target) (*check.Result, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}
	h := newHarness(func(c *testCfg) {
		c.Checks = map[string]map[string]any{"slow": {"timeout": "40ms"}}
	}, []model.Asset{a}, slow)
	start := time.Now()
	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not enforced")
	}
	runs := h.st.runs()
	if len(runs) != 1 || !strings.Contains(runs[0].Error, "deadline exceeded") {
		t.Fatalf("runs: %+v", runs)
	}
	if len(h.proc.calls) != 0 {
		t.Fatal("timed-out result processed")
	}
}

func TestRunScanIgnoredContextTimeoutStillErrors(t *testing.T) {
	// A check that ignores ctx and returns a result after the deadline must
	// not have that result trusted.
	a := hostAsset(1, "a.example.com")
	rude := &fakeCheck{name: "rude", tier: model.TierPassive,
		run: func(ctx context.Context, _ check.Target) (*check.Result, error) {
			<-ctx.Done()
			return &check.Result{}, nil
		}}
	h := newHarness(func(c *testCfg) { c.Checks = map[string]map[string]any{"rude": {"timeout": "20ms"}} }, []model.Asset{a}, rude)
	_ = h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive})
	if r := h.st.runs(); len(r) != 1 || r[0].Error == "" || len(h.proc.calls) != 0 {
		t.Fatalf("runs=%+v proc=%d", r, len(h.proc.calls))
	}
}

func TestRunScanCheckErrorDoesNotProcess(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	c := &fakeCheck{name: "e", tier: model.TierPassive,
		run: func(context.Context, check.Target) (*check.Result, error) { return nil, errors.New("dns timeout") }}
	h := newHarness(nil, []model.Asset{a}, c)
	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}
	if len(h.proc.calls) != 0 {
		t.Fatal("errored check must not reconcile findings")
	}
	if r := h.st.runs(); len(r) != 1 || r[0].Error != "dns timeout" {
		t.Fatalf("%+v", r)
	}
	if len(h.rec.scans) != 1 || h.rec.scans[0].err == nil {
		t.Fatal("metrics should see the error")
	}
}

func TestRunScanProcessErrorIsRecorded(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	h := newHarness(nil, []model.Asset{a}, passiveCheck("c"))
	h.proc.err = errors.New("db write")
	_ = h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive})
	if r := h.st.runs(); len(r) != 1 || !strings.Contains(r[0].Error, "db write") {
		t.Fatalf("%+v", r)
	}
}

func TestRunScanNilResultTreatedAsEmpty(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	c := &fakeCheck{name: "n", tier: model.TierPassive,
		run: func(context.Context, check.Target) (*check.Result, error) { return nil, nil }}
	h := newHarness(nil, []model.Asset{a}, c)
	_ = h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive})
	if len(h.proc.calls) != 1 || h.proc.calls[0].res == nil {
		t.Fatalf("expected Process with empty result: %+v", h.proc.calls)
	}
}

func TestRunScanDiscoveredFeedsInventoryAndQueuesPassive(t *testing.T) {
	src := hostAsset(1, "a.example.com")
	newHost := hostAsset(10, "new.example.com")
	newShared := model.Asset{ID: 11, Kind: model.KindIP, Key: "104.16.0.9"}
	disc := &fakeCheck{name: "tls.cert", tier: model.TierPassive,
		run: func(context.Context, check.Target) (*check.Result, error) {
			return &check.Result{Discovered: []model.AssetInput{{Kind: model.KindHostname, Key: "new.example.com"}}}, nil
		}}
	pc := passiveCheck("dns.x")
	for _, tc := range []struct {
		name     string
		onChange bool
		want     []string
	}{
		{"on_inventory_change", true, []string{"10|passive|dns.x", "10|passive|tls.cert"}},
		{"off", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(func(c *testCfg) { c.Profiles.Passive.OnInventoryChange = tc.onChange },
				[]model.Asset{src, newHost, newShared}, disc, pc)
			h.g.classes[newShared.Key] = model.ScopeShared
			h.inv.discDiff = store.InventoryDiff{Added: []model.Asset{newHost, newShared}}
			if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive, Check: "tls.cert"}); err != nil {
				t.Fatal(err)
			}
			if rc := h.inv.replCalls(); len(rc) != 1 || rc[0].origin != "tls.cert" || rc[0].parent != 1 || len(rc[0].assets) != 1 {
				t.Fatalf("ReplaceDerived calls: %+v", rc)
			}
			if len(h.inv.discOrig) != 0 {
				t.Fatalf("check discovery must not use AddDiscovered: %v", h.inv.discOrig)
			}
			if got := h.q.keys(); strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("queued %v want %v", got, tc.want)
			}
			if h.rec.changes["added"] != 2 {
				t.Fatalf("inventory metric: %v", h.rec.changes)
			}
		})
	}
}

func TestPerHostConcurrencyAndRate(t *testing.T) {
	// Two service assets behind one IP, per_host_concurrency 1: never overlap.
	a1 := model.Asset{ID: 1, Kind: model.KindService, Key: "203.0.113.1:80/tcp"}
	a2 := model.Asset{ID: 2, Kind: model.KindService, Key: "203.0.113.1:443/tcp"}
	a3 := model.Asset{ID: 3, Kind: model.KindService, Key: "203.0.113.2:443/tcp"}
	var cur, peak, otherHostSeen atomic.Int64
	var mu sync.Mutex
	chk := &fakeCheck{name: "n", tier: model.TierActive,
		run: func(ctx context.Context, tg check.Target) (*check.Result, error) {
			if tg.Asset.ID == 3 {
				otherHostSeen.Add(1)
				return &check.Result{}, nil
			}
			n := cur.Add(1)
			mu.Lock()
			if n > peak.Load() {
				peak.Store(n)
			}
			mu.Unlock()
			time.Sleep(40 * time.Millisecond)
			cur.Add(-1)
			return &check.Result{}, nil
		}}
	h := newHarness(func(c *testCfg) { c.Profiles.Active.PerHostConcurrency = 1 }, []model.Asset{a1, a2, a3}, chk)
	var wg sync.WaitGroup
	for id := int64(1); id <= 3; id++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.r.runScan(context.Background(), scanJob{AssetID: id, Tier: model.TierActive})
		}()
	}
	wg.Wait()
	if peak.Load() != 1 {
		t.Fatalf("peak concurrency on one host = %d, want 1", peak.Load())
	}
	if otherHostSeen.Load() != 1 {
		t.Fatal("other host did not run")
	}
	if h.r.sems.size() != 0 {
		t.Fatalf("semaphore entries leaked: %d", h.r.sems.size())
	}
}

func TestLimiterShared(t *testing.T) {
	l := newLimiterSet()
	first, second := l.get(model.TierActive, 50), l.get(model.TierActive, 50)
	if first != second {
		t.Fatal("same tier+rate must share a limiter")
	}
	if l.get(model.TierActive, 50) == l.get(model.TierActive, 5) || l.get(model.TierActive, 50) == l.get(model.TierPassive, 50) {
		t.Fatal("different tier/rate must not share")
	}
	if err := l.get(model.TierPassive, 0).Wait(context.Background(), "x.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestKeyedSemCancel(t *testing.T) {
	k := newKeyedSem()
	rel, err := k.acquire(context.Background(), "h", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := k.acquire(ctx, "h", 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	rel()
	rel() // idempotent
	if k.size() != 0 {
		t.Fatalf("size %d", k.size())
	}
}

func TestCheckTimeoutParsing(t *testing.T) {
	r := newRunner(Deps{})
	for _, tc := range []struct {
		v    any
		want time.Duration
	}{
		{"30s", 30 * time.Second}, {5 * time.Second, 5 * time.Second}, {10, 10 * time.Second},
		{int64(7), 7 * time.Second}, {1.5, 1500 * time.Millisecond},
		{"garbage", defaultCheckTimeout}, {"-1s", defaultCheckTimeout}, {0, defaultCheckTimeout}, {nil, defaultCheckTimeout},
	} {
		r.Config.Checks = map[string]map[string]any{"c": {"timeout": tc.v}}
		if tc.v == nil {
			r.Config.Checks = nil
		}
		if got := r.checkTimeout("c"); got != tc.want {
			t.Errorf("%v: got %v want %v", tc.v, got, tc.want)
		}
	}
}

// ---- sync ----

func TestRunSync(t *testing.T) {
	added, changed, revived, removed := hostAsset(1, "add.example.com"), hostAsset(2, "chg.example.com"),
		hostAsset(3, "rev.example.com"), hostAsset(4, "rem.example.com")
	pc := passiveCheck("dns.x")
	src := &fakeSource{name: "cf"}
	mk := func(cfg func(*testCfg)) *harness {
		h := newHarness(func(c *testCfg) {
			c.sources = append(c.sources, src)
			if cfg != nil {
				cfg(c)
			}
		}, []model.Asset{added, changed, revived, removed}, pc)
		h.inv.syncDiff = store.InventoryDiff{Added: []model.Asset{added}, Changed: []model.Asset{changed},
			Revived: []model.Asset{revived}, Removed: []model.Asset{removed}}
		return h
	}
	t.Run("queues passive scans for added/changed/revived, never removed", func(t *testing.T) {
		h := mk(nil)
		if err := h.r.runSync(context.Background(), "cf"); err != nil {
			t.Fatal(err)
		}
		want := "1|passive|dns.x,2|passive|dns.x,3|passive|dns.x"
		if got := strings.Join(h.q.keys(), ","); got != want {
			t.Fatalf("queued %s want %s", got, want)
		}
		if h.rec.syncs["cf"][0] != true || h.rec.changes["added"] != 1 || h.rec.changes["removed"] != 1 ||
			h.rec.changes["changed"] != 1 || h.rec.changes["revived"] != 1 {
			t.Fatalf("metrics: %+v %+v", h.rec.syncs, h.rec.changes)
		}
	})
	t.Run("on_inventory_change off queues nothing", func(t *testing.T) {
		h := mk(func(c *testCfg) { c.Profiles.Passive.OnInventoryChange = false })
		_ = h.r.runSync(context.Background(), "cf")
		if len(h.q.keys()) != 0 {
			t.Fatalf("queued %v", h.q.keys())
		}
	})
	t.Run("failure is returned, queues nothing", func(t *testing.T) {
		h := mk(nil)
		h.inv.syncErr = errors.New("cf 503")
		err := h.r.runSync(context.Background(), "cf")
		if err == nil || !strings.Contains(err.Error(), "cf 503") {
			t.Fatalf("err=%v", err)
		}
		if len(h.q.keys()) != 0 || h.rec.syncs["cf"][0] != false || len(h.rec.changes) != 0 {
			t.Fatalf("queued=%v syncs=%v changes=%v", h.q.keys(), h.rec.syncs, h.rec.changes)
		}
	})
	t.Run("unknown source is not retried", func(t *testing.T) {
		h := mk(nil)
		if err := h.r.runSync(context.Background(), "nope"); err != nil {
			t.Fatal(err)
		}
		if len(h.inv.synced) != 0 {
			t.Fatal("synced unknown source")
		}
	})
}

// ---- scheduling ----

func TestScheduleTierDueComputation(t *testing.T) {
	never := hostAsset(1, "never.example.com")
	recent := hostAsset(2, "recent.example.com")
	old := hostAsset(3, "old.example.com")
	shared := model.Asset{ID: 4, Kind: model.KindIP, Key: "104.16.0.1"}
	sharedHost := hostAsset(5, "sharedhost.example.com")
	inapplicable := model.Asset{ID: 6, Kind: model.KindZone, Key: "example.com"}
	chk := &fakeCheck{name: "dns.x", tier: model.TierPassive, applies: func(a model.Asset) bool { return a.Kind != model.KindZone }}

	h := newHarness(nil, []model.Asset{never, recent, old, shared, sharedHost, inapplicable}, chk)
	h.g.classes[shared.Key] = model.ScopeShared
	h.g.classes[sharedHost.Key] = model.ScopeShared
	h.st.scans = []store.ScanRun{
		{AssetID: 2, Check: "dns.x", StartedAt: h.now.Add(-time.Minute)},
		{AssetID: 3, Check: "dns.x", StartedAt: h.now.Add(-time.Hour)},
		{AssetID: 3, Check: "dns.x", StartedAt: h.now.Add(-48 * time.Hour)}, // older duplicate ignored
		{AssetID: 2, Check: "other", StartedAt: h.now.Add(-time.Hour)},      // different check
	}
	n, err := h.r.scheduleTier(context.Background(), model.TierPassive)
	if err != nil {
		t.Fatal(err)
	}
	// never (1), old (3: 1h > 5m), sharedHost (5: hostname probe is allowed). Not recent (2),
	// not the shared IP (4), not the zone (inapplicable).
	want := "1|passive|dns.x,3|passive|dns.x,5|passive|dns.x"
	if got := strings.Join(h.q.keys(), ","); got != want || n != 3 {
		t.Fatalf("queued %s (n=%d) want %s", got, n, want)
	}
	// A second tick enqueues nothing new (dedupe).
	if n, _ := h.r.scheduleTier(context.Background(), model.TierPassive); n != 0 {
		t.Fatalf("second tick queued %d duplicates", n)
	}
}

func TestScheduleTierRespectsProfilesAndOverlay(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	act := &fakeCheck{name: "net.x", tier: model.TierActive}
	intr := &fakeCheck{name: "i.x", tier: model.TierIntrusive}
	h := newHarness(func(c *testCfg) {
		c.AssetGroups = append(c.AssetGroups, groupWithInterval("lab", "example.com", "active", time.Minute))
	}, []model.Asset{a}, act, intr)
	h.st.scans = []store.ScanRun{{AssetID: 1, Check: "net.x", StartedAt: h.now.Add(-2 * time.Minute)}}

	if n, _ := h.r.scheduleTier(context.Background(), model.TierIntrusive); n != 0 {
		t.Fatal("intrusive is off by default; nothing may be queued")
	}
	if n, _ := h.r.scheduleTier(context.Background(), model.TierActive); n != 1 {
		t.Fatalf("group interval 1m, last scan 2m ago: want 1 queued, got %d", n)
	}
	// Overlay: a scan recorded by this process counts even if the store's view is stale.
	h2 := newHarness(nil, []model.Asset{a}, act)
	h2.r.last[ScanKey{1, "net.x"}] = store.ScanLast{LastAttempt: h2.now.Add(-time.Minute), LastSuccess: h2.now.Add(-time.Minute)}
	if n, _ := h2.r.scheduleTier(context.Background(), model.TierActive); n != 0 {
		t.Fatal("recent local scan ignored")
	}
}

func TestIsDue(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	for _, tc := range []struct {
		name  string
		last  store.ScanLast
		iv    time.Duration
		retry time.Duration
		want  bool
	}{
		{"never run", store.ScanLast{}, time.Hour, 10 * time.Minute, true},
		{"succeeded recently", store.ScanLast{LastAttempt: ago(time.Minute), LastSuccess: ago(time.Minute)}, time.Hour, 10 * time.Minute, false},
		{"succeeded long ago", store.ScanLast{LastAttempt: ago(2 * time.Hour), LastSuccess: ago(2 * time.Hour)}, time.Hour, 10 * time.Minute, true},
		{"succeeded exactly one interval ago", store.ScanLast{LastAttempt: ago(time.Hour), LastSuccess: ago(time.Hour)}, time.Hour, 10 * time.Minute, true},
		{"never succeeded, failed just now", store.ScanLast{LastAttempt: ago(time.Second)}, time.Hour, 10 * time.Minute, false},
		{"never succeeded, failed long ago", store.ScanLast{LastAttempt: ago(30 * time.Minute)}, time.Hour, 10 * time.Minute, true},
		{"old success, failed just now", store.ScanLast{LastAttempt: ago(time.Minute), LastSuccess: ago(3 * time.Hour)}, time.Hour, 10 * time.Minute, false},
		{"old success, failed long ago", store.ScanLast{LastAttempt: ago(20 * time.Minute), LastSuccess: ago(3 * time.Hour)}, time.Hour, 10 * time.Minute, true},
		{"recent success, later failure is not due", store.ScanLast{LastAttempt: ago(time.Minute), LastSuccess: ago(30 * time.Minute)}, time.Hour, 10 * time.Minute, false},
		{"retry capped by a short interval", store.ScanLast{LastAttempt: ago(2 * time.Minute)}, time.Minute, 10 * time.Minute, true},
	} {
		if got := isDue(tc.last, now, tc.iv, tc.retry); got != tc.want {
			t.Errorf("%s: isDue=%v want %v", tc.name, got, tc.want)
		}
	}
}

// A failed attempt must not hammer: it is retried after min(interval,
// scheduling.error_retry), while a success waits the full interval.
func TestScheduleTierRetriesFailuresSoonerButNotImmediately(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	chk := passiveCheck("dns.x") // passive interval 5m in baseCfg; use a longer one
	h := newHarness(func(c *testCfg) {
		c.Profiles.Passive.Interval = 6 * time.Hour
		c.Scheduling.ErrorRetry = 10 * time.Minute
	}, []model.Asset{a}, chk)
	h.st.scans = []store.ScanRun{{AssetID: 1, Check: "dns.x", StartedAt: h.now.Add(-time.Minute), Error: "boom"}}
	if n, _ := h.r.scheduleTier(context.Background(), model.TierPassive); n != 0 {
		t.Fatalf("failed 1m ago, retry 10m: queued %d", n)
	}
	h.st.scans = []store.ScanRun{{AssetID: 1, Check: "dns.x", StartedAt: h.now.Add(-15 * time.Minute), Error: "boom"}}
	if n, _ := h.r.scheduleTier(context.Background(), model.TierPassive); n != 1 {
		t.Fatalf("failed 15m ago, retry 10m: queued %d", n)
	}
	// A success 15m ago with a 6h interval is not due.
	h2 := newHarness(func(c *testCfg) { c.Profiles.Passive.Interval = 6 * time.Hour }, []model.Asset{a}, chk)
	h2.st.scans = []store.ScanRun{{AssetID: 1, Check: "dns.x", StartedAt: h2.now.Add(-15 * time.Minute)}}
	if n, _ := h2.r.scheduleTier(context.Background(), model.TierPassive); n != 0 {
		t.Fatalf("succeeded 15m ago: queued %d", n)
	}
}

func TestHousekeeping(t *testing.T) {
	h := newHarness(nil, nil)
	if err := h.r.housekeeping(context.Background()); err != nil || h.st.expired != 1 {
		t.Fatalf("err=%v expired=%d", err, h.st.expired)
	}
}

func TestJitterSchedule(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		rnd  float64
		want time.Duration
	}{{0, 9 * time.Minute}, {0.5, 10 * time.Minute}, {1, 11 * time.Minute}} {
		s := jitterSchedule{interval: 10 * time.Minute, frac: 0.1, rnd: func() float64 { return tc.rnd }}
		if got := s.Next(t0).Sub(t0); got != tc.want {
			t.Errorf("rnd=%v: %v want %v", tc.rnd, got, tc.want)
		}
	}
	s := jitterSchedule{interval: 10 * time.Minute, frac: 0.1}
	for i := 0; i < 100; i++ {
		if d := s.Next(t0).Sub(t0); d < 9*time.Minute || d > 11*time.Minute {
			t.Fatalf("jitter out of range: %v", d)
		}
	}
}

func TestMemQueueDedupes(t *testing.T) {
	q := newMemQueue()
	j := scanJob{AssetID: 1, Tier: model.TierPassive, Check: "c"}
	if ok, _ := q.enqueueScan(context.Background(), j); !ok {
		t.Fatal("first insert")
	}
	if ok, _ := q.enqueueScan(context.Background(), j); ok {
		t.Fatal("duplicate accepted")
	}
	if len(q.take()) != 1 || len(q.take()) != 0 {
		t.Fatal("take semantics")
	}
	if ok, _ := q.enqueueScan(context.Background(), j); ok {
		t.Fatal("job re-queued after take within one pass")
	}
}

func unresolvedFinding(id int64, assetID int64, chk string, st model.FindingStatus) model.Finding {
	return model.Finding{ID: id, Fingerprint: "fp" + string(rune('a'+id)), Check: chk, AssetID: assetID, Status: st,
		Severity: model.SeverityHigh, Evidence: map[string]any{"template_id": "tpl-" + string(rune('a'+id))}}
}

// Target.OpenFindings is filled only for checks that ask for it, from one
// bounded query for this asset and check; resolved findings are excluded.
func TestRunScanOpenFindingsOnlyForChecksThatWantThem(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	plain := passiveCheck("c.plain")
	wants := wantsCheck{passiveCheck("c.wants")}
	h := newHarness(nil, []model.Asset{a}, plain, wants)
	h.st.findings = []model.Finding{
		unresolvedFinding(1, 1, "c.wants", model.StatusOpen),
		unresolvedFinding(2, 1, "c.wants", model.StatusAcknowledged),
		unresolvedFinding(3, 1, "c.wants", model.StatusSuppressed),
		unresolvedFinding(4, 1, "c.wants", model.StatusFalsePositive),
		unresolvedFinding(5, 1, "c.wants", model.StatusResolved), // not unresolved
		unresolvedFinding(6, 1, "c.plain", model.StatusOpen),     // other check
		unresolvedFinding(7, 2, "c.wants", model.StatusOpen),     // other asset
	}
	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}
	if len(plain.targets) != 1 || plain.targets[0].OpenFindings != nil {
		t.Fatalf("a check that did not ask got open findings: %+v", plain.targets)
	}
	if len(wants.targets) != 1 || len(wants.targets[0].OpenFindings) != 4 {
		t.Fatalf("open findings = %+v, want the 4 unresolved of this asset and check", wants.targets)
	}
	if got := wants.targets[0].OpenFindings[0]; got.Fingerprint == "" || got.Evidence["template_id"] == nil || got.Status != model.StatusOpen {
		t.Errorf("finding view = %+v", got)
	}
	if len(h.st.findingsReqs) != 1 {
		t.Fatalf("queries = %d, want exactly 1 (not run for the plain check)", len(h.st.findingsReqs))
	}
	if r := h.st.findingsReqs[0]; r.Limit != check.MaxOpenFindings || r.AssetID != 1 || r.Check != "c.wants" {
		t.Errorf("query = %+v", r)
	}
}

// A failed lookup fails the run before the check executes: a re-verifying
// check must not run blind.
func TestRunScanOpenFindingsLookupFailureFailsTheRun(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	wants := wantsCheck{passiveCheck("c.wants")}
	h := newHarness(nil, []model.Asset{a}, wants)
	h.st.findingsErr = errors.New("db down")
	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}
	if wants.calls.Load() != 0 || len(h.proc.calls) != 0 {
		t.Fatal("the check ran or findings were processed despite the failed lookup")
	}
	runs := h.st.runs()
	if len(runs) != 1 || !strings.Contains(runs[0].Error, "open findings") {
		t.Fatalf("runs = %+v", runs)
	}
}

// Target.Baseline holds other checks' baselines only for checks that ask for
// them (and only the ones that exist); the check's own is always loaded.
func TestRunScanOtherBaselinesOnlyForChecksThatWantThem(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	plain := passiveCheck("c.plain")
	wants := baselinesCheck{passiveCheck("c.wants"), []string{"net.ports", "c.wants", "never.ran"}}
	h := newHarness(nil, []model.Asset{a}, plain, wants)
	h.st.baselines[ScanKey{1, "net.ports"}] = &store.Baseline{AssetID: 1, Check: "net.ports", Data: map[string]any{"ports": []any{"22"}}}
	h.st.baselines[ScanKey{1, "c.wants"}] = &store.Baseline{AssetID: 1, Check: "c.wants", Data: map[string]any{"own": true}}
	h.st.baselines[ScanKey{2, "net.ports"}] = &store.Baseline{AssetID: 2, Check: "net.ports", Data: map[string]any{"other": "asset"}}
	if err := h.r.runScan(context.Background(), scanJob{AssetID: 1, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}
	if got := plain.targets[0].Baseline; len(got) != 0 {
		t.Errorf("a check that did not ask got baselines: %v", got)
	}
	got := wants.targets[0].Baseline
	if len(got) != 2 || got["net.ports"]["ports"] == nil || got["c.wants"]["own"] != true {
		t.Errorf("baselines = %v, want net.ports and its own, nothing for never.ran", got)
	}
	if _, ok := got["never.ran"]; ok {
		t.Error("a missing baseline must stay absent")
	}
}
