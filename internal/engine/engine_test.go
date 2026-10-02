package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func newTestEngine(t *testing.T, cfg func(*testCfg), assets []model.Asset, checks ...check.Check) (*Engine, *harness) {
	t.Helper()
	h := newHarness(cfg, assets, checks...)
	e, err := New(h.r.Deps, WithRoles(RoleAPI, RoleScheduler, RoleWorker))
	if err != nil {
		t.Fatal(err)
	}
	return e, h
}

func TestNewValidation(t *testing.T) {
	h := newHarness(nil, nil)
	d := h.r.Deps
	for name, mut := range map[string]func(*Deps){
		"no store":     func(d *Deps) { d.Store = nil },
		"no guard":     func(d *Deps) { d.Guard = nil },
		"no inventory": func(d *Deps) { d.Inventory = nil },
		"no findings":  func(d *Deps) { d.Findings = nil },
		"dup checks":   func(d *Deps) { d.Checks = []check.Check{passiveCheck("x"), passiveCheck("x")} },
	} {
		dd := d
		mut(&dd)
		if _, err := New(dd); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := New(d, WithRoles("bogus")); err == nil {
		t.Error("bogus role accepted")
	}
	if _, err := New(d, WithQueueWorkers(map[string]int{QueueActive: 0})); err == nil {
		t.Error("zero-worker queue accepted")
	}
	e, err := New(d)
	if err != nil || !e.roles[RoleWorker] || !e.roles[RoleScheduler] || !e.roles[RoleAPI] {
		t.Fatalf("default roles: %v %v", e, err)
	}
	// Roles come from config when no option is given.
	d.Config.Server.Roles = []string{RoleAPI}
	e, _ = New(d)
	if e.roles[RoleWorker] {
		t.Error("config roles ignored")
	}
}

func TestStartWithoutPool(t *testing.T) {
	e, _ := newTestEngine(t, nil, nil)
	if err := e.Start(context.Background()); !errors.Is(err, ErrNoQueue) {
		t.Fatalf("worker role without pool: %v", err)
	}
	h := newHarness(nil, nil)
	api, _ := New(h.r.Deps, WithRoles(RoleAPI))
	if err := api.Start(context.Background()); err != nil {
		t.Fatalf("api-only start is a no-op: %v", err)
	}
	if err := api.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRescanAsset(t *testing.T) {
	host := hostAsset(1, "a.example.com")
	ipShared := model.Asset{ID: 2, Kind: model.KindIP, Key: "104.16.0.1"}
	pc := passiveCheck("p.one")
	ac := &fakeCheck{name: "a.one", tier: model.TierActive}
	ic := &fakeCheck{name: "i.one", tier: model.TierIntrusive}
	e, h := newTestEngine(t, nil, []model.Asset{host, ipShared}, pc, ac, ic)
	h.g.classes[ipShared.Key] = model.ScopeShared
	e.r.q = h.q

	if err := e.RescanAsset(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	// Intrusive profile is off: not queued. Due-ness is bypassed (no history needed here).
	if got := h.q.keys(); len(got) != 2 || got[0] != "1|active|a.one" || got[1] != "1|passive|p.one" {
		t.Fatalf("queued %v", got)
	}
	// Bypasses the due check even right after a scan.
	h.q = newRecQueue()
	e.r.q = h.q
	e.r.last[ScanKey{1, "p.one"}] = store.ScanLast{LastAttempt: h.now, LastSuccess: h.now}
	if err := e.RescanAsset(context.Background(), 1); err != nil || len(h.q.keys()) != 2 {
		t.Fatalf("recent scan blocked rescan: %v %v", err, h.q.keys())
	}

	// Scope check is NOT bypassed.
	if err := e.RescanAsset(context.Background(), 2); !errors.Is(err, ErrNotScannable) {
		t.Fatalf("shared ip: %v", err)
	}
	if err := e.RescanAsset(context.Background(), 404); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing asset: %v", err)
	}
}

func TestTriggerSync(t *testing.T) {
	src := &fakeSource{name: "cf"}
	e, h := newTestEngine(t, func(c *testCfg) { c.sources = append(c.sources, src) }, nil)
	e.r.q = h.q
	if err := e.TriggerSync(context.Background(), "cf"); err != nil || len(h.q.syncs) != 1 || h.q.syncs[0] != "cf" {
		t.Fatalf("err=%v syncs=%v", err, h.q.syncs)
	}
	err := e.TriggerSync(context.Background(), "nope")
	var use *UnknownSourceError
	if !errors.Is(err, ErrUnknownSource) || !errors.As(err, &use) || use.Name != "nope" {
		t.Fatalf("unknown source error: %v", err)
	}
	if len(h.q.syncs) != 1 {
		t.Fatal("unknown source queued")
	}
	// Without a queue (no pool) the action fails clearly.
	e2, _ := newTestEngine(t, func(c *testCfg) { c.sources = append(c.sources, src) }, nil)
	if err := e2.TriggerSync(context.Background(), "cf"); !errors.Is(err, ErrNoQueue) {
		t.Fatalf("no queue: %v", err)
	}
}

func TestRunOnce(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	b := hostAsset(2, "b.example.com")
	shared := model.Asset{ID: 3, Kind: model.KindIP, Key: "104.16.0.1"}
	pc, ac, ic := passiveCheck("p.one"), &fakeCheck{name: "a.one", tier: model.TierActive}, &fakeCheck{name: "i.one", tier: model.TierIntrusive}
	good := &fakeSource{name: "good"}
	bad := &fakeSource{name: "bad"}
	e, h := newTestEngine(t, func(c *testCfg) { c.sources = []source.Source{good, bad} },
		[]model.Asset{a, b, shared}, pc, ac, ic)
	h.g.classes[shared.Key] = model.ScopeShared
	h.inv.syncDiff = store.InventoryDiff{Added: []model.Asset{a}}
	// Make the second source fail while the first succeeds.
	e.r.Inventory = &selectiveInv{fakeInv: h.inv, failFor: "bad"}

	err := e.RunOnce(context.Background())
	if err == nil {
		t.Fatal("source failure should be reported")
	}
	// Every due, in-scope asset scanned exactly once per applicable check, despite
	// asset a being queued by both the sync diff and the tier tick.
	if pc.calls.Load() != 2 || ac.calls.Load() != 2 {
		t.Fatalf("passive=%d active=%d, want 2 each", pc.calls.Load(), ac.calls.Load())
	}
	if ic.calls.Load() != 0 {
		t.Fatal("intrusive ran while disabled")
	}
	if len(h.st.runs()) != 4 {
		t.Fatalf("scan runs: %+v", h.st.runs())
	}
	if h.st.expired != 1 {
		t.Fatal("housekeeping not run")
	}
	// Second pass: nothing is due.
	pc.calls.Store(0)
	ac.calls.Store(0)
	h.st.scans = h.st.runs()
	for i := range h.st.scans {
		h.st.scans[i].StartedAt = h.now
	}
	_ = e.RunOnce(context.Background())
	if pc.calls.Load()+ac.calls.Load() != 0 {
		// 'a' is re-queued by the (still-reported) sync diff: passive only.
		if pc.calls.Load() != 1 || ac.calls.Load() != 0 {
			t.Fatalf("second pass ran passive=%d active=%d", pc.calls.Load(), ac.calls.Load())
		}
	}
}

// RunOnce follows discovery: a check that discovers a new asset gets it scanned
// in the same pass.
func TestRunOnceFollowsDiscovery(t *testing.T) {
	a := hostAsset(1, "a.example.com")
	n := hostAsset(2, "new.example.com")
	disc := &fakeCheck{name: "p.disc", tier: model.TierPassive,
		applies: func(x model.Asset) bool { return x.ID == 1 },
		run: func(context.Context, check.Target) (*check.Result, error) {
			return &check.Result{Discovered: []model.AssetInput{{Kind: model.KindHostname, Key: n.Key}}}, nil
		}}
	other := &fakeCheck{name: "p.other", tier: model.TierPassive, applies: func(x model.Asset) bool { return x.ID == 2 }}
	e, h := newTestEngine(t, nil, []model.Asset{a}, disc, other)
	h.inv.discDiff = store.InventoryDiff{Added: []model.Asset{n}}
	h.inv.onDiscovered = func() { // what the real inventory does: insert the asset
		h.st.mu.Lock()
		h.st.assets[n.ID] = n
		h.st.mu.Unlock()
	}
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if other.calls.Load() != 1 {
		t.Fatalf("discovered asset scanned %d times, want 1", other.calls.Load())
	}
}
