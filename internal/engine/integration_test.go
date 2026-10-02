package engine

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// dbInventory is the minimum real inventory: classify with the real guard and
// write through the real store.
type dbInventory struct {
	st store.Store
	g  *scope.Guard
}

func (i *dbInventory) ups(in []model.AssetInput) []store.AssetUpsert {
	var out []store.AssetUpsert
	for _, a := range in {
		out = append(out, store.AssetUpsert{AssetInput: a, Scope: i.g.Classify(a.Kind, a.Key)})
	}
	return out
}

func (i *dbInventory) Sync(ctx context.Context, src source.Source) (store.InventoryDiff, error) {
	d, err := src.Discover(ctx)
	if err != nil {
		return store.InventoryDiff{}, err
	}
	return i.st.ApplySnapshot(ctx, src.Name(), i.ups(d.Assets), d.Relations, time.Now())
}

func (i *dbInventory) AddDiscovered(ctx context.Context, _ string, in []model.AssetInput, rels []model.RelationInput) (store.InventoryDiff, error) {
	return i.st.AddDiscovered(ctx, i.ups(in), rels, time.Now())
}

func (i *dbInventory) ReplaceDerived(ctx context.Context, parent int64, origin string, in []model.AssetInput, rels []model.RelationInput) (store.InventoryDiff, error) {
	var keep []model.AssetInput
	for _, a := range in {
		if a.Source == "" {
			a.Source = origin
		}
		if i.g.Classify(a.Kind, a.Key) == model.ScopeOwned {
			keep = append(keep, a)
		}
	}
	return i.st.ReplaceDerived(ctx, parent, origin, i.ups(keep), rels, time.Now())
}

type recordingCheck struct {
	name string
	tier model.Tier
	mu   sync.Mutex
	keys []string
	hold time.Duration
}

func (c *recordingCheck) Name() string             { return c.name }
func (c *recordingCheck) Tier() model.Tier         { return c.tier }
func (c *recordingCheck) Applies(model.Asset) bool { return true }
func (c *recordingCheck) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	c.mu.Lock()
	c.keys = append(c.keys, t.Asset.Key)
	c.mu.Unlock()
	if c.hold > 0 {
		time.Sleep(c.hold) // deliberately ignores ctx: a long in-flight job
	}
	return &check.Result{}, nil
}
func (c *recordingCheck) ran() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.keys...)
}

func integrationSetup(t *testing.T, roles []string, chk check.Check, assets []model.AssetInput) (*Engine, store.Store, *fakeRec, *fakeSource, *fakeProc) {
	t.Helper()
	st, pool := migratedDB(t)
	cfg := baseCfg()
	cfg.Sync.Interval = time.Hour
	cfg.Scope = config.ScopeConfig{Include: []string{"*.example.com"}}
	g, err := scope.NewGuard(cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeSource{name: "fake", disc: &source.Discovery{Assets: assets}}
	rec, proc := newFakeRec(), &fakeProc{}
	e, err := New(Deps{
		Config: cfg, Store: st, Guard: g, Inventory: &dbInventory{st, g}, Findings: proc,
		Recorder: rec, Checks: []check.Check{chk}, Sources: []source.Source{src}, Pool: pool,
	}, WithRoles(roles...), WithTickInterval(time.Hour), WithGaugeInterval(100*time.Millisecond),
		WithQueueWorkers(map[string]int{QueueSync: 2, QueuePassive: 4, QueueActive: 2, QueueIntrusive: 1, QueueDefault: 2}))
	if err != nil {
		t.Fatal(err)
	}
	return e, st, rec, src, proc
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func scanRuns(t *testing.T, st store.Store) []store.ScanRun {
	t.Helper()
	r, err := st.ListScans(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestIntegrationSyncScanAndSafety runs the whole pipeline on real River and
// Postgres: sync adds assets, an immediate passive scan runs for the owned
// hostname only, a second sync enqueues nothing new, and a scan job forced onto
// a shared-IP asset is refused without ever calling the check.
func TestIntegrationSyncScanAndSafety(t *testing.T) {
	chk := &recordingCheck{name: "p.rec", tier: model.TierPassive}
	e, st, rec, _, proc := integrationSetup(t, []string{RoleAPI, RoleScheduler, RoleWorker}, chk, []model.AssetInput{
		{Kind: model.KindHostname, Key: "app.example.com", Source: "fake", Zone: "example.com"},
		{Kind: model.KindIP, Key: "104.16.0.1", Source: "fake"}, // Cloudflare edge: shared
	})
	ctx := context.Background()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := e.Stop(sctx); err != nil {
			t.Errorf("stop: %v", err)
		}
	}
	defer stop()

	eventually(t, "asset in inventory and scanned", func() bool {
		return len(scanRuns(t, st)) >= 1
	})
	runs := scanRuns(t, st)
	if len(runs) != 1 || runs[0].Check != "p.rec" || runs[0].Tier != "passive" || runs[0].Error != "" {
		t.Fatalf("scan runs: %+v", runs)
	}
	assets, _, _ := st.ListAssets(ctx, store.AssetFilter{})
	if len(assets) != 2 {
		t.Fatalf("assets: %+v", assets)
	}
	var shared model.Asset
	for _, a := range assets {
		if a.Key == "104.16.0.1" {
			shared = a
		}
		if a.ID == runs[0].AssetID && a.Key != "app.example.com" {
			t.Fatalf("scanned %s", a.Key)
		}
	}
	if len(proc.calls) != 1 {
		t.Fatalf("processor calls: %d", len(proc.calls))
	}

	// Second sync: nothing changed, nothing new is queued or scanned.
	// (A trigger that lands while the first sync job is still finishing is
	// deduped by River, so keep triggering until a second sync is observed.)
	eventually(t, "second sync observed", func() bool {
		if err := e.TriggerSync(ctx, "fake"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.syncs["fake"]) >= 2
	})
	time.Sleep(500 * time.Millisecond)
	if n := len(scanRuns(t, st)); n != 1 {
		t.Fatalf("second sync produced extra scans: %d runs", n)
	}

	// SAFETY: force a scan job onto the shared IP straight through River.
	if _, err := e.r.q.enqueueScan(ctx, scanJob{AssetID: shared.ID, Tier: model.TierPassive}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "forced job refused", func() bool { return len(scanRuns(t, st)) >= 2 })
	var skipped *store.ScanRun
	for _, r := range scanRuns(t, st) {
		if r.AssetID == shared.ID {
			r := r
			skipped = &r
		}
	}
	if skipped == nil || !strings.HasPrefix(skipped.Error, SkippedPrefix) {
		t.Fatalf("shared asset run: %+v", skipped)
	}
	for _, k := range chk.ran() {
		if k == "104.16.0.1" {
			t.Fatal("check was run against a shared IP")
		}
	}

	// Queue depth gauge reports every queue.
	eventually(t, "queue depth gauge", func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		_, ok := rec.depth[QueuePassive]
		return ok
	})
	stop()
}

// TestIntegrationUniqueDedupe: the same (asset, tier, check) is never queued
// twice while a job is outstanding, distinct ones are, and a finished job does
// not block the next one.
func TestIntegrationUniqueDedupe(t *testing.T) {
	chk := &recordingCheck{name: "p.rec", tier: model.TierPassive}
	e, _, _, _, _ := integrationSetup(t, []string{RoleAPI}, chk, nil) // insert-only: nothing consumes jobs
	ctx := context.Background()
	j := scanJob{AssetID: 1, Tier: model.TierPassive, Check: "p.rec"}
	for i, want := range []bool{true, false, false} {
		got, err := e.r.q.enqueueScan(ctx, j)
		if err != nil || got != want {
			t.Fatalf("insert %d: got %v err %v want %v", i, got, err, want)
		}
	}
	for _, other := range []scanJob{
		{AssetID: 2, Tier: model.TierPassive, Check: "p.rec"},
		{AssetID: 1, Tier: model.TierActive, Check: "p.rec"},
		{AssetID: 1, Tier: model.TierPassive, Check: "p.other"},
	} {
		if ok, err := e.r.q.enqueueScan(ctx, other); err != nil || !ok {
			t.Fatalf("%+v: ok=%v err=%v", other, ok, err)
		}
	}
	if ok, _ := e.r.q.enqueueSync(ctx, "fake"); !ok {
		t.Fatal("first sync enqueue")
	}
	if ok, _ := e.r.q.enqueueSync(ctx, "fake"); ok {
		t.Fatal("duplicate sync job accepted")
	}
}

// TestIntegrationRerunsAfterCompletion: completed jobs must not dedupe future
// ones (River keeps completed rows for a day).
func TestIntegrationRerunsAfterCompletion(t *testing.T) {
	chk := &recordingCheck{name: "p.rec", tier: model.TierPassive}
	e, st, _, _, _ := integrationSetup(t, []string{RoleAPI, RoleScheduler, RoleWorker}, chk, []model.AssetInput{
		{Kind: model.KindHostname, Key: "app.example.com", Source: "fake", Zone: "example.com"},
	})
	ctx := context.Background()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		_ = e.Stop(sctx)
	}()
	eventually(t, "first scan", func() bool { return len(scanRuns(t, st)) >= 1 })
	time.Sleep(500 * time.Millisecond) // let the first job complete
	n0 := len(scanRuns(t, st))
	id := scanRuns(t, st)[0].AssetID
	if err := e.RescanAsset(ctx, id); err != nil {
		t.Fatal(err)
	}
	eventually(t, "rescan after completed job", func() bool { return len(scanRuns(t, st)) > n0 })
}

// TestIntegrationGracefulStop: Stop waits for an in-flight job to finish and
// its ScanRun is recorded; after Stop nothing more is fetched.
func TestIntegrationGracefulStop(t *testing.T) {
	chk := &recordingCheck{name: "p.rec", tier: model.TierPassive, hold: 1500 * time.Millisecond}
	e, st, _, _, _ := integrationSetup(t, []string{RoleAPI, RoleScheduler, RoleWorker}, chk, []model.AssetInput{
		{Kind: model.KindHostname, Key: "app.example.com", Source: "fake", Zone: "example.com"},
	})
	ctx := context.Background()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "check in flight", func() bool { return len(chk.ran()) == 1 })
	start := time.Now()
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := e.Stop(sctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Fatal("Stop returned before the in-flight job finished")
	}
	if n := len(scanRuns(t, st)); n != 1 {
		t.Fatalf("in-flight scan not recorded: %d runs", n)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatalf("second stop: %v", err)
	}
}

func TestMigrateIdempotentAndConcurrent(t *testing.T) {
	_, pool := migratedDB(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- Migrate(ctx, pool) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migrate: %v", err)
		}
	}
}
