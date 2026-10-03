package engine

import (
	"context"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// TestIntegrationExpandZone runs expansion on real River and Postgres: the
// scheduler role enqueues one expand_zone job for the owned zone, the worker
// runs it, the discovered owned name is added and immediately scanned, and the
// out-of-scope candidate (a name the Guard does not classify as owned) is
// dropped. A duplicate insert for the same zone is skipped by River.
func TestIntegrationExpandZone(t *testing.T) {
	st, pool := migratedDB(t)
	cfg := baseCfg()
	cfg.Sync.Interval = time.Hour
	cfg.Expansion = config.ExpansionConfig{CTLogs: true, Interval: time.Hour}
	cfg.Scope = config.ScopeConfig{Include: []string{"example.com", "*.example.com"}}
	g, err := scope.NewGuard(cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeSource{name: "fake", disc: &source.Discovery{Assets: []model.AssetInput{
		{Kind: model.KindZone, Key: "example.com", Source: "fake", Zone: "example.com"},
	}}}
	chk := &recordingCheck{name: "p.rec", tier: model.TierPassive}
	fx := &fakeExpander{res: ExpandResult{CT: cand("example.com", "ct", "new.example.com", "evil.attacker.net")}}
	e, err := New(Deps{
		Config: cfg, Store: st, Guard: g, Inventory: &ownedOnlyInventory{dbInventory{st, g}, g}, Findings: &fakeProc{},
		Recorder: newFakeRec(), Checks: []check.Check{chk}, Sources: []source.Source{src}, Pool: pool,
		Expander: fx,
	}, WithRoles(RoleAPI, RoleScheduler, RoleWorker), WithTickInterval(time.Hour), WithGaugeInterval(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		_ = e.Stop(sctx)
	}()

	eventually(t, "expanded host added and scanned", func() bool {
		for _, r := range scanRuns(t, st) {
			if r.Check == "p.rec" {
				a, err := st.GetAsset(ctx, r.AssetID)
				if err == nil && a.Key == "new.example.com" {
					return true
				}
			}
		}
		return false
	})
	assets, _, _ := st.ListAssets(ctx, store.AssetFilter{})
	for _, a := range assets {
		if a.Key == "evil.attacker.net" {
			t.Fatal("non-owned candidate reached the inventory")
		}
	}
	zones, _, _ := st.ListAssets(ctx, store.AssetFilter{Kind: model.KindZone})
	if len(zones) != 1 {
		t.Fatalf("zones: %+v", zones)
	}
	ok1, err := e.r.q.enqueueExpand(ctx, zones[0].ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ok2, err := e.r.q.enqueueExpand(ctx, zones[0].ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = ok1 // may be false if the periodic tick already queued this zone
	if ok2 {
		t.Fatalf("unique-per-zone: first=%v second=%v", ok1, ok2)
	}
}

// ownedOnlyInventory mirrors inventory.Service.AddDiscovered, which drops
// everything the Guard does not classify as owned.
type ownedOnlyInventory struct {
	dbInventory
	g *scope.Guard
}

func (i *ownedOnlyInventory) AddDiscovered(ctx context.Context, origin string, in []model.AssetInput, rels []model.RelationInput) (store.InventoryDiff, error) {
	var keep []model.AssetInput
	for _, a := range in {
		if i.g.Classify(a.Kind, a.Key) == model.ScopeOwned {
			keep = append(keep, a)
		}
	}
	return i.dbInventory.AddDiscovered(ctx, origin, keep, rels)
}

// TestIntegrationExpandSnoozesWhileCTIsDown: on real River, a CT source that
// keeps answering 502 leaves the zone's job snoozed (scheduled ~5m out, no
// attempt used, no error recorded) instead of erroring and retrying; the
// zone keeps exactly one expansion job meanwhile.
func TestIntegrationExpandSnoozesWhileCTIsDown(t *testing.T) {
	st, pool := migratedDB(t)
	cfg := baseCfg()
	cfg.Sync.Interval = time.Hour
	cfg.Expansion = config.ExpansionConfig{CTLogs: true, Interval: 6 * time.Hour}
	cfg.Scope = config.ScopeConfig{Include: []string{"example.com"}}
	g, err := scope.NewGuard(cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeSource{name: "fake", disc: &source.Discovery{Assets: []model.AssetInput{
		{Kind: model.KindZone, Key: "example.com", Source: "fake", Zone: "example.com"},
	}}}
	fx := &fakeExpander{err: ct502("example.com")}
	e, err := New(Deps{
		Config: cfg, Store: st, Guard: g, Inventory: &ownedOnlyInventory{dbInventory{st, g}, g}, Findings: &fakeProc{},
		Recorder: newFakeRec(), Sources: []source.Source{src}, Pool: pool, Expander: fx,
	}, WithRoles(RoleScheduler, RoleWorker), WithTickInterval(time.Hour), WithGaugeInterval(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		_ = e.Stop(sctx)
	}()

	type jobRow struct {
		state       string
		attempt     int
		errs        int
		snoozes     string
		scheduledIn time.Duration
	}
	var jobs []jobRow
	eventually(t, "expansion job snoozed", func() bool {
		rows, err := pool.Query(ctx, `SELECT state, attempt, coalesce(array_length(errors, 1), 0),
			coalesce(metadata->>'snoozes', ''), scheduled_at - now() FROM river_job WHERE kind = $1`, KindExpandZone)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		jobs = jobs[:0]
		for rows.Next() {
			var j jobRow
			if err := rows.Scan(&j.state, &j.attempt, &j.errs, &j.snoozes, &j.scheduledIn); err != nil {
				t.Fatal(err)
			}
			jobs = append(jobs, j)
		}
		return len(jobs) == 1 && jobs[0].snoozes == "1"
	})
	j := jobs[0]
	if j.state != "scheduled" || j.attempt != 0 || j.errs != 0 {
		t.Fatalf("job = %+v, want scheduled with no attempt used and no error recorded", j)
	}
	if j.scheduledIn < 4*time.Minute || j.scheduledIn > 6*time.Minute {
		t.Fatalf("snoozed for %v, want about 5m", j.scheduledIn)
	}
	zones, _, _ := st.ListAssets(ctx, store.AssetFilter{Kind: model.KindZone})
	if ok, err := e.r.q.enqueueExpand(ctx, zones[0].ID, 0); err != nil || ok {
		t.Fatalf("a snoozed zone must keep its single job: inserted=%v err=%v", ok, err)
	}
}
