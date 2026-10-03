package engine

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/all"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// tierCheck is a check with no optional interfaces: it follows its tier.
type tierCheck struct {
	name string
	tier model.Tier
}

func (c tierCheck) Name() string             { return c.name }
func (c tierCheck) Tier() model.Tier         { return c.tier }
func (c tierCheck) Applies(model.Asset) bool { return true }
func (c tierCheck) Run(context.Context, check.Target) (*check.Result, error) {
	return &check.Result{}, nil
}

// slowTierCheck declares check.SlowLookups.
type slowTierCheck struct{ tierCheck }

func (slowTierCheck) SlowLookups() bool { return true }

// notSlowCheck implements check.SlowLookups but answers false.
type notSlowCheck struct{ tierCheck }

func (notSlowCheck) SlowLookups() bool { return false }

func TestScanQueueRouting(t *testing.T) {
	checks := []check.Check{
		tierCheck{"t.passive", model.TierPassive},
		tierCheck{"t.active", model.TierActive},
		tierCheck{"t.intrusive", model.TierIntrusive},
		slowTierCheck{tierCheck{"t.slow.passive", model.TierPassive}},
		slowTierCheck{tierCheck{"t.slow.active", model.TierActive}},
		notSlowCheck{tierCheck{"t.notslow", model.TierPassive}},
	}
	r := newRunner(Deps{Checks: checks})
	for _, tc := range []struct {
		job  scanJob
		want string
	}{
		{scanJob{Tier: model.TierPassive, Check: "t.passive"}, QueuePassive},
		{scanJob{Tier: model.TierActive, Check: "t.active"}, QueueActive},
		{scanJob{Tier: model.TierIntrusive, Check: "t.intrusive"}, QueueIntrusive},
		{scanJob{Tier: model.TierPassive, Check: "t.slow.passive"}, QueueIntel},
		{scanJob{Tier: model.TierActive, Check: "t.slow.active"}, QueueIntel},
		{scanJob{Tier: model.TierPassive, Check: "t.notslow"}, QueuePassive},
		// A job without a check name runs the whole tier and follows it.
		{scanJob{Tier: model.TierPassive}, QueuePassive},
		{scanJob{Tier: model.TierActive}, QueueActive},
		// A check the engine does not know (removed since the job was queued).
		{scanJob{Tier: model.TierPassive, Check: "t.gone"}, QueuePassive},
	} {
		if got := r.scanQueue(tc.job); got != tc.want {
			t.Errorf("%s/%s -> %q, want %q", tc.job.Tier, tc.job.Check, got, tc.want)
		}
	}
}

// TestScanQueueRoutingBuiltInChecks pins the routing of the real checks: the
// slow lookups land in intel, the DNS checks that carry the takeover signal
// stay in passive.
func TestScanQueueRoutingBuiltInChecks(t *testing.T) {
	r := newRunner(Deps{Checks: all.Checks(nil)})
	want := map[string]string{
		"web.history":      QueueIntel,
		"domain.expiry":    QueueIntel,
		"intel.internetdb": QueueIntel,
		"cloud.bucket":     QueueIntel,
		"domain.lookalike": QueueIntel,
		"dns.dangling":     QueuePassive,
		"dns.takeover":     QueuePassive,
		"dns.hygiene":      QueuePassive,
		"tls.cert":         QueuePassive,
		"http.probe":       QueuePassive,
	}
	for name, q := range want {
		if got := r.scanQueue(scanJob{Tier: model.TierPassive, Check: name}); got != q {
			t.Errorf("%s -> %q, want %q", name, got, q)
		}
	}
}

// TestEveryQueueHasDefaultWorkers fails when a queue is used by a job kind or
// by the routing but has no worker default: River would accept the jobs and
// never run them.
func TestEveryQueueHasDefaultWorkers(t *testing.T) {
	def := DefaultQueueWorkers()
	used := map[string]string{
		"sync_source":        SyncSourceArgs{}.InsertOpts().Queue,
		"schedule_tier":      ScheduleTierArgs{}.InsertOpts().Queue,
		"housekeeping":       HousekeepingArgs{}.InsertOpts().Queue,
		"expand_zone":        ExpandZoneArgs{}.InsertOpts().Queue,
		"schedule_expansion": ScheduleExpansionArgs{}.InsertOpts().Queue,
		"refresh_refdata":    RefreshRefdataArgs{}.InsertOpts().Queue,
		"update_templates":   UpdateTemplatesArgs{}.InsertOpts().Queue,
		"scan_new_templates": ScanNewTemplatesArgs{}.InsertOpts().Queue,
		"scan_cves":          ScanCVEsArgs{}.InsertOpts().Queue,
		"refresh_vulnintel":  RefreshVulnintelArgs{}.InsertOpts().Queue,
		"tier passive":       queueForTier(model.TierPassive),
		"tier active":        queueForTier(model.TierActive),
		"tier intrusive":     queueForTier(model.TierIntrusive),
		"slow lookups":       queueForScan(model.TierPassive, true),
	}
	for what, q := range used {
		if q == "" {
			continue // River's default queue, which is QueueDefault
		}
		if _, ok := def[q]; !ok {
			t.Errorf("%s uses queue %q, which has no entry in DefaultQueueWorkers", what, q)
		}
	}
	if def[QueueIntel] != 8 {
		t.Errorf("intel default workers = %d, want 8", def[QueueIntel])
	}
	// The returned map is the caller's.
	def[QueueIntel] = 99
	if DefaultQueueWorkers()[QueueIntel] != 8 {
		t.Error("DefaultQueueWorkers shares its map")
	}
}

// ---- real River + Postgres ----

const (
	slowName = "t.slow"
	fastName = "t.fast"
	actName  = "t.active"
	actSlow  = "t.active.slow"
)

// routingEngine builds an engine on a fresh database with a fake source of the
// given owned hostnames. wrap may replace the store the runner sees.
func routingEngine(t *testing.T, checks []check.Check, hosts []string, workers map[string]int, wrap func(store.Store) store.Store) *Engine {
	t.Helper()
	st, pool := migratedDB(t)
	cfg := baseCfg()
	cfg.Sync.Interval = time.Hour
	cfg.Profiles.Active.OnInventoryChange = true
	cfg.Scope = config.ScopeConfig{Include: []string{"*.example.com"}}
	g, err := scope.NewGuard(cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	var assets []model.AssetInput
	for _, h := range hosts {
		assets = append(assets, model.AssetInput{Kind: model.KindHostname, Key: h, Source: "fake", Zone: "example.com"})
	}
	var s store.Store = st
	if wrap != nil {
		s = wrap(st)
	}
	e, err := New(Deps{
		Config: cfg, Store: s, Guard: g, Inventory: &dbInventory{st, g}, Findings: &fakeProc{},
		Recorder: newFakeRec(), Checks: checks, Pool: pool,
		Sources: []source.Source{&fakeSource{name: "fake", disc: &source.Discovery{Assets: assets}}},
	}, WithRoles(RoleScheduler, RoleWorker), WithTickInterval(time.Hour), WithGaugeInterval(time.Hour),
		WithQueueWorkers(workers))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func routingChecks() []check.Check {
	return []check.Check{
		slowTierCheck{tierCheck{slowName, model.TierPassive}},
		tierCheck{fastName, model.TierPassive},
		tierCheck{actName, model.TierActive},
		slowTierCheck{tierCheck{actSlow, model.TierActive}},
	}
}

var wantQueue = map[string]string{
	slowName: QueueIntel, fastName: QueuePassive, actName: QueueActive, actSlow: QueueIntel,
}

// scanJobQueues maps check name -> the queues of its scan_asset rows.
func scanJobQueues(t *testing.T, pool *pgxpool.Pool) map[string][]string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT args->>'check', queue FROM river_job WHERE kind = 'scan_asset' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var c, q string
		if err := rows.Scan(&c, &q); err != nil {
			t.Fatal(err)
		}
		out[c] = append(out[c], q)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func assertRouted(t *testing.T, path string, pool *pgxpool.Pool, must ...string) {
	t.Helper()
	got := scanJobQueues(t, pool)
	for _, c := range must {
		if len(got[c]) == 0 {
			t.Errorf("%s: no scan job for %s (jobs: %v)", path, c, got)
		}
	}
	for c, qs := range got {
		for _, q := range qs {
			if q != wantQueue[c] {
				t.Errorf("%s: %s job in queue %q, want %q", path, c, q, wantQueue[c])
			}
		}
	}
}

func clearScanJobs(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `DELETE FROM river_job WHERE kind = 'scan_asset'`); err != nil {
		t.Fatal(err)
	}
}

// TestScanJobsRoutedOnEveryInsertPath checks the queue of the rows each path
// that inserts scan jobs leaves in river_job (the engine is not started, so
// nothing consumes them).
func TestScanJobsRoutedOnEveryInsertPath(t *testing.T) {
	e := routingEngine(t, routingChecks(), []string{"a.example.com"}, nil, nil)
	pool, ctx := e.d.Pool, context.Background()

	// On a new asset: the sync that finds it queues its immediate scans.
	if err := e.r.runSync(ctx, "fake"); err != nil {
		t.Fatal(err)
	}
	assertRouted(t, "on-new-asset", pool, slowName, fastName, actName, actSlow)

	// Scheduled ticks.
	clearScanJobs(t, pool)
	for _, tier := range []model.Tier{model.TierPassive, model.TierActive} {
		if _, err := e.r.scheduleTier(ctx, tier); err != nil {
			t.Fatal(err)
		}
	}
	assertRouted(t, "scheduled tick", pool, slowName, fastName, actName, actSlow)

	// Rescan API.
	clearScanJobs(t, pool)
	assets, _, err := e.d.Store.ListAssets(ctx, store.AssetFilter{})
	if err != nil || len(assets) != 1 {
		t.Fatalf("assets: %v %v", assets, err)
	}
	if err := e.RescanAsset(ctx, assets[0].ID); err != nil {
		t.Fatal(err)
	}
	assertRouted(t, "rescan API", pool, slowName, fastName, actName, actSlow)
}

// TestReclaimedJobsKeepTheirQueue: reclaiming the running jobs of a dead
// instance only changes their state; each goes back to the queue it was
// routed to.
func TestReclaimedJobsKeepTheirQueue(t *testing.T) {
	e := routingEngine(t, routingChecks(), []string{"a.example.com"}, nil, nil)
	e.o.reclaimSpread = 0
	pool, ctx := e.d.Pool, context.Background()
	if err := e.r.runSync(ctx, "fake"); err != nil {
		t.Fatal(err)
	}
	registerInstance(t, pool, "dead_host", 5*time.Minute)
	if _, err := pool.Exec(ctx, `UPDATE river_job SET state = 'running', attempt = 1,
		attempted_at = now() - interval '5 minutes', attempted_by = ARRAY['dead_host']
		WHERE kind = 'scan_asset'`); err != nil {
		t.Fatal(err)
	}
	got, err := e.reclaimOrphans(ctx)
	if err != nil || got.total() != 4 {
		t.Fatalf("reclaimed %v, %v", got, err)
	}
	assertRouted(t, "reclaim", pool, slowName, fastName, actName, actSlow)
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'scan_asset' AND state = 'retryable'`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("retryable jobs = %d, %v", n, err)
	}
}

// failFirstGets fails the first n GetAsset calls, as a database blip would.
type failFirstGets struct {
	store.Store
	left atomic.Int32
}

func (s *failFirstGets) GetAsset(ctx context.Context, id int64) (*model.Asset, error) {
	if s.left.Add(-1) >= 0 {
		return nil, context.DeadlineExceeded
	}
	return s.Store.GetAsset(ctx, id)
}

// TestRetriedJobsKeepTheirQueue drives River's own retry: both scan jobs fail
// once, are rescheduled by River, and the retry runs in the queue the job was
// inserted in.
func TestRetriedJobsKeepTheirQueue(t *testing.T) {
	flaky := &failFirstGets{}
	var real store.Store
	flaky.left.Store(2)
	checks := []check.Check{slowTierCheck{tierCheck{slowName, model.TierPassive}}, tierCheck{fastName, model.TierPassive}}
	e := routingEngine(t, checks, []string{"a.example.com"}, nil, func(s store.Store) store.Store {
		flaky.Store, real = s, s
		return flaky
	})
	ctx := context.Background()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := e.Stop(sctx); err != nil {
			t.Errorf("stop: %v", err)
		}
	}()
	eventually(t, "both jobs to fail once and be rescheduled", func() bool {
		var n int
		if err := e.d.Pool.QueryRow(ctx, `SELECT count(*) FROM river_job
			WHERE kind = 'scan_asset' AND coalesce(array_length(errors, 1), 0) >= 1`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 2
	})
	got := scanJobQueues(t, e.d.Pool)
	if !slices.Equal(got[slowName], []string{QueueIntel}) || !slices.Equal(got[fastName], []string{QueuePassive}) {
		t.Fatalf("queues after the first failure: %v", got)
	}
	eventually(t, "the retries to run and finish", func() bool {
		return len(scanRuns(t, real)) == 2
	})
	assertRouted(t, "retry", e.d.Pool, slowName, fastName)
}

// gateCheck blocks every run until release is closed.
type gateCheck struct {
	slowTierCheck
	started atomic.Int32
	done    atomic.Int32
	release chan struct{}
}

func (c *gateCheck) Run(ctx context.Context, _ check.Target) (*check.Result, error) {
	c.started.Add(1)
	defer c.done.Add(1)
	select {
	case <-c.release:
	case <-ctx.Done():
	}
	return &check.Result{}, nil
}

// countCheck counts finished runs.
type countCheck struct {
	tierCheck
	done atomic.Int32
}

func (c *countCheck) Run(context.Context, check.Target) (*check.Result, error) {
	c.done.Add(1)
	return &check.Result{}, nil
}

// TestSlowChecksDoNotStarveFastChecks models the production incident: a slow
// check waiting on a third-party service held the passive workers and left the
// fast DNS checks overdue. Here one engine runs a slow check on more assets
// than the passive queue has workers, and every slow run stays blocked until
// the test ends; the fast check of the same tier must still complete on every
// asset meanwhile. Nothing sleeps: the slow runs wait on a channel.
func TestSlowChecksDoNotStarveFastChecks(t *testing.T) {
	const passiveWorkers, intelWorkers, assets = 2, 2, 8
	slow := &gateCheck{slowTierCheck: slowTierCheck{tierCheck{slowName, model.TierPassive}}, release: make(chan struct{})}
	fast := &countCheck{tierCheck: tierCheck{fastName, model.TierPassive}}
	var hosts []string
	for _, h := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		hosts = append(hosts, h+".example.com")
	}
	if len(hosts) != assets {
		t.Fatal("test setup")
	}
	// Slow first, so a single shared queue would hand its workers to the slow
	// jobs before any fast job.
	e := routingEngine(t, []check.Check{slow, fast}, hosts,
		map[string]int{QueuePassive: passiveWorkers, QueueIntel: intelWorkers}, nil)
	ctx := context.Background()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			close(slow.release)
		}
	}
	defer func() {
		release()
		sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := e.Stop(sctx); err != nil {
			t.Errorf("stop: %v", err)
		}
	}()

	eventually(t, "every fast check to complete while the slow ones are blocked", func() bool {
		return fast.done.Load() == assets
	})
	if got := slow.done.Load(); got != 0 {
		t.Fatalf("%d slow runs finished: they were meant to still be running", got)
	}
	eventually(t, "the intel workers to be busy with slow runs", func() bool {
		return slow.started.Load() == intelWorkers
	})

	release()
	eventually(t, "the slow checks to drain", func() bool {
		return slow.done.Load() == assets
	})
}
