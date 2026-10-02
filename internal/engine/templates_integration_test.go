package engine

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei"
	"github.com/chainseer-xyz/deckard/internal/nuclei/updater"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// templateEngine builds an engine on real River/Postgres with fake template
// collaborators and one owned URL asset already in the store.
func templateEngine(t *testing.T, roles []string, opts ...Option) (*Engine, *pgxpool.Pool, *fakeTemplates, *fakeDelta, *fakeProc, store.Store) {
	t.Helper()
	return templateEngineCfg(t, roles, nil, opts...)
}

func templateEngineCfg(t *testing.T, roles []string, mut func(*config.Config), opts ...Option) (*Engine, *pgxpool.Pool, *fakeTemplates, *fakeDelta, *fakeProc, store.Store) {
	t.Helper()
	st, pool := migratedDB(t)
	cfg := baseCfg()
	cfg.Sync.Interval = time.Hour
	cfg.Scope = config.ScopeConfig{Include: []string{"*.example.com"}}
	cfg.Nuclei.Update = config.NucleiUpdateConfig{Enabled: true, Interval: 6 * time.Hour, RunNewTemplates: true}
	if mut != nil {
		mut(&cfg)
	}
	g, err := scope.NewGuard(cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := st.AddDiscovered(ctx, []store.AssetUpsert{{
		AssetInput: model.AssetInput{Kind: model.KindURL, Key: "https://app.example.com/", Source: "fake", Zone: "example.com"},
		Scope:      model.ScopeOwned,
	}}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	tpl := &fakeTemplates{up: updater.Update{
		Changed: true, Version: "v10.5.0", TemplateCount: 5000,
		NewTemplates: []string{"http/cves/2025/CVE-2025-55182.yaml"}, NewIDs: []string{"CVE-2025-55182"},
	}}
	dl := &fakeDelta{
		res:      nuclei.ScanResult{},
		cveTable: map[string][]string{"CVE-2025-55182": {"http/cves/2025/CVE-2025-55182.yaml"}},
	}
	proc := &fakeProc{}
	e, err := New(Deps{
		Config: cfg, Store: st, Guard: g, Inventory: &dbInventory{st, g}, Findings: proc,
		Recorder: newFakeRec(), Checks: []check.Check{}, Pool: pool, Templates: tpl, Delta: dl,
	}, append([]Option{WithRoles(roles...), WithTickInterval(time.Hour), WithGaugeInterval(time.Hour),
		WithTemplateGuard(-1, 0)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return e, pool, tpl, dl, proc, st
}

func riverJobs(t *testing.T, pool *pgxpool.Pool, kind string) (queues []string, n int) {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT queue FROM river_job WHERE kind = $1`, kind)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var q string
		if err := rows.Scan(&q); err != nil {
			t.Fatal(err)
		}
		queues = append(queues, q)
		n++
	}
	return queues, n
}

func startStop(t *testing.T, e *Engine) {
	t.Helper()
	ctx := context.Background()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		_ = e.Stop(sctx)
	})
}

// The full River path: the scheduler's periodic job runs update_templates on
// the maintenance queue shortly after start; an update that added templates
// queues scan_new_templates on the active queue; the worker scans the owned web
// asset and reconciles the finding as a partial run.
func TestIntegrationUpdateJobQueuesAndRunsNewTemplateScans(t *testing.T) {
	e, pool, tpl, dl, _, _ := templateEngine(t, []string{RoleAPI, RoleScheduler, RoleWorker})
	dl.res = nuclei.ScanResult{Findings: map[int64][]model.FindingInput{}}
	startStop(t, e)

	eventually(t, "update_templates job executed", func() bool { return slices.Contains(tpl.called(), "update") })
	eventually(t, "new-template scan executed", func() bool { return len(dl.requests()) >= 1 })
	reqs := dl.requests()
	if len(reqs) != 1 || len(reqs[0].Targets) != 1 || reqs[0].Targets[0].URL != "https://app.example.com/" ||
		!slices.Equal(reqs[0].Templates, []string{"/tpl/http/cves/2025/CVE-2025-55182.yaml"}) {
		t.Fatalf("scan requests = %+v", reqs)
	}
	if q, n := riverJobs(t, pool, KindUpdateTemplates); n != 1 || q[0] != QueueMaintenance {
		t.Errorf("update_templates jobs: queues=%v", q)
	}
	if q, n := riverJobs(t, pool, KindScanNewTemplates); n != 1 || q[0] != QueueActive {
		t.Errorf("scan_new_templates jobs: queues=%v", q)
	}
	// The periodic job fires once at start, not in a loop.
	time.Sleep(500 * time.Millisecond)
	if n := len(tpl.called()); n != 1 {
		t.Errorf("updater calls = %v, want exactly the start-up update", tpl.called())
	}
}

func TestIntegrationDeltaFindingIsAPartialRun(t *testing.T) {
	e, _, _, dl, proc, st := templateEngine(t, []string{RoleAPI, RoleScheduler, RoleWorker})
	ctx := context.Background()
	assets, _, _ := st.ListAssets(ctx, store.AssetFilter{})
	dl.res = nuclei.ScanResult{Findings: map[int64][]model.FindingInput{
		assets[0].ID: {{Check: "cve.nuclei", Key: "CVE-2025-55182", Severity: model.SeverityCritical, Title: "RSC RCE"}},
	}}
	startStop(t, e)
	eventually(t, "finding processed", func() bool {
		proc.mu.Lock()
		defer proc.mu.Unlock()
		return len(proc.calls) == 1
	})
	c := proc.calls[0]
	if c.check != "cve.nuclei" || !c.res.Partial || c.asset.ID != assets[0].ID || c.res.Findings[0].Key != "CVE-2025-55182" {
		t.Fatalf("Process call = %+v", c)
	}
	eventually(t, "delta scan recorded", func() bool {
		for _, r := range scanRuns(t, st) {
			if r.Check == DeltaCheck && r.Findings == 1 && r.Error == "" {
				return true
			}
		}
		return false
	})
}

// Only the scheduler schedules the update; an api-only replica schedules and
// runs nothing; a scheduler without workers leaves the job for a worker node.
func TestIntegrationUpdateIsScheduledOnTheSchedulerOnly(t *testing.T) {
	t.Run("scheduler only: queued on maintenance, not run", func(t *testing.T) {
		e, pool, tpl, _, _, _ := templateEngine(t, []string{RoleScheduler})
		startStop(t, e)
		eventually(t, "update_templates queued", func() bool { _, n := riverJobs(t, pool, KindUpdateTemplates); return n == 1 })
		if q, _ := riverJobs(t, pool, KindUpdateTemplates); q[0] != QueueMaintenance {
			t.Errorf("queue = %v", q)
		}
		time.Sleep(300 * time.Millisecond)
		if len(tpl.called()) != 0 {
			t.Errorf("a scheduler-only node ran the update: %v", tpl.called())
		}
	})
	t.Run("api only: nothing scheduled", func(t *testing.T) {
		e, pool, tpl, _, _, _ := templateEngine(t, []string{RoleAPI})
		startStop(t, e)
		time.Sleep(500 * time.Millisecond)
		if _, n := riverJobs(t, pool, KindUpdateTemplates); n != 0 || len(tpl.called()) != 0 {
			t.Errorf("api-only node scheduled/ran updates: jobs=%d calls=%v", n, tpl.called())
		}
	})
	t.Run("disabled by config: nothing scheduled", func(t *testing.T) {
		e, pool, tpl, _, _, _ := templateEngineCfg(t, []string{RoleScheduler, RoleWorker},
			func(c *config.Config) { c.Nuclei.Update.Enabled = false },
			WithTemplateGuard(10*time.Millisecond, 20*time.Millisecond))
		startStop(t, e)
		time.Sleep(600 * time.Millisecond)
		if _, n := riverJobs(t, pool, KindUpdateTemplates); n != 0 || len(tpl.called()) != 0 {
			t.Errorf("opted-out node scheduled/ran updates: jobs=%d calls=%v", n, tpl.called())
		}
	})
}

func TestIntegrationUpdateJobIsUnique(t *testing.T) {
	e, pool, _, _, _, _ := templateEngine(t, []string{RoleAPI}) // insert-only: nothing consumes jobs
	ctx := context.Background()
	c := e.client
	for i, want := range []bool{true, false, false} {
		res, err := c.Insert(ctx, UpdateTemplatesArgs{}, nil)
		if err != nil || res.UniqueSkippedAsDuplicate == want {
			t.Fatalf("insert %d: dup=%v err=%v", i, res != nil && res.UniqueSkippedAsDuplicate, err)
		}
	}
	if _, n := riverJobs(t, pool, KindUpdateTemplates); n != 1 {
		t.Errorf("update_templates jobs = %d, want 1", n)
	}
}

// EnqueueCVEScan from an API-only replica (no workers, no templates locally):
// jobs are queued on the active queue and deduplicated; a worker picks them up.
func TestIntegrationEnqueueCVEScanFromAPIReplica(t *testing.T) {
	api, pool, _, _, _, _ := templateEngine(t, []string{RoleAPI})
	ctx := context.Background()
	n, err := api.EnqueueCVEScan(ctx, []string{"cve-2025-55182"})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if n, err := api.EnqueueCVEScan(ctx, []string{"CVE-2025-55182"}); err != nil || n != 0 {
		t.Fatalf("repeat: n=%d err=%v (unique by args)", n, err)
	}
	if q, cnt := riverJobs(t, pool, KindScanCVEs); cnt != 1 || q[0] != QueueActive {
		t.Fatalf("scan_cves jobs: %v", q)
	}
	// A worker engine on the same database consumes it and looks the CVE up.
	worker, err := New(Deps{
		Config: api.d.Config, Store: api.d.Store, Guard: api.d.Guard, Inventory: api.d.Inventory, Findings: &fakeProc{},
		Recorder: newFakeRec(), Pool: pool, Delta: &fakeDelta{cveTable: map[string][]string{"CVE-2025-55182": {"http/cves/2025/CVE-2025-55182.yaml"}}},
	}, WithRoles(RoleWorker), WithGaugeInterval(time.Hour), WithTemplateGuard(-1, 0))
	if err != nil {
		t.Fatal(err)
	}
	startStop(t, worker)
	dl := worker.d.Delta.(*fakeDelta)
	eventually(t, "scan_cves executed by the worker", func() bool { return len(dl.requests()) == 1 })
	if got := dl.lookups; len(got) != 1 || !slices.Equal(got[0], []string{"CVE-2025-55182"}) {
		t.Errorf("lookups = %v", got)
	}
}

// A worker-only node (separate replica/volume) keeps its own templates fresh.
func TestIntegrationWorkerCatchUpLoop(t *testing.T) {
	e, _, tpl, _, _, _ := templateEngine(t, []string{RoleWorker}, WithTemplateGuard(10*time.Millisecond, 50*time.Millisecond))
	startStop(t, e)
	eventually(t, "catch-up update", func() bool {
		for _, c := range tpl.called() {
			if c == "ifolder:7h30m0s" {
				return true
			}
		}
		return false
	})
	// A scheduler-only node does not run a loop (it executes no jobs at all).
	e2, _, tpl2, _, _, _ := templateEngine(t, []string{RoleScheduler}, WithTemplateGuard(10*time.Millisecond, 50*time.Millisecond))
	startStop(t, e2)
	time.Sleep(400 * time.Millisecond)
	for _, c := range tpl2.called() {
		t.Errorf("scheduler-only node updated: %s", c)
	}
}
