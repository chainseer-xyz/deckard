package engine

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func expansionQueue(t *testing.T) (riverQueue, *pgxpool.Pool) {
	t.Helper()
	chk := &recordingCheck{name: "p.rec", tier: model.TierPassive}
	e, _, _, _, _ := integrationSetup(t, []string{RoleAPI}, chk, nil)
	return e.r.q.(riverQueue), e.d.Pool
}

func expansionJob(t *testing.T, pool *pgxpool.Pool) (int64, string, time.Time) {
	t.Helper()
	var id int64
	var state string
	var scheduledAt time.Time
	if err := pool.QueryRow(context.Background(), `SELECT id, state, scheduled_at
		FROM river_job WHERE kind = $1`, KindExpandZone).Scan(&id, &state, &scheduledAt); err != nil {
		t.Fatal(err)
	}
	return id, state, scheduledAt
}

// A periodic tick can see the committed zone before runSync queues its
// immediate expansion. The duplicate must remove that tick's fresh jitter.
func TestIntegrationImmediateExpansionPromotesFreshScheduledJob(t *testing.T) {
	q, pool := expansionQueue(t)
	ctx := context.Background()
	if inserted, err := q.enqueueExpand(ctx, 77, maxExpansionJitter); err != nil || !inserted {
		t.Fatalf("scheduled expansion: inserted=%v err=%v", inserted, err)
	}
	id, state, before := expansionJob(t, pool)
	if state != "scheduled" || time.Until(before) < 4*time.Minute {
		t.Fatalf("initial state=%s scheduled_at=%s", state, before)
	}
	if inserted, err := q.enqueueExpand(ctx, 77, 0); err != nil || inserted {
		t.Fatalf("immediate duplicate: inserted=%v err=%v", inserted, err)
	}
	gotID, gotState, after := expansionJob(t, pool)
	var due bool
	if err := pool.QueryRow(ctx, `SELECT scheduled_at <= now() FROM river_job WHERE id = $1`, id).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if gotID != id || gotState != "scheduled" || !due || !after.Before(before) {
		t.Fatalf("promotion: id=%d state=%s scheduled_at=%s; want original job due now", gotID, gotState, after)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = $1`, KindExpandZone).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expansion jobs=%d, want 1", count)
	}
}

func expansionJobSnapshot(t *testing.T, pool *pgxpool.Pool, id int64) string {
	t.Helper()
	var snapshot string
	if err := pool.QueryRow(context.Background(), `SELECT row_to_json(j)::text
		FROM river_job j WHERE id = $1`, id).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestIntegrationImmediateExpansionPreservesOutstandingJobs(t *testing.T) {
	cases := []struct {
		name, state, metadata string
		attempt               int
		attempted, errored    bool
		due                   bool
		delay                 time.Duration
	}{
		{name: "delayed duplicate keeps jitter", state: "scheduled", metadata: "{}", delay: time.Minute},
		{name: "available", state: "available", metadata: "{}"},
		{name: "pending", state: "pending", metadata: "{}"},
		{name: "running", state: "running", metadata: "{}", attempt: 1, attempted: true},
		{name: "retryable", state: "retryable", metadata: "{}", attempt: 1, attempted: true, errored: true},
		{name: "scheduled retry", state: "scheduled", metadata: "{}", attempt: 1, attempted: true, errored: true},
		{name: "snoozed", state: "scheduled", metadata: `{"snoozes":1}`, attempted: true},
		{name: "snooze metadata alone", state: "scheduled", metadata: `{"snoozes":1}`},
		{name: "previous attempt alone", state: "scheduled", metadata: "{}", attempted: true},
		{name: "attempt count alone", state: "scheduled", metadata: "{}", attempt: 1},
		{name: "error history alone", state: "scheduled", metadata: "{}", errored: true},
		{name: "already due", state: "scheduled", metadata: "{}", due: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, pool := expansionQueue(t)
			ctx := context.Background()
			if inserted, err := q.enqueueExpand(ctx, 77, maxExpansionJitter); err != nil || !inserted {
				t.Fatalf("scheduled expansion: inserted=%v err=%v", inserted, err)
			}
			id, _, _ := expansionJob(t, pool)
			_, err := pool.Exec(ctx, `UPDATE river_job SET state = $2, attempt = $3,
				attempted_at = CASE WHEN $4 THEN now() ELSE NULL END, metadata = $5::jsonb,
				errors = CASE WHEN $6 THEN ARRAY['{}'::jsonb] ELSE ARRAY[]::jsonb[] END,
				scheduled_at = CASE WHEN $7 THEN now() - interval '1 hour' ELSE scheduled_at END
				WHERE id = $1`, id, tc.state, tc.attempt, tc.attempted, tc.metadata, tc.errored, tc.due)
			if err != nil {
				t.Fatal(err)
			}
			before := expansionJobSnapshot(t, pool, id)
			if inserted, err := q.enqueueExpand(ctx, 77, tc.delay); err != nil || inserted {
				t.Fatalf("duplicate expansion: inserted=%v err=%v", inserted, err)
			}
			if after := expansionJobSnapshot(t, pool, id); after != before {
				t.Fatalf("outstanding job changed:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

func TestIntegrationImmediateExpansionConcurrentPromotion(t *testing.T) {
	q, pool := expansionQueue(t)
	ctx := context.Background()
	if inserted, err := q.enqueueExpand(ctx, 77, maxExpansionJitter); err != nil || !inserted {
		t.Fatalf("scheduled expansion: inserted=%v err=%v", inserted, err)
	}
	id, _, _ := expansionJob(t, pool)
	const callers = 12
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			inserted, err := q.enqueueExpand(ctx, 77, 0)
			if err != nil {
				errs <- fmt.Errorf("duplicate expansion: %w", err)
			} else if inserted {
				errs <- fmt.Errorf("duplicate expansion inserted=%v", inserted)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	var count int
	var due bool
	if err := pool.QueryRow(ctx, `SELECT count(*), bool_and(scheduled_at <= now())
		FROM river_job WHERE kind = $1`, KindExpandZone).Scan(&count, &due); err != nil {
		t.Fatal(err)
	}
	if count != 1 || !due {
		t.Fatalf("concurrent promotion: count=%d due=%v", count, due)
	}
	before := expansionJobSnapshot(t, pool, id)
	if inserted, err := q.enqueueExpand(ctx, 77, 0); err != nil || inserted {
		t.Fatalf("repeated expansion: inserted=%v err=%v", inserted, err)
	}
	if after := expansionJobSnapshot(t, pool, id); after != before {
		t.Fatalf("repeated promotion changed due job:\nbefore %s\nafter  %s", before, after)
	}
}

// Simulate the duplicate Insert returning a fresh job, then a worker finishing
// it before promotion acquires the row lock. The UPDATE must recheck state.
func TestIntegrationImmediateExpansionDoesNotReviveCompletedSnapshot(t *testing.T) {
	q, pool := expansionQueue(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if inserted, err := q.enqueueExpand(ctx, 77, maxExpansionJitter); err != nil || !inserted {
		t.Fatalf("scheduled expansion: inserted=%v err=%v", inserted, err)
	}
	id, _, scheduledBefore := expansionJob(t, pool)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT id FROM river_job WHERE id = $1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := q.pool.Exec(ctx, promoteFreshExpansionSQL, id, KindExpandZone)
		done <- err
	}()
	eventually(t, "promotion waiting for worker lock", func() bool {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity
			WHERE query = $1 AND wait_event_type = 'Lock')`, promoteFreshExpansionSQL).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		return blocked
	})
	if _, err := tx.Exec(ctx, `UPDATE river_job SET state = 'completed',
		attempt = 1, attempted_at = now(), finalized_at = now() WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	gotID, state, scheduledAt := expansionJob(t, pool)
	if gotID != id || state != "completed" || !scheduledAt.Equal(scheduledBefore) {
		t.Fatalf("stale snapshot promotion: id=%d state=%s scheduled_at=%s", gotID, state, scheduledAt)
	}
}

func expansionWorkerEngine(t *testing.T) (*Engine, int64) {
	t.Helper()
	st, pool := migratedDB(t)
	cfg := baseCfg()
	cfg.Sync.Interval = 0
	cfg.Expansion = config.ExpansionConfig{CTLogs: true, Interval: time.Hour}
	cfg.Scope = config.ScopeConfig{Include: []string{"example.com", "*.example.com"}}
	g, err := scope.NewGuard(cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	zone := store.AssetUpsert{AssetInput: model.AssetInput{
		Kind: model.KindZone, Key: "example.com", Source: "fake", Zone: "example.com",
	}, Scope: model.ScopeOwned}
	diff, err := st.ApplySnapshot(context.Background(), "fake", []store.AssetUpsert{zone}, nil, time.Now())
	if err != nil || len(diff.Added) != 1 {
		t.Fatalf("zone snapshot: diff=%+v err=%v", diff, err)
	}
	fx := &fakeExpander{res: ExpandResult{CT: cand("example.com", "ct", "new.example.com")}}
	e, err := New(Deps{
		Config: cfg, Store: st, Guard: g, Inventory: &ownedOnlyInventory{dbInventory{st, g}, g},
		Findings: &fakeProc{}, Recorder: newFakeRec(), Pool: pool, Expander: fx,
	}, WithRoles(RoleScheduler, RoleWorker), WithTickInterval(time.Hour), WithGaugeInterval(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return e, diff.Added[0].ID
}

// Queue jitter first, then its immediate duplicate, before any worker starts.
// A real River scheduler and worker must execute the promoted job, rather than
// merely leaving a due-now row that no producer can fetch.
func TestIntegrationImmediateExpansionRunsPromotedJob(t *testing.T) {
	e, zoneID := expansionWorkerEngine(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if inserted, err := e.r.q.enqueueExpand(ctx, zoneID, maxExpansionJitter); err != nil || !inserted {
		t.Fatalf("scheduled expansion: inserted=%v err=%v", inserted, err)
	}
	if inserted, err := e.r.q.enqueueExpand(ctx, zoneID, 0); err != nil || inserted {
		t.Fatalf("immediate expansion: inserted=%v err=%v", inserted, err)
	}
	started := time.Now()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer stopCancel()
		if err := e.Stop(stopCtx); err != nil {
			t.Errorf("stop: %v", err)
		}
	}()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		assets, _, err := e.d.Store.ListAssets(ctx, store.AssetFilter{Kind: model.KindHostname})
		if err != nil {
			t.Fatal(err)
		}
		for _, asset := range assets {
			if asset.Key == "new.example.com" {
				t.Logf("promoted expansion ran through River scheduler and worker in %s", time.Since(started))
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("promoted expansion did not run: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}
