package engine

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// seedScanJob inserts a scan job of check into queue and forces it into state,
// as a version without the intel queue (or a client that fetched it) would
// have left it. Each call uses a fresh asset id, so uniqueness never applies.
func seedScanJob(t *testing.T, e *Engine, id int64, tier model.Tier, chk, queue, state string) int64 {
	t.Helper()
	ctx := context.Background()
	res, err := e.client.Insert(ctx, ScanAssetArgs{AssetID: id, Tier: tier, Check: chk}, &river.InsertOpts{Queue: queue})
	if err != nil || res.UniqueSkippedAsDuplicate {
		t.Fatalf("seed %s/%s: %v %v", chk, state, res, err)
	}
	finalized := "NULL"
	switch state {
	case "completed", "cancelled", "discarded":
		finalized = "now()"
	}
	if _, err := e.d.Pool.Exec(ctx, `UPDATE river_job SET state = $2::river_job_state, finalized_at = `+finalized+`,
		scheduled_at = CASE WHEN $2 IN ('scheduled', 'retryable') THEN now() + interval '1 hour' ELSE scheduled_at END
		WHERE id = $1`, res.Job.ID, state); err != nil {
		t.Fatal(err)
	}
	return res.Job.ID
}

func jobQueueState(t *testing.T, pool *pgxpool.Pool, id int64) (queue, state string) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), `SELECT queue, state::text FROM river_job WHERE id = $1`, id).Scan(&queue, &state); err != nil {
		t.Fatal(err)
	}
	return queue, state
}

type seeded struct {
	id        int64
	what      string
	wantQueue string
	wantState string
}

func TestMoveSlowJobsMovesOnlyPendingJobsOfSlowChecks(t *testing.T) {
	e := routingEngine(t, routingChecks(), nil, nil, nil)
	pool, ctx := e.d.Pool, context.Background()

	var n int64
	next := func() int64 { n++; return n }
	var rows []seeded
	add := func(what string, tier model.Tier, chk, queue, state, wantQueue string) {
		rows = append(rows, seeded{seedScanJob(t, e, next(), tier, chk, queue, state), what, wantQueue, state})
	}
	// Moved: pending states of slow checks, from any tier queue.
	add("slow available", model.TierPassive, slowName, QueuePassive, "available", QueueIntel)
	add("slow scheduled", model.TierPassive, slowName, QueuePassive, "scheduled", QueueIntel)
	add("slow retryable", model.TierPassive, slowName, QueuePassive, "retryable", QueueIntel)
	add("slow active-tier available", model.TierActive, actSlow, QueueActive, "available", QueueIntel)
	// Left alone: a running job is held by a worker.
	add("slow running", model.TierPassive, slowName, QueuePassive, "running", QueuePassive)
	// Left alone: finished or not yet pending.
	add("slow completed", model.TierPassive, slowName, QueuePassive, "completed", QueuePassive)
	add("slow discarded", model.TierPassive, slowName, QueuePassive, "discarded", QueuePassive)
	add("slow cancelled", model.TierPassive, slowName, QueuePassive, "cancelled", QueuePassive)
	add("slow pending", model.TierPassive, slowName, QueuePassive, "pending", QueuePassive)
	// Left alone: other checks, unknown checks, jobs already in intel.
	add("fast available", model.TierPassive, fastName, QueuePassive, "available", QueuePassive)
	add("active-tier fast available", model.TierActive, actName, QueueActive, "available", QueueActive)
	add("removed check available", model.TierPassive, "t.gone", QueuePassive, "available", QueuePassive)
	add("whole-tier job available", model.TierPassive, "", QueuePassive, "available", QueuePassive)
	add("slow already in intel", model.TierPassive, slowName, QueueIntel, "available", QueueIntel)
	// Left alone: not a scan job, whatever its args.
	res, err := e.client.Insert(ctx, SyncSourceArgs{Source: slowName}, &river.InsertOpts{Queue: QueuePassive})
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, seeded{res.Job.ID, "sync job", QueuePassive, "available"})

	moved, err := e.moveSlowJobs(ctx)
	if err != nil || moved != 4 {
		t.Fatalf("moved %d, %v; want 4", moved, err)
	}
	check := func(pass string) {
		t.Helper()
		for _, r := range rows {
			if q, s := jobQueueState(t, pool, r.id); q != r.wantQueue || s != r.wantState {
				t.Errorf("%s: %s is in %s/%s, want %s/%s", pass, r.what, q, s, r.wantQueue, r.wantState)
			}
		}
	}
	check("first pass")

	// Idempotent: nothing left to move.
	if moved, err := e.moveSlowJobs(ctx); err != nil || moved != 0 {
		t.Fatalf("second pass moved %d, %v", moved, err)
	}
	check("second pass")
}

func TestMoveSlowJobsIsBounded(t *testing.T) {
	e := routingEngine(t, routingChecks(), nil, nil, nil)
	e.o.moveBatch = 3
	ctx := context.Background()
	var ids []int64
	for i := int64(1); i <= 7; i++ {
		ids = append(ids, seedScanJob(t, e, i, model.TierPassive, slowName, QueuePassive, "available"))
	}
	for i, want := range []int64{3, 3, 1, 0} {
		if got, err := e.moveSlowJobs(ctx); err != nil || got != want {
			t.Fatalf("pass %d moved %d, %v; want %d", i+1, got, err, want)
		}
	}
	for _, id := range ids {
		if q, _ := jobQueueState(t, e.d.Pool, id); q != QueueIntel {
			t.Errorf("job %d in %s", id, q)
		}
	}
}

// A checkless engine has nothing to move and must not touch the database.
func TestMoveSlowJobsWithoutSlowChecks(t *testing.T) {
	e := routingEngine(t, []check.Check{tierCheck{fastName, model.TierPassive}}, nil, nil, nil)
	id := seedScanJob(t, e, 1, model.TierPassive, fastName, QueuePassive, "available")
	if moved, err := e.moveSlowJobs(context.Background()); err != nil || moved != 0 {
		t.Fatalf("moved %d, %v", moved, err)
	}
	if q, _ := jobQueueState(t, e.d.Pool, id); q != QueuePassive {
		t.Errorf("fast job moved to %s", q)
	}
}

// TestMaintainMovesJobsQueuedByOlderInstances: an instance of the old version
// keeps inserting into the passive queue while a rolling update runs; the
// periodic upkeep of a new instance moves what it queued.
func TestMaintainMovesJobsQueuedByOlderInstances(t *testing.T) {
	e := routingEngine(t, routingChecks(), nil, nil, nil)
	id := seedScanJob(t, e, 1, model.TierPassive, slowName, QueuePassive, "available")
	e.maintainJobs(context.Background())
	if q, s := jobQueueState(t, e.d.Pool, id); q != QueueIntel || s != "available" {
		t.Errorf("job is in %s/%s", q, s)
	}
}

// TestStartMovesPendingJobsBeforeWorking: after an upgrade the database holds
// pending jobs in the passive queue. They must be worked by the intel workers,
// not by the passive ones, from the first fetch.
func TestStartMovesPendingJobsBeforeWorking(t *testing.T) {
	e := routingEngine(t, routingChecks(), nil, nil, nil)
	ctx := context.Background()
	var slowIDs []int64
	for i := int64(1); i <= 4; i++ {
		slowIDs = append(slowIDs, seedScanJob(t, e, i, model.TierPassive, slowName, QueuePassive, "available"))
	}
	// Assets 1..4 do not exist, so each scan returns at once; what is
	// observed is the queue the jobs are worked in.
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
	eventually(t, "the pending jobs to finish", func() bool {
		for _, id := range slowIDs {
			if _, s := jobQueueState(t, e.d.Pool, id); s != "completed" {
				return false
			}
		}
		return true
	})
	for _, id := range slowIDs {
		if q, _ := jobQueueState(t, e.d.Pool, id); q != QueueIntel {
			t.Errorf("job %d finished in queue %s", id, q)
		}
	}
}
