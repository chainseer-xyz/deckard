package engine

import (
	"context"
	"fmt"
	"slices"
)

// Moving pending scan jobs of slow-lookup checks to the intel queue.
//
// A job's queue is fixed when it is inserted (runner.scanQueue). Jobs queued
// by a version that had no intel queue, or by an instance of an older version
// that is still running during a rolling update, sit in the tier's queue; the
// instance that starts moves them, so they are not worked next to the fast
// local checks they were meant to be isolated from.

// moveSlowBatch bounds the rows one pass moves; the instance loop repeats it,
// so a very large backlog drains over a few passes instead of one long lock.
const moveSlowBatch = 10000

// moveSlowSQL moves pending scan jobs of the checks in $3 from the tier queues
// in $2 to the queue in $1, at most $4 of them. 'running' jobs are never in
// the state list: a job a worker holds stays where it is. Rows locked by a
// worker fetching them or by a concurrent pass are skipped, and the UPDATE
// re-checks state and queue, so concurrent or repeated runs are harmless: a
// second pass finds nothing left to move. Uniqueness is by args, not queue, so
// the move cannot collide with a job that is already in the target queue.
const moveSlowSQL = `
WITH picked AS (
	SELECT id FROM river_job
	WHERE kind = 'scan_asset'
		AND queue = ANY($2::text[])
		AND state IN ('available', 'scheduled', 'retryable')
		AND args ->> 'check' = ANY($3::text[])
	ORDER BY id
	LIMIT $4
	FOR UPDATE SKIP LOCKED
)
UPDATE river_job j SET queue = $1
FROM picked p
WHERE j.id = p.id
	AND j.queue = ANY($2::text[])
	AND j.state IN ('available', 'scheduled', 'retryable')`

// moveSlowJobs moves up to one batch (moveSlowBatch) of pending scan jobs of the checks that
// declare check.SlowLookups to the intel queue and returns how many it moved.
func (e *Engine) moveSlowJobs(ctx context.Context) (int64, error) {
	if len(e.r.slow) == 0 {
		return 0, nil
	}
	checks := make([]string, 0, len(e.r.slow))
	for name := range e.r.slow {
		checks = append(checks, name)
	}
	slices.Sort(checks)
	from := []string{QueuePassive, QueueActive, QueueIntrusive}
	tag, err := e.d.Pool.Exec(ctx, moveSlowSQL, QueueIntel, from, checks, e.o.moveBatch)
	if err != nil {
		return 0, fmt.Errorf("move slow-lookup scan jobs to %s: %w", QueueIntel, err)
	}
	n := tag.RowsAffected()
	if n > 0 {
		e.r.log.Info("moved pending scan jobs of slow-lookup checks to the intel queue (queued by an older version or instance)",
			"jobs", n, "from", from, "to", QueueIntel, "checks", checks)
	}
	return n, nil
}
