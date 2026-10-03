package engine

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Instance liveness and reclaim of orphaned jobs.
//
// A job is 'running' in river_job from the moment a client fetches it until
// that client records the outcome. When the process dies hard (OOMKilled,
// SIGKILL at the end of a pod's grace period) the row stays running, and
// because jobs are unique per args a stuck periodic job (sync_source,
// update_templates) also blocks its next run. River only rescues such jobs
// after RescueStuckJobsAfter, and keeps no client heartbeat of its own, so
// every worker/scheduler instance registers its River client id in
// deckard_instances and refreshes seen_at; any live instance moves the
// running jobs of an instance that stopped heartbeating back to retryable.
const (
	heartbeatEvery = 10 * time.Second
	// staleAfter is how long an instance may miss heartbeats before its
	// running jobs are reclaimed: six missed beats, far above a GC pause or a
	// slow query, so a live instance is never mistaken for a dead one.
	staleAfter   = 60 * time.Second
	reclaimEvery = 30 * time.Second
	// instanceTTL prunes rows of instances gone for a day. Their jobs were
	// reclaimed long before (reclaim runs before prune at startup too).
	instanceTTL = 24 * time.Hour
	// deregisterTimeout bounds the row delete at the end of Stop.
	deregisterTimeout = 2 * time.Second
)

// newClientID mirrors River's default client id (<hostname>_<start time>), set
// explicitly so the engine knows the id River records in attempted_by.
func newClientID(startedAt time.Time) string {
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown_host"
	}
	host = strings.ReplaceAll(host, ".", "_")
	if len(host) > 60 {
		host = host[:60]
	}
	return host + "_" + strings.Replace(startedAt.UTC().Format("2006_01_02T15_04_05.000000"), ".", "_", 1)
}

// heartbeat registers this instance or refreshes its seen_at. It is an upsert
// so a row removed by a peer's prune (after a very long stall) comes back.
func (e *Engine) heartbeat(ctx context.Context) error {
	_, err := e.d.Pool.Exec(ctx, `
		INSERT INTO deckard_instances (client_id) VALUES ($1)
		ON CONFLICT (client_id) DO UPDATE SET seen_at = now()`, e.clientID)
	if err != nil {
		return fmt.Errorf("instance heartbeat: %w", err)
	}
	return nil
}

func (e *Engine) deregister(ctx context.Context) error {
	if _, err := e.d.Pool.Exec(ctx, `DELETE FROM deckard_instances WHERE client_id = $1`, e.clientID); err != nil {
		return fmt.Errorf("instance deregister: %w", err)
	}
	return nil
}

func (e *Engine) pruneInstances(ctx context.Context) error {
	if _, err := e.d.Pool.Exec(ctx, `DELETE FROM deckard_instances WHERE seen_at < now() - make_interval(secs => $1)`,
		instanceTTL.Seconds()); err != nil {
		return fmt.Errorf("prune instances: %w", err)
	}
	return nil
}

// reclaimSQL moves the running jobs of dead instances out of 'running'. It
// mirrors River's rescuer (JobRescueMany in riverpgxv5 and
// internal/maintenance/job_rescuer.go) column for column:
//
//   - a job whose cancellation was requested (metadata.cancel_attempted_at)
//     becomes cancelled, finalized now, scheduled_at kept;
//   - a job with no attempts left (attempt >= max_attempts) is discarded,
//     finalized now, scheduled_at kept;
//   - otherwise it becomes retryable with finalized_at NULL and is due now.
//
// In every case one AttemptError is appended to errors (attempt is the
// current attempt, not incremented: the next fetch counts the retry, exactly
// as after a River rescue) and metadata."river:rescue_count" is bumped.
//
// Safety: only jobs whose LAST attempted_by entry is a client registered in
// deckard_instances with a heartbeat older than $1 seconds are touched. A
// client that never registered (an older deckard during a rolling update) is
// left to River's rescuer, a live client is never touched, and all times come
// from the database clock so instance clock skew cannot matter. Rows locked by
// a concurrent reclaim are skipped, and the UPDATE re-checks state and owner,
// so concurrent or repeated runs are harmless.
const reclaimSQL = `
WITH dead AS (
	SELECT client_id FROM deckard_instances
	WHERE seen_at < now() - make_interval(secs => $1)
),
victim AS (
	SELECT j.id, d.client_id AS owner
	FROM river_job j
	JOIN dead d ON d.client_id = j.attempted_by[array_upper(j.attempted_by, 1)]
	WHERE j.state = 'running'
	FOR UPDATE OF j SKIP LOCKED
),
reclaimed AS (
	UPDATE river_job j SET
		state = (` + reclaimState + `)::river_job_state,
		finalized_at = CASE WHEN ` + reclaimState + ` = 'retryable' THEN NULL ELSE now() END,
		scheduled_at = CASE WHEN ` + reclaimState + ` = 'retryable' THEN now() ELSE j.scheduled_at END,
		errors = array_append(j.errors, jsonb_build_object(
			'at', now(),
			'attempt', greatest(j.attempt, 0),
			'error', 'Running job reclaimed from dead instance ' || v.owner || ' by deckard',
			'trace', '')),
		metadata = j.metadata || jsonb_build_object(
			'river:rescue_count',
			coalesce(
				CASE WHEN jsonb_typeof(j.metadata -> 'river:rescue_count') = 'number'
					THEN (j.metadata ->> 'river:rescue_count')::int END,
				0) + 1)
	FROM victim v
	WHERE j.id = v.id
		AND j.state = 'running'
		AND j.attempted_by[array_upper(j.attempted_by, 1)] = v.owner
	RETURNING j.kind, j.state
)
SELECT kind, state::text, count(*) FROM reclaimed GROUP BY kind, state`

// reclaimState is the state a reclaimed job moves to, evaluated in the UPDATE
// against the locked row (SET expressions all see its pre-update values).
const reclaimState = `CASE
			WHEN j.metadata ? 'cancel_attempted_at' THEN 'cancelled'
			WHEN j.attempt >= j.max_attempts THEN 'discarded'
			ELSE 'retryable'
		END`

// reclaimed is what one reclaim pass moved, per job kind and new state.
type reclaimed map[string]map[string]int

func (r reclaimed) total() int {
	n := 0
	for _, byState := range r {
		for _, c := range byState {
			n += c
		}
	}
	return n
}

// reclaimOrphans runs one reclaim pass, then counts and logs what it moved.
func (e *Engine) reclaimOrphans(ctx context.Context) (reclaimed, error) {
	rows, err := e.d.Pool.Query(ctx, reclaimSQL, staleAfter.Seconds())
	if err != nil {
		return nil, fmt.Errorf("reclaim orphaned jobs: %w", err)
	}
	defer rows.Close()
	out := reclaimed{}
	for rows.Next() {
		var kind, state string
		var n int
		if err := rows.Scan(&kind, &state, &n); err != nil {
			return nil, fmt.Errorf("reclaim orphaned jobs: %w", err)
		}
		if out[kind] == nil {
			out[kind] = map[string]int{}
		}
		out[kind][state] += n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reclaim orphaned jobs: %w", err)
	}
	if out.total() == 0 {
		return out, nil
	}
	kinds := make([]string, 0, len(out))
	for k := range out {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	attrs := []any{"total", out.total()}
	for _, k := range kinds {
		n := 0
		for _, c := range out[k] {
			n += c
		}
		e.r.rec.JobsReclaimed(k, n)
		attrs = append(attrs, k, out[k])
	}
	e.r.log.Warn("reclaimed running jobs from a dead instance (it stopped heartbeating without a graceful stop)", attrs...)
	return out, nil
}

// instanceLoop heartbeats, reclaims and prunes until ctx is cancelled. Start
// has already registered the instance; the first reclaim runs immediately.
func (e *Engine) instanceLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	hb := time.NewTicker(heartbeatEvery)
	defer hb.Stop()
	rc := time.NewTicker(reclaimEvery)
	defer rc.Stop()
	failing := false
	maintain := func() {
		if _, err := e.reclaimOrphans(ctx); err != nil && ctx.Err() == nil {
			e.r.log.Warn("reclaim orphaned jobs", "err", err)
		}
		if err := e.pruneInstances(ctx); err != nil && ctx.Err() == nil {
			e.r.log.Warn("prune instances", "err", err)
		}
	}
	maintain()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rc.C:
			maintain()
		case <-hb.C:
			// Log transitions only: a database outage would otherwise log
			// every 10s, and River reports the outage anyway.
			err := e.heartbeat(ctx)
			switch {
			case err != nil && ctx.Err() == nil && !failing:
				failing = true
				e.r.log.Warn("instance heartbeat failing; peers reclaim this instance's running jobs after "+staleAfter.String(), "err", err)
			case err == nil && failing:
				failing = false
				e.r.log.Info("instance heartbeat recovered")
			}
		}
	}
}
