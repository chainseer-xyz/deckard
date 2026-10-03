package engine

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// registerInstance records a peer instance last seen age ago.
func registerInstance(t *testing.T, pool *pgxpool.Pool, id string, age time.Duration) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO deckard_instances (client_id, seen_at) VALUES ($1, now() - make_interval(secs => $2))`,
		id, age.Seconds()); err != nil {
		t.Fatal(err)
	}
}

// insertJob inserts args through River, then forces the row into state with
// the given attempted_by history, as a client that fetched it would leave it.
func insertJob(t *testing.T, e *Engine, args river.JobArgs, state string, attempt int, by []string, extraSQL string) int64 {
	t.Helper()
	ctx := context.Background()
	res, err := e.client.Insert(ctx, args, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.UniqueSkippedAsDuplicate {
		t.Fatalf("test setup: %v deduplicated", args)
	}
	finalized := "NULL"
	if state == "completed" || state == "cancelled" || state == "discarded" {
		finalized = "now()"
	}
	if _, err := e.d.Pool.Exec(ctx, `UPDATE river_job SET state = $2::river_job_state, attempt = $3,
		attempted_at = now() - interval '5 minutes', attempted_by = $4, finalized_at = `+finalized+extraSQL+` WHERE id = $1`,
		res.Job.ID, state, attempt, by); err != nil {
		t.Fatal(err)
	}
	return res.Job.ID
}

type jobRow struct {
	state       string
	attempt     int
	finalized   bool
	scheduled   time.Time
	dueIn       time.Duration // scheduled_at - now(); not compared
	errors      int
	rescueCount int
	lastBy      string
}

func getJob(t *testing.T, pool *pgxpool.Pool, id int64) jobRow {
	t.Helper()
	var r jobRow
	var due float64
	if err := pool.QueryRow(context.Background(), `
		SELECT state::text, attempt, finalized_at IS NOT NULL, scheduled_at,
			extract(epoch FROM scheduled_at - now())::float8,
			coalesce(array_length(errors, 1), 0),
			coalesce((metadata ->> 'river:rescue_count')::int, 0),
			coalesce(attempted_by[array_upper(attempted_by, 1)], '')
		FROM river_job WHERE id = $1`, id).Scan(&r.state, &r.attempt, &r.finalized, &r.scheduled, &due, &r.errors, &r.rescueCount, &r.lastBy); err != nil {
		t.Fatal(err)
	}
	r.dueIn = time.Duration(due * float64(time.Second))
	return r
}

func reclaimEngine(t *testing.T) (*Engine, *fakeRec) {
	t.Helper()
	e, _, rec, _, _ := integrationSetup(t, []string{RoleScheduler, RoleWorker}, &recordingCheck{name: "p.rec", tier: model.TierPassive}, nil)
	e.o.reclaimSpread = 0 // due at once unless a test spreads them
	return e, rec
}

func scanArgs(id int64) ScanAssetArgs { return ScanAssetArgs{AssetID: id, Tier: model.TierPassive} }

// TestReclaimOrphans pins who is reclaimed and how: only running jobs whose
// latest attempt belongs to a registered instance with a stale heartbeat, with
// the columns River's own rescuer would write.
func TestReclaimOrphans(t *testing.T) {
	e, rec := reclaimEngine(t)
	pool := e.d.Pool
	registerInstance(t, pool, "dead_host", 5*time.Minute)
	registerInstance(t, pool, "live_host", 0)
	ctx := context.Background()

	type tc struct {
		name      string
		state     string
		attempt   int
		by        []string
		extra     string
		wantState string
		wantFinal bool
	}
	cases := []tc{
		{name: "stale registered owner", state: "running", attempt: 1, by: []string{"dead_host"}, wantState: "retryable"},
		{name: "latest attempt by a dead owner", state: "running", attempt: 2, by: []string{"live_host", "dead_host"}, wantState: "retryable"},
		{name: "fresh owner", state: "running", attempt: 1, by: []string{"live_host"}, wantState: "running"},
		{name: "latest attempt by a live owner", state: "running", attempt: 2, by: []string{"dead_host", "live_host"}, wantState: "running"},
		{name: "never registered owner", state: "running", attempt: 1, by: []string{"old_version_host"}, wantState: "running"},
		{name: "available", state: "available", attempt: 1, by: []string{"dead_host"}, wantState: "available"},
		{name: "retryable", state: "retryable", attempt: 1, by: []string{"dead_host"}, wantState: "retryable"},
		{name: "completed", state: "completed", attempt: 1, by: []string{"dead_host"}, wantState: "completed", wantFinal: true},
		{name: "no attempts left", state: "running", attempt: 3, by: []string{"dead_host"}, wantState: "discarded", wantFinal: true},
		{name: "cancel requested", state: "running", attempt: 1, by: []string{"dead_host"},
			extra: `, metadata = jsonb_build_object('cancel_attempted_at', now())`, wantState: "cancelled", wantFinal: true},
	}
	ids := make([]int64, len(cases))
	for i, c := range cases {
		ids[i] = insertJob(t, e, scanArgs(int64(i+1)), c.state, c.attempt, c.by, c.extra)
	}
	before := make([]jobRow, len(cases))
	for i := range cases {
		before[i] = getJob(t, pool, ids[i])
	}

	got, err := e.reclaimOrphans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.total() != 4 || got[KindScanAsset]["retryable"] != 2 || got[KindScanAsset]["discarded"] != 1 || got[KindScanAsset]["cancelled"] != 1 {
		t.Errorf("reclaimed = %v, want 2 retryable, 1 discarded, 1 cancelled", got)
	}
	if rec.reclaim[KindScanAsset] != 4 {
		t.Errorf("metric = %v, want scan_asset 4", rec.reclaim)
	}

	for i, c := range cases {
		j := getJob(t, pool, ids[i])
		if j.state != c.wantState || j.finalized != c.wantFinal {
			t.Errorf("%s: state %s finalized %v, want %s %v", c.name, j.state, j.finalized, c.wantState, c.wantFinal)
		}
		if j.attempt != before[i].attempt {
			t.Errorf("%s: attempt %d -> %d; a reclaim must not use an attempt", c.name, before[i].attempt, j.attempt)
		}
		touched := c.state == "running" && c.wantState != "running"
		if !touched {
			if j.dueIn = before[i].dueIn; j != before[i] {
				t.Errorf("%s: row changed: %+v -> %+v", c.name, before[i], j)
			}
			continue
		}
		if j.errors != 1 || j.rescueCount != 1 {
			t.Errorf("%s: errors %d rescue_count %d, want 1 and 1", c.name, j.errors, j.rescueCount)
		}
		switch c.wantState {
		case "retryable":
			if j.dueIn > time.Second || j.dueIn < -time.Minute {
				t.Errorf("%s: scheduled %v from now, want now", c.name, j.dueIn)
			}
		default: // finalized states keep their schedule, as River's rescuer does
			if !j.scheduled.Equal(before[i].scheduled) {
				t.Errorf("%s: scheduled_at moved: %v -> %v", c.name, before[i].scheduled, j.scheduled)
			}
		}
	}

	// River itself reads the reclaimed row back: the appended error decodes.
	jr, err := e.client.JobGet(ctx, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(jr.Errors) != 1 || jr.Errors[0].Attempt != 1 || !strings.Contains(jr.Errors[0].Error, "dead instance dead_host") || jr.Errors[0].At.IsZero() {
		t.Errorf("River sees errors %+v", jr.Errors)
	}

	// Idempotent: a second pass (or a peer's concurrent one) finds nothing.
	again, err := e.reclaimOrphans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.total() != 0 {
		t.Errorf("second pass reclaimed %v", again)
	}
	if j := getJob(t, pool, ids[0]); j.errors != 1 || j.rescueCount != 1 {
		t.Errorf("second pass touched a reclaimed row: %+v", j)
	}
}

// TestReclaimUnblocksUniqueSync is the live incident: a sync_source job left
// running by a pod that was OOMKilled blocked every periodic sync of that
// source (the job is unique per source) until River's one-hour rescue. A
// starting instance reclaims it at once, the sync runs here, and the source
// can be enqueued again.
func TestReclaimUnblocksUniqueSync(t *testing.T) {
	e, rec := reclaimEngine(t)
	pool := e.d.Pool
	ctx := context.Background()
	registerInstance(t, pool, "oomkilled_host", 5*time.Minute)
	orphan := insertJob(t, e, SyncSourceArgs{Source: "fake"}, "running", 1, []string{"oomkilled_host"}, "")

	if dup, err := e.client.Insert(ctx, SyncSourceArgs{Source: "fake"}, nil); err != nil || !dup.UniqueSkippedAsDuplicate {
		t.Fatalf("precondition: the orphan should block a new sync: %+v %v", dup, err)
	}

	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop(context.Background()) })

	eventually(t, "orphaned sync reclaimed and run here", func() bool {
		j := getJob(t, pool, orphan)
		return j.state == "completed" && j.lastBy == e.clientID
	})
	rec.mu.Lock()
	synced, reclaimedN := len(rec.syncs["fake"]), rec.reclaim[KindSyncSource]
	rec.mu.Unlock()
	if synced == 0 || reclaimedN != 1 {
		t.Errorf("syncs %d, reclaimed %d", synced, reclaimedN)
	}

	// The periodic sync may have queued behind the orphan; once nothing live
	// is left for the source, a new sync is accepted, not deduplicated.
	eventually(t, "no live sync job", func() bool {
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = $1 AND state NOT IN ('completed','cancelled','discarded')`, KindSyncSource).Scan(&n)
		return n == 0
	})
	res, err := e.client.Insert(ctx, SyncSourceArgs{Source: "fake"}, nil)
	if err != nil || res.UniqueSkippedAsDuplicate {
		t.Fatalf("sync not enqueueable after reclaim: %+v %v", res, err)
	}
}

// TestInstanceLifecycle: Start registers the River client id River records in
// attempted_by, and a graceful Stop removes it.
func TestInstanceLifecycle(t *testing.T) {
	e, _ := reclaimEngine(t)
	ctx := context.Background()
	if e.client.ID() != e.clientID {
		t.Fatalf("River client id %q, engine %q", e.client.ID(), e.clientID)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+_\d{4}_\d{2}_\d{2}T\d{2}_\d{2}_\d{2}_\d{6}$`).MatchString(e.clientID) {
		t.Errorf("client id %q is not River's <host>_<time> shape", e.clientID)
	}
	registered := func() bool {
		var n int
		if err := e.d.Pool.QueryRow(ctx, `SELECT count(*) FROM deckard_instances WHERE client_id = $1`, e.clientID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !registered() {
		t.Fatal("not registered after Start")
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if registered() {
		t.Error("graceful Stop left the instance registered")
	}
}

// TestPruneInstances drops rows of instances gone for a day, and only those.
func TestPruneInstances(t *testing.T) {
	e, _ := reclaimEngine(t)
	pool := e.d.Pool
	registerInstance(t, pool, "gone_long_ago", instanceTTL+time.Hour)
	registerInstance(t, pool, "gone_recently", time.Hour)
	if err := e.pruneInstances(context.Background()); err != nil {
		t.Fatal(err)
	}
	var left []string
	rows, err := pool.Query(context.Background(), `SELECT client_id FROM deckard_instances ORDER BY client_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		left = append(left, s)
	}
	if strings.Join(left, ",") != "gone_recently" {
		t.Errorf("left %v", left)
	}
}

// ctxCheck blocks until its context is cancelled, like a scan cut off by
// shutdown.
type ctxCheck struct{ started chan struct{} }

func (c *ctxCheck) Name() string             { return "p.block" }
func (c *ctxCheck) Tier() model.Tier         { return model.TierPassive }
func (c *ctxCheck) Applies(model.Asset) bool { return true }
func (c *ctxCheck) Run(ctx context.Context, _ check.Target) (*check.Result, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestStopPastDeadlineLeavesNothingRunning: when the drain deadline passes,
// Stop cancels in-flight jobs and River records them before Stop returns, so
// a shutdown that completes inside the pod's grace period orphans nothing, and
// the instance deregisters.
func TestStopPastDeadlineLeavesNothingRunning(t *testing.T) {
	chk := &ctxCheck{started: make(chan struct{}, 1)}
	e, _, _, _, _ := integrationSetup(t, []string{RoleScheduler, RoleWorker}, chk, []model.AssetInput{
		{Kind: model.KindHostname, Key: "app.example.com", Source: "fake", Zone: "example.com"},
	})
	ctx := context.Background()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-chk.started:
	case <-time.After(45 * time.Second):
		_ = e.Stop(ctx)
		t.Fatal("scan never started")
	}

	sctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	began := time.Now()
	if err := e.Stop(sctx); err == nil {
		t.Error("Stop past its deadline should report the cancelled jobs")
	}
	if took := time.Since(began); took > 200*time.Millisecond+StopOverrun {
		t.Errorf("Stop took %v, budget is the deadline + %v", took, StopOverrun)
	}
	var running, registered int
	if err := e.d.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM river_job WHERE state = 'running'),
		(SELECT count(*) FROM deckard_instances WHERE client_id = $1)`, e.clientID).Scan(&running, &registered); err != nil {
		t.Fatal(err)
	}
	if running != 0 || registered != 0 {
		t.Errorf("after Stop: %d jobs running, instance registered=%d; want 0 and 0", running, registered)
	}
}

// TestReclaimSpreadsRetries: the jobs of a dead instance come back spread over
// the window instead of all due in the same second.
func TestReclaimSpreadsRetries(t *testing.T) {
	e, _ := reclaimEngine(t)
	e.o.reclaimSpread = time.Minute
	registerInstance(t, e.d.Pool, "dead_host", 5*time.Minute)
	const n = 20
	ids := make([]int64, n)
	for i := range ids {
		ids[i] = insertJob(t, e, scanArgs(int64(i+1)), "running", 1, []string{"dead_host"}, "")
	}
	if got, err := e.reclaimOrphans(context.Background()); err != nil || got.total() != n {
		t.Fatalf("reclaimed %v, %v", got, err)
	}
	distinct := map[time.Time]bool{}
	for _, id := range ids {
		j := getJob(t, e.d.Pool, id)
		if j.state != "retryable" || j.dueIn < -5*time.Second || j.dueIn > time.Minute {
			t.Errorf("job %d: %s due in %v, want retryable within the minute", id, j.state, j.dueIn)
		}
		distinct[j.scheduled] = true
	}
	if len(distinct) < n/2 {
		t.Errorf("%d jobs share %d due times; not spread", n, len(distinct))
	}
}
