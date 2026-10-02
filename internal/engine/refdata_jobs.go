package engine

import (
	"context"
	"time"

	"github.com/riverqueue/river"

	"github.com/chainseer-xyz/deckard/internal/refdata"
)

// KindRefreshRefdata refreshes the embedded reference datasets (takeover
// fingerprints, shared-infrastructure ranges) from their published sources.
const KindRefreshRefdata = "refresh_refdata"

// Refresher is the slice of *refdata.Manager the engine uses.
type Refresher interface {
	RefreshAll(ctx context.Context) ([]refdata.Result, error)
}

// RefreshRefdataArgs is the (argument-less) refresh job. It is unique, so a
// slow or retrying refresh is never stacked. It runs on the default queue:
// there is no dedicated maintenance queue.
type RefreshRefdataArgs struct{}

func (RefreshRefdataArgs) Kind() string { return KindRefreshRefdata }
func (RefreshRefdataArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueDefault, MaxAttempts: 3, UniqueOpts: uniqueOpts()}
}

type refdataWorker struct {
	river.WorkerDefaults[RefreshRefdataArgs]
	e *Engine
}

// Work refreshes every dataset. Only transient failures (download or apply
// errors) fail the job so River retries it; a rejected download is a verdict
// on the data and is left for the next interval. The embedded and last good
// copies stay live either way.
func (w *refdataWorker) Work(ctx context.Context, _ *river.Job[RefreshRefdataArgs]) error {
	if w.e.d.Refdata == nil {
		return nil
	}
	_, err := w.e.d.Refdata.RefreshAll(ctx)
	return err
}

func (w *refdataWorker) Timeout(*river.Job[RefreshRefdataArgs]) time.Duration {
	return 5 * time.Minute
}

// refdataEnabled reports whether periodic refresh is configured.
func (e *Engine) refdataEnabled() bool {
	c := e.d.Config.Refdata
	return e.d.Refdata != nil && c.Enabled && c.Interval > 0
}

// refdataPeriodicJobs schedules the refresh with jitter, once at startup and
// then every refdata.interval.
func (e *Engine) refdataPeriodicJobs() []*river.PeriodicJob {
	if !e.refdataEnabled() {
		return nil
	}
	return []*river.PeriodicJob{river.NewPeriodicJob(
		jitterSchedule{interval: e.d.Config.Refdata.Interval, frac: e.o.syncJitter},
		func() (river.JobArgs, *river.InsertOpts) { return RefreshRefdataArgs{}, nil },
		&river.PeriodicJobOpts{ID: "refdata", RunOnStart: true})}
}

// refreshRefdata is the RunOnce step. A failed refresh never fails the scan:
// the embedded or last good data is already live.
func (e *Engine) refreshRefdata(ctx context.Context) {
	if !e.refdataEnabled() {
		return
	}
	if _, err := e.d.Refdata.RefreshAll(ctx); err != nil {
		e.r.log.Warn("refdata refresh failed; continuing with embedded or last good data", "err", err)
	}
}

// SetRefresher replaces (or, with nil, removes) the refresher before the
// engine starts, e.g. for a one-shot scan with --no-update.
func (e *Engine) SetRefresher(r Refresher) { e.d.Refdata = r }

// RunRefdataLoop refreshes the datasets now and then every refdata.interval
// (with jitter) until ctx ends. The River job already covers the cluster, but
// it executes on one node only; this keeps every scanning node's in-memory
// copy current. Conditional requests make the extra fetches nearly free.
func (e *Engine) RunRefdataLoop(ctx context.Context) {
	if !e.refdataEnabled() {
		return
	}
	sched := jitterSchedule{interval: e.d.Config.Refdata.Interval, frac: e.o.syncJitter}
	for {
		e.refreshRefdata(ctx)
		t := time.NewTimer(time.Until(sched.Next(time.Now())))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
