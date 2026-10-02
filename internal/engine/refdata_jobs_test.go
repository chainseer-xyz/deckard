package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/riverqueue/river"

	"github.com/chainseer-xyz/deckard/internal/refdata"
)

type fakeRefresher struct {
	calls atomic.Int32
	err   error
}

func (f *fakeRefresher) RefreshAll(context.Context) ([]refdata.Result, error) {
	f.calls.Add(1)
	return nil, f.err
}

func refdataEngine(t *testing.T, enabled bool, r Refresher) *Engine {
	t.Helper()
	h := newHarness(func(c *testCfg) {
		c.Refdata.Enabled = enabled
		c.Refdata.Interval = 24 * time.Hour
	}, nil)
	h.r.Deps.Refdata = r
	e, err := New(h.r.Deps, WithRoles(RoleAPI, RoleScheduler, RoleWorker))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRefreshRefdataArgs(t *testing.T) {
	a := RefreshRefdataArgs{}
	if a.Kind() != "refresh_refdata" {
		t.Fatal(a.Kind())
	}
	o := a.InsertOpts()
	if o.Queue != QueueDefault || !o.UniqueOpts.ByArgs || o.MaxAttempts < 2 {
		t.Errorf("opts: %+v", o)
	}
}

func TestRefdataPeriodicJobOnlyWhenConfigured(t *testing.T) {
	base := len(refdataEngine(t, false, nil).periodicJobs())
	if n := len(refdataEngine(t, true, nil).periodicJobs()); n != base {
		t.Errorf("no refresher: %d jobs, want %d", n, base)
	}
	if n := len(refdataEngine(t, false, &fakeRefresher{}).periodicJobs()); n != base {
		t.Errorf("disabled: %d jobs, want %d", n, base)
	}
	if n := len(refdataEngine(t, true, &fakeRefresher{}).periodicJobs()); n != base+1 {
		t.Errorf("enabled: %d jobs, want %d", n, base+1)
	}
}

func TestRefdataWorker(t *testing.T) {
	f := &fakeRefresher{}
	w := &refdataWorker{e: refdataEngine(t, true, f)}
	if err := w.Work(context.Background(), &river.Job[RefreshRefdataArgs]{}); err != nil || f.calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d", err, f.calls.Load())
	}
	f.err = errors.New("network down")
	if err := w.Work(context.Background(), &river.Job[RefreshRefdataArgs]{}); err == nil {
		t.Error("transient failure must fail the job so River retries it")
	}
	w = &refdataWorker{e: refdataEngine(t, true, nil)}
	if err := w.Work(context.Background(), &river.Job[RefreshRefdataArgs]{}); err != nil {
		t.Errorf("no refresher: %v", err)
	}
}

func TestRunOnceRefreshesRefdataAndToleratesFailure(t *testing.T) {
	f := &fakeRefresher{}
	e := refdataEngine(t, true, f)
	if err := e.RunOnce(context.Background()); err != nil || f.calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d", err, f.calls.Load())
	}
	f.err = errors.New("offline")
	if err := e.RunOnce(context.Background()); err != nil || f.calls.Load() != 2 {
		t.Fatalf("a failed refresh must not fail the scan: err=%v calls=%d", err, f.calls.Load())
	}
	off := &fakeRefresher{}
	if err := refdataEngine(t, false, off).RunOnce(context.Background()); err != nil || off.calls.Load() != 0 {
		t.Fatalf("disabled must not refresh: err=%v calls=%d", err, off.calls.Load())
	}
}
