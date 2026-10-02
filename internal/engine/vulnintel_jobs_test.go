package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

type fakeFeed struct {
	mu        sync.Mutex
	delta     vulnintel.Delta
	err       error
	epssErr   error
	refreshes int
	epssCalls [][]string
}

func (f *fakeFeed) Refresh(context.Context) (vulnintel.Delta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes++
	d := f.delta
	f.delta = vulnintel.Delta{} // like the real service: a delta is reported once
	return d, f.err
}

func (f *fakeFeed) RefreshEPSS(_ context.Context, cves []string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.epssCalls = append(f.epssCalls, append([]string(nil), cves...))
	return len(cves), f.epssErr
}

type fakeTrigger struct {
	calls [][]string
	err   error
}

func (t *fakeTrigger) EnqueueCVEScan(_ context.Context, cves []string) (int, error) {
	t.calls = append(t.calls, append([]string(nil), cves...))
	return len(cves), t.err
}

type fakeLister struct {
	fs  []model.Finding
	err error
}

func (l *fakeLister) ListFindings(_ context.Context, f store.FindingFilter) ([]model.Finding, int, error) {
	if len(f.Statuses) != 1 || f.Statuses[0] != model.StatusOpen {
		panic("job must list open findings only")
	}
	return l.fs, len(l.fs), l.err
}

type fakeVIRec struct {
	refresh map[string]int
	kevOpen int
	set     bool
}

func (r *fakeVIRec) ObserveVulnintelRefresh(feed, result string) {
	if r.refresh == nil {
		r.refresh = map[string]int{}
	}
	r.refresh[feed+"/"+result]++
}
func (r *fakeVIRec) SetKEVOpen(n int) { r.kevOpen, r.set = n, true }

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func openFinding(tags []string, ev map[string]any) model.Finding {
	return model.Finding{Status: model.StatusOpen, Tags: tags, Evidence: ev}
}

func newJob(feed *fakeFeed, trig CVEScanTrigger, l findingLister, rec VulnIntelRecorder) *vulnintelJob {
	return &vulnintelJob{feed: feed, trigger: trig, findings: l, rec: rec, log: quietLog}
}

func TestVulnintelJobRefreshesEPSSForOpenFindingsAndTriggersNewKEV(t *testing.T) {
	feed := &fakeFeed{delta: vulnintel.Delta{NewKEV: []string{"CVE-2025-00002", "CVE-2025-00009"}, Entries: 10}}
	trig := &fakeTrigger{}
	lister := &fakeLister{fs: []model.Finding{
		openFinding([]string{"cve", "cve-2021-44228"}, nil),
		openFinding([]string{"cve-2021-44228", "kev"}, nil),
		openFinding(nil, map[string]any{"cves": []any{"CVE-2025-00002"}}),
		openFinding([]string{"ssh"}, nil),
	}}
	rec := &fakeVIRec{}
	if err := newJob(feed, trig, lister, rec).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"CVE-2021-44228", "CVE-2025-00002", "CVE-2025-00009"}}; !reflect.DeepEqual(feed.epssCalls, want) { // open findings plus the newly KEV-listed
		t.Errorf("EPSS batch = %v, want %v", feed.epssCalls, want)
	}
	if want := [][]string{{"CVE-2025-00002", "CVE-2025-00009"}}; !reflect.DeepEqual(trig.calls, want) {
		t.Errorf("trigger calls = %v, want %v", trig.calls, want)
	}
	if rec.refresh["kev/ok"] != 1 || rec.refresh["epss/ok"] != 1 || !rec.set || rec.kevOpen != 1 {
		t.Errorf("metrics = %+v", rec)
	}
}

func TestVulnintelJobNoNewKEVNoTrigger(t *testing.T) {
	feed := &fakeFeed{delta: vulnintel.Delta{NotModified: true, Entries: 10}}
	trig := &fakeTrigger{}
	rec := &fakeVIRec{}
	if err := newJob(feed, trig, &fakeLister{}, rec).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(trig.calls) != 0 || len(feed.epssCalls) != 0 {
		t.Errorf("trigger=%v epss=%v", trig.calls, feed.epssCalls)
	}
	if rec.refresh["kev/not_modified"] != 1 {
		t.Errorf("metrics = %+v", rec.refresh)
	}
}

func TestVulnintelJobNilTriggerIsSafe(t *testing.T) {
	feed := &fakeFeed{delta: vulnintel.Delta{NewKEV: []string{"CVE-2025-00002"}}}
	j := newJob(feed, nil, nil, nil)
	if err := j.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(j.pending) != 0 {
		t.Errorf("pending grows with no trigger: %v", j.pending)
	}
}

func TestVulnintelJobOfflineKEVFailureStillRunsEPSSAndReportsError(t *testing.T) {
	feed := &fakeFeed{err: errors.New("offline")}
	rec := &fakeVIRec{}
	lister := &fakeLister{fs: []model.Finding{openFinding([]string{"cve-2021-44228"}, nil)}}
	err := newJob(feed, &fakeTrigger{}, lister, rec).run(context.Background())
	if err == nil {
		t.Fatal("expected the failure to surface so the job retries")
	}
	if len(feed.epssCalls) != 1 || rec.refresh["kev/error"] != 1 {
		t.Errorf("epss=%v metrics=%v", feed.epssCalls, rec.refresh)
	}
}

func TestVulnintelJobEPSSFailureRecorded(t *testing.T) {
	feed := &fakeFeed{epssErr: errors.New("429")}
	rec := &fakeVIRec{}
	lister := &fakeLister{fs: []model.Finding{openFinding([]string{"cve-2021-44228"}, nil)}}
	if err := newJob(feed, nil, lister, rec).run(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if rec.refresh["epss/error"] != 1 {
		t.Errorf("metrics = %v", rec.refresh)
	}
}

func TestVulnintelJobListFailureDoesNotBreakKEV(t *testing.T) {
	feed := &fakeFeed{delta: vulnintel.Delta{Entries: 3}}
	rec := &fakeVIRec{}
	if err := newJob(feed, nil, &fakeLister{err: errors.New("db")}, rec).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec.set {
		t.Error("kev_open set despite list failure")
	}
}

func TestVulnintelJobRetriesRejectedTriggerBatch(t *testing.T) {
	feed := &fakeFeed{delta: vulnintel.Delta{NewKEV: []string{"CVE-2025-00002"}}}
	trig := &fakeTrigger{err: errors.New("queue down")}
	j := newJob(feed, trig, nil, nil)
	if err := j.run(context.Background()); err == nil {
		t.Fatal("trigger failure must surface")
	}
	// The next run sees an empty delta (already reported once) but must still
	// deliver the undelivered CVE.
	trig.err = nil
	if err := j.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(trig.calls) != 2 || !reflect.DeepEqual(trig.calls[1], []string{"CVE-2025-00002"}) {
		t.Fatalf("calls = %v", trig.calls)
	}
	// Delivered once: a third run sends nothing.
	if err := j.run(context.Background()); err != nil || len(trig.calls) != 2 {
		t.Fatalf("redelivered: %v %v", err, trig.calls)
	}
}

func TestVulnintelPeriodicRegistration(t *testing.T) {
	mk := func(enabled bool, interval time.Duration, feed VulnIntelFeed) *Engine {
		h := newHarness(func(c *testCfg) {
			c.Vulnintel.Enabled, c.Vulnintel.Interval = enabled, interval
		}, nil)
		var opts []Option
		if feed != nil {
			opts = append(opts, WithVulnIntel(feed))
		}
		e, err := New(h.r.Deps, opts...)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	if n := len(mk(true, time.Hour, &fakeFeed{}).vulnintelPeriodic()); n != 1 {
		t.Errorf("enabled: %d periodic jobs", n)
	}
	for name, e := range map[string]*Engine{
		"no feed":  mk(true, time.Hour, nil),
		"disabled": mk(false, time.Hour, &fakeFeed{}),
		"no ivl":   mk(true, 0, &fakeFeed{}),
	} {
		if n := len(e.vulnintelPeriodic()); n != 0 {
			t.Errorf("%s: %d periodic jobs", name, n)
		}
	}
}

func TestVulnintelArgsAndWorkerDeclareUniqueQueueAndTimeout(t *testing.T) {
	o := (RefreshVulnintelArgs{}).InsertOpts()
	if o.Queue != QueueDefault || !o.UniqueOpts.ByArgs || o.MaxAttempts < 2 {
		t.Errorf("insert opts = %+v", o)
	}
	if (RefreshVulnintelArgs{}).Kind() != "refresh_vulnintel" {
		t.Error("kind")
	}
	if d := (&vulnintelWorker{}).Timeout(&river.Job[RefreshVulnintelArgs]{}); d < 5*time.Minute {
		t.Errorf("timeout %v", d)
	}
}

func TestRunOnceRefreshesVulnintelAndNeverFailsOnIt(t *testing.T) {
	feed := &fakeFeed{err: errors.New("offline")}
	h := newHarness(func(c *testCfg) { c.Vulnintel.Enabled, c.Vulnintel.Interval = true, time.Hour }, nil)
	e, err := New(h.r.Deps, WithVulnIntel(feed))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce failed because of an offline feed: %v", err)
	}
	if feed.refreshes != 1 {
		t.Fatalf("refreshes = %d", feed.refreshes)
	}
}

func TestEngineWithoutVulnintelIsUntouched(t *testing.T) {
	e, _ := newTestEngine(t, nil, nil)
	if err := e.refreshVulnintel(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.vulnintelPeriodic()) != 0 {
		t.Fatal("periodic job without feed")
	}
}
