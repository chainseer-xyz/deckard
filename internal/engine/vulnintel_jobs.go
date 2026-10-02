package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/riverqueue/river"

	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

// KindRefreshVulnintel is the job kind that refreshes exploit-intelligence
// feeds (CISA KEV, FIRST EPSS).
const KindRefreshVulnintel = "refresh_vulnintel"

// Feed names used for metrics labels.
const (
	FeedKEV  = "kev"
	FeedEPSS = "epss"
)

// VulnIntelFeed is the slice of *vulnintel.Service the refresh job drives.
type VulnIntelFeed interface {
	// Refresh updates the KEV catalog and reports CVEs newly added to KEV.
	Refresh(ctx context.Context) (vulnintel.Delta, error)
	// RefreshEPSS fetches missing/expired EPSS scores for cves (batched).
	RefreshEPSS(ctx context.Context, cves []string) (int, error)
}

var _ VulnIntelFeed = (*vulnintel.Service)(nil)

// CVEScanTrigger starts targeted scans for CVEs that were just added to KEV.
// It is the consumer-side seam for the CVE-scan workstream: the lead wires an
// implementation with WithCVEScanTrigger. EnqueueCVEScan returns how many
// scans were queued.
type CVEScanTrigger interface {
	EnqueueCVEScan(ctx context.Context, cves []string) (int, error)
}

// VulnIntelRecorder is the optional metrics side of the refresh job. The
// engine uses it when Deps.Recorder implements it (metrics.Metrics does), so
// existing Recorder fakes keep compiling.
type VulnIntelRecorder interface {
	// ObserveVulnintelRefresh counts one refresh attempt of a feed
	// ("kev"/"epss") with result "ok", "not_modified" or "error".
	ObserveVulnintelRefresh(feed, result string)
	// SetKEVOpen sets the number of open findings tagged kev.
	SetKEVOpen(n int)
}

// findingLister is the optional store capability the job uses to read open
// findings (store.Store has it; narrow engine fakes do not need it).
type findingLister interface {
	ListFindings(ctx context.Context, f store.FindingFilter) ([]model.Finding, int, error)
}

type vulnintelOpts struct {
	feed    VulnIntelFeed
	trigger CVEScanTrigger
}

// WithVulnIntel enables the refresh_vulnintel job over feed (nil disables).
// The job is scheduled on the scheduler role every vulnintel.interval with
// jitter, and once at startup.
func WithVulnIntel(feed VulnIntelFeed) Option { return func(o *options) { o.vi.feed = feed } }

// WithCVEScanTrigger sets the hook invoked with CVEs newly added to KEV. nil
// (the default) only logs.
func WithCVEScanTrigger(t CVEScanTrigger) Option { return func(o *options) { o.vi.trigger = t } }

// RefreshVulnintelArgs is the periodic exploit-intelligence refresh.
type RefreshVulnintelArgs struct{}

func (RefreshVulnintelArgs) Kind() string { return KindRefreshVulnintel }
func (RefreshVulnintelArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueDefault, MaxAttempts: 3, UniqueOpts: uniqueOpts()}
}

type vulnintelWorker struct {
	river.WorkerDefaults[RefreshVulnintelArgs]
	e *Engine
}

func (w *vulnintelWorker) Work(ctx context.Context, _ *river.Job[RefreshVulnintelArgs]) error {
	return w.e.refreshVulnintel(ctx)
}
func (w *vulnintelWorker) Timeout(*river.Job[RefreshVulnintelArgs]) time.Duration {
	return 10 * time.Minute
}

// vulnintelEnabled reports whether the job should be scheduled.
func (e *Engine) vulnintelEnabled() bool {
	return e.o.vi.feed != nil && e.d.Config.Vulnintel.Enabled && e.d.Config.Vulnintel.Interval > 0
}

// vulnintelPeriodic returns the periodic job (empty when disabled).
func (e *Engine) vulnintelPeriodic() []*river.PeriodicJob {
	if !e.vulnintelEnabled() {
		return nil
	}
	return []*river.PeriodicJob{river.NewPeriodicJob(
		jitterSchedule{interval: e.d.Config.Vulnintel.Interval, frac: e.o.syncJitter},
		func() (river.JobArgs, *river.InsertOpts) { return RefreshVulnintelArgs{}, nil },
		&river.PeriodicJobOpts{ID: "vulnintel", RunOnStart: true})}
}

func (e *Engine) vulnJob() *vulnintelJob {
	log := e.d.Logger
	if log == nil {
		log = slog.Default()
	}
	rec, _ := e.d.Recorder.(VulnIntelRecorder)
	fl, _ := e.d.Store.(findingLister)
	e.vulnOnce.Do(func() {
		e.vuln = &vulnintelJob{feed: e.o.vi.feed, trigger: e.o.vi.trigger, findings: fl, rec: rec, log: log}
	})
	return e.vuln
}

// refreshVulnintel runs one refresh (River job and RunOnce share it).
func (e *Engine) refreshVulnintel(ctx context.Context) error {
	if e.o.vi.feed == nil || !e.d.Config.Vulnintel.Enabled {
		return nil
	}
	return e.vulnJob().run(ctx)
}

// vulnintelJob is the testable core of refresh_vulnintel.
type vulnintelJob struct {
	feed     VulnIntelFeed
	trigger  CVEScanTrigger
	findings findingLister
	rec      VulnIntelRecorder
	log      *slog.Logger

	mu      sync.Mutex
	pending map[string]struct{} // new-KEV CVEs the trigger has not accepted yet
}

func (j *vulnintelJob) observe(feed, result string) {
	if j.rec != nil {
		j.rec.ObserveVulnintelRefresh(feed, result)
	}
}

// run refreshes KEV, batch-fetches EPSS for CVEs in open findings and hands
// newly KEV-listed CVEs to the scan trigger. Every step runs even if an
// earlier one failed; errors are joined so River retries.
func (j *vulnintelJob) run(ctx context.Context) error {
	var errs []error

	delta, err := j.feed.Refresh(ctx)
	switch {
	case err != nil:
		j.observe(FeedKEV, "error")
		j.log.Warn("vulnintel: KEV refresh failed; serving the last good copy", "err", err)
		errs = append(errs, fmt.Errorf("kev refresh: %w", err))
	case delta.NotModified:
		j.observe(FeedKEV, "not_modified")
	default:
		j.observe(FeedKEV, "ok")
		j.log.Info("vulnintel: KEV refreshed", "entries", delta.Entries, "new", len(delta.NewKEV), "first_load", delta.FirstLoad)
	}

	openCVEs, kevOpen, listed := j.openCVEs(ctx)
	if listed && j.rec != nil {
		j.rec.SetKEVOpen(kevOpen)
	}
	// Newly KEV-listed CVEs are scored too, before the targeted scan the
	// trigger starts, so the finding it opens carries EPSS from the start.
	if want := mergeCVEs(openCVEs, delta.NewKEV); len(want) > 0 {
		if _, err := j.feed.RefreshEPSS(ctx, want); err != nil {
			j.observe(FeedEPSS, "error")
			j.log.Warn("vulnintel: EPSS refresh incomplete", "err", err)
			errs = append(errs, fmt.Errorf("epss refresh: %w", err))
		} else {
			j.observe(FeedEPSS, "ok")
		}
	}

	if terr := j.dispatchNewKEV(ctx, delta.NewKEV, openCVEs); terr != nil {
		errs = append(errs, terr)
	}
	return errors.Join(errs...)
}

// openCVEs lists the distinct CVE ids referenced by open findings and how
// many open findings carry the kev tag. listed is false when findings could
// not be read.
func (j *vulnintelJob) openCVEs(ctx context.Context) (cves []string, kevOpen int, listed bool) {
	if j.findings == nil {
		return nil, 0, false
	}
	fs, _, err := j.findings.ListFindings(ctx, store.FindingFilter{Statuses: []model.FindingStatus{model.StatusOpen}})
	if err != nil {
		j.log.Warn("vulnintel: listing open findings failed", "err", err)
		return nil, 0, false
	}
	seen := map[string]bool{}
	for _, f := range fs {
		for _, t := range f.Tags {
			if t == finding.TagKEV {
				kevOpen++
				break
			}
		}
		for _, c := range finding.CVEsOf(model.FindingInput{Tags: f.Tags, Evidence: f.Evidence}) {
			if !seen[c] {
				seen[c] = true
				cves = append(cves, c)
			}
		}
	}
	sort.Strings(cves)
	return cves, kevOpen, true
}

// dispatchNewKEV passes newly KEV-listed CVEs (plus any the trigger rejected
// earlier) to the trigger. CVEs matching currently open findings need no scan:
// the next processor pass upgrades those findings, which this only logs.
func (j *vulnintelJob) dispatchNewKEV(ctx context.Context, newKEV, openCVEs []string) error {
	j.mu.Lock()
	if j.pending == nil {
		j.pending = map[string]struct{}{}
	}
	for _, c := range newKEV {
		j.pending[c] = struct{}{}
	}
	batch := make([]string, 0, len(j.pending))
	for c := range j.pending {
		batch = append(batch, c)
	}
	j.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	sort.Strings(batch)

	open := map[string]bool{}
	for _, c := range openCVEs {
		open[c] = true
	}
	var hits []string
	for _, c := range newKEV {
		if open[c] {
			hits = append(hits, c)
		}
	}
	if len(hits) > 0 {
		j.log.Warn("vulnintel: CVEs in open findings were just added to CISA KEV; severities upgrade on their next scan", "cves", hits)
	}

	if j.trigger == nil {
		j.log.Info("vulnintel: no CVE scan trigger configured", "new_kev", len(batch))
		j.mu.Lock()
		j.pending = nil // nothing will ever consume them; do not grow
		j.mu.Unlock()
		return nil
	}
	n, err := j.trigger.EnqueueCVEScan(ctx, batch)
	if err != nil {
		j.log.Warn("vulnintel: CVE scan trigger failed; will retry", "err", err, "cves", len(batch))
		return fmt.Errorf("enqueue cve scan: %w", err)
	}
	j.mu.Lock()
	for _, c := range batch {
		delete(j.pending, c)
	}
	j.mu.Unlock()
	j.log.Info("vulnintel: queued targeted scans for newly exploited CVEs", "cves", len(batch), "scans", n)
	return nil
}

// mergeCVEs returns the sorted union of two CVE id lists.
func mergeCVEs(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	var out []string
	for _, l := range [][]string{a, b} {
		for _, c := range l {
			if _, ok := seen[c]; !ok {
				seen[c] = struct{}{}
				out = append(out, c)
			}
		}
	}
	sort.Strings(out)
	return out
}
