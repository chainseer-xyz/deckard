package engine

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/riverqueue/river"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei"
	"github.com/chainseer-xyz/deckard/internal/nuclei/updater"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// QueueMaintenance carries the nuclei template update (one worker).
const QueueMaintenance = "maintenance"

// Job kinds added by the template workstream.
const (
	KindUpdateTemplates  = "update_templates"
	KindScanNewTemplates = "scan_new_templates"
	KindScanCVEs         = "scan_cves"
)

// DeltaCheck is the check name template-limited scans use in scan history. It
// is deliberately not "cve.nuclei": recording a delta run under the regular
// check's name would make the scheduler believe the full scan just succeeded
// and postpone it. Findings themselves are still reconciled under cve.nuclei.
const DeltaCheck = "cve.nuclei.delta"

const (
	deltaTemplateChunk = 500              // templates per job (keeps job args small)
	deltaAssetBatch    = 50               // assets per job (bounds nuclei process count)
	deltaWorkerMargin  = 10 * time.Minute // storage/reconciliation time after the nuclei process
	deltaNotReadyMax   = 12 * time.Hour
	deltaNotReadySnooz = 5 * time.Minute
)

// errTemplatesNotReady means the active template set on this node does not
// have the templates yet (a sibling node updated first). The job is snoozed
// instead of failed.
var errTemplatesNotReady = errors.New("engine: nuclei templates not yet available on this node")

// ErrNoTemplateScanning is returned by EnqueueCVEScan when the engine was not
// given a nuclei scanner (nuclei disabled or not installed).
var ErrNoTemplateScanning = errors.New("nuclei template scanning is not configured")

// TemplateManager is the engine's view of the nuclei template updater;
// *updater.Updater satisfies it.
type TemplateManager interface {
	Update(ctx context.Context) (updater.Update, error)
	// UpdateIfOlderThan updates only when the active release was not confirmed
	// current within maxAge; ran reports whether an update was attempted.
	UpdateIfOlderThan(ctx context.Context, maxAge time.Duration) (updater.Update, bool, error)
	Status() (updater.Status, error)
}

// DeltaScanner is the engine's view of template-limited nuclei runs;
// *nuclei.Scanner satisfies it. Scan must refuse (never run) any target that
// fails scope verification.
type DeltaScanner interface {
	Scan(ctx context.Context, req nuclei.ScanRequest) (nuclei.ScanResult, error)
	// Resolve maps relative template paths to absolute paths in the active
	// set, dropping missing ones; it fails with nuclei.ErrNoTemplates before
	// the first update.
	Resolve(rel []string) ([]string, error)
	LookupCVEs(cves []string) ([]string, error)
}

var (
	_ TemplateManager = (*updater.Updater)(nil)
	_ DeltaScanner    = (*nuclei.Scanner)(nil)
)

// TemplateRecorder is an optional extension of Recorder (the engine asserts for
// it, so existing Recorder fakes keep compiling).
type TemplateRecorder interface {
	// ObserveTemplateUpdate counts one update attempt: "ok" (new release
	// installed), "unchanged" or "error".
	ObserveTemplateUpdate(result string)
	// AddNewTemplates counts templates an update added.
	AddNewTemplates(n int)
	// SetTemplateStatus reports the active release size and when it was last
	// confirmed current.
	SetTemplateStatus(count int, checkedAt time.Time)
}

type noopTemplateRecorder struct{}

func (noopTemplateRecorder) ObserveTemplateUpdate(string)     {}
func (noopTemplateRecorder) AddNewTemplates(int)              {}
func (noopTemplateRecorder) SetTemplateStatus(int, time.Time) {}

func (r *runner) templateRec() TemplateRecorder {
	if t, ok := r.rec.(TemplateRecorder); ok {
		return t
	}
	return noopTemplateRecorder{}
}

// ---- job args -----------------------------------------------------------------

// UpdateTemplatesArgs updates the nuclei templates. Unique, so a slow or
// retrying update is never stacked.
type UpdateTemplatesArgs struct{}

func (UpdateTemplatesArgs) Kind() string { return KindUpdateTemplates }
func (UpdateTemplatesArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMaintenance, MaxAttempts: 3, UniqueOpts: uniqueOpts()}
}

// ScanNewTemplatesArgs runs the given (relative) templates against a batch of
// assets as a partial run. A crashed run is simply redone by River.
type ScanNewTemplatesArgs struct {
	Templates []string `json:"templates"`
	AssetIDs  []int64  `json:"asset_ids"`
	Release   string   `json:"release,omitempty"`
}

func (ScanNewTemplatesArgs) Kind() string { return KindScanNewTemplates }
func (ScanNewTemplatesArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueActive, MaxAttempts: 3, UniqueOpts: uniqueOpts()}
}

// ScanCVEsArgs runs the templates of the current set that match the CVE ids
// against a batch of assets as a partial run. The template lookup happens in
// the job, against the node's current set.
type ScanCVEsArgs struct {
	CVEs     []string `json:"cves"`
	AssetIDs []int64  `json:"asset_ids"`
}

func (ScanCVEsArgs) Kind() string { return KindScanCVEs }
func (ScanCVEsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueActive, MaxAttempts: 3, UniqueOpts: uniqueOpts()}
}

type updateTemplatesWorker struct {
	river.WorkerDefaults[UpdateTemplatesArgs]
	r *runner
}

func (w *updateTemplatesWorker) Work(ctx context.Context, _ *river.Job[UpdateTemplatesArgs]) error {
	return w.r.updateAndScan(ctx, 0)
}
func (w *updateTemplatesWorker) Timeout(*river.Job[UpdateTemplatesArgs]) time.Duration {
	return 15 * time.Minute
}

type scanNewTemplatesWorker struct {
	river.WorkerDefaults[ScanNewTemplatesArgs]
	r *runner
}

func (w *scanNewTemplatesWorker) Work(ctx context.Context, j *river.Job[ScanNewTemplatesArgs]) error {
	err := w.r.runDelta(ctx, deltaJob{Kind: KindScanNewTemplates, Templates: j.Args.Templates, AssetIDs: j.Args.AssetIDs, Release: j.Args.Release})
	return notReadyResult(err, j.CreatedAt, w.r.now())
}
func (w *scanNewTemplatesWorker) Timeout(*river.Job[ScanNewTemplatesArgs]) time.Duration {
	return w.deltaTimeout()
}

type scanCVEsWorker struct {
	river.WorkerDefaults[ScanCVEsArgs]
	r *runner
}

func (w *scanCVEsWorker) Work(ctx context.Context, j *river.Job[ScanCVEsArgs]) error {
	err := w.r.runDelta(ctx, deltaJob{Kind: KindScanCVEs, CVEs: j.Args.CVEs, AssetIDs: j.Args.AssetIDs})
	return notReadyResult(err, j.CreatedAt, w.r.now())
}
func (w *scanCVEsWorker) Timeout(*river.Job[ScanCVEsArgs]) time.Duration {
	return w.deltaTimeout()
}

func (w *scanNewTemplatesWorker) deltaTimeout() time.Duration {
	return deltaTimeout(w.r)
}

func (w *scanCVEsWorker) deltaTimeout() time.Duration {
	return deltaTimeout(w.r)
}

func deltaTimeout(r *runner) time.Duration {
	var cfg map[string]any
	if r != nil {
		cfg = r.Config.Checks[nuclei.NameActive]
	}
	return nuclei.ProcessTimeout(cfg, deltaAssetBatch) + deltaWorkerMargin
}

// notReadyResult turns "this node lacks the templates" into a snooze (the node's
// own updater or catch-up loop will install them), cancelling a job that has
// waited too long for templates that never arrived.
func notReadyResult(err error, created, now time.Time) error {
	if !errors.Is(err, errTemplatesNotReady) {
		return err
	}
	if now.Sub(created) > deltaNotReadyMax {
		return river.JobCancel(fmt.Errorf("templates still unavailable after %s: %w", deltaNotReadyMax, err))
	}
	return river.JobSnooze(deltaNotReadySnooz)
}

// ---- queue plumbing ---------------------------------------------------------------

// deltaJob is one template-limited scan batch.
type deltaJob struct {
	Kind      string
	Templates []string // relative to the active set
	CVEs      []string
	AssetIDs  []int64
	Release   string
}

func (j deltaJob) key() string {
	return fmt.Sprintf("%s|%s|%s|%s|%v", j.Kind, j.Release, strings.Join(j.Templates, ","), strings.Join(j.CVEs, ","), j.AssetIDs)
}

// templateQueue is implemented by every queue (River, in-memory, none); the
// runner reaches it by assertion so the base queue interface stays untouched.
type templateQueue interface {
	enqueueDelta(ctx context.Context, j deltaJob) (bool, error)
}

func (q riverQueue) enqueueDelta(ctx context.Context, j deltaJob) (bool, error) {
	var args river.JobArgs
	switch j.Kind {
	case KindScanCVEs:
		args = ScanCVEsArgs{CVEs: j.CVEs, AssetIDs: j.AssetIDs}
	default:
		args = ScanNewTemplatesArgs{Templates: j.Templates, AssetIDs: j.AssetIDs, Release: j.Release}
	}
	res, err := q.c.Insert(ctx, args, nil)
	if err != nil {
		return false, err
	}
	return !res.UniqueSkippedAsDuplicate, nil
}

func (noQueue) enqueueDelta(context.Context, deltaJob) (bool, error) { return false, ErrNoQueue }

func (m *memQueue) enqueueDelta(_ context.Context, j deltaJob) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[j.key()] {
		return false, nil
	}
	m.seen[j.key()] = true
	m.deltas = append(m.deltas, j)
	return true, nil
}

func (m *memQueue) takeDeltas() []deltaJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.deltas
	m.deltas = nil
	return out
}

func (r *runner) deltaQueue() (templateQueue, bool) {
	tq, ok := r.q.(templateQueue)
	return tq, ok
}

// ---- update ---------------------------------------------------------------------------

// updateTemplates performs one template update and reports metrics. minAge > 0
// makes it conditional on staleness (see TemplateManager.UpdateIfOlderThan).
func (r *runner) updateTemplates(ctx context.Context, minAge time.Duration) (up updater.Update, ran bool, err error) {
	if r.Templates == nil {
		return up, false, nil
	}
	tr := r.templateRec()
	if minAge > 0 {
		up, ran, err = r.Templates.UpdateIfOlderThan(ctx, minAge)
	} else {
		up, err = r.Templates.Update(ctx)
		ran = true
	}
	if !ran && err == nil {
		r.reportTemplateStatus()
		return up, false, nil
	}
	switch {
	case err != nil:
		tr.ObserveTemplateUpdate("error")
	case up.Changed:
		tr.ObserveTemplateUpdate("ok")
		tr.AddNewTemplates(len(up.NewTemplates))
	default:
		tr.ObserveTemplateUpdate("unchanged")
	}
	r.reportTemplateStatus()
	if err != nil {
		return up, true, fmt.Errorf("update nuclei templates: %w", err)
	}
	r.log.Info("nuclei templates checked", "version", up.Version, "templates", up.TemplateCount,
		"changed", up.Changed, "new_templates", len(up.NewTemplates))
	return up, true, nil
}

// reportTemplateStatus pushes the active release's size and last-confirmed time.
func (r *runner) reportTemplateStatus() {
	if r.Templates == nil {
		return
	}
	st, err := r.Templates.Status()
	if err != nil || st.CheckedAt.IsZero() {
		return
	}
	r.templateRec().SetTemplateStatus(st.TemplateCount, st.CheckedAt)
	if warn := r.Config.Nuclei.Update.MaxAgeWarn; warn > 0 && r.now().Sub(st.CheckedAt) > warn {
		r.log.Warn("nuclei templates are older than nuclei.update.max_age_warn: new CVE templates are not being picked up",
			"age", r.now().Sub(st.CheckedAt).Round(time.Minute), "max_age_warn", warn, "version", st.Version, "last_error", st.LastError)
	}
}

// updateAndScan is the update_templates job body: update, then scan every
// eligible asset with the templates the update added.
func (r *runner) updateAndScan(ctx context.Context, minAge time.Duration) error {
	up, ran, err := r.updateTemplates(ctx, minAge)
	if err != nil {
		return err
	}
	if ran && up.Changed {
		if _, err := r.enqueueNewTemplateScans(ctx, up); err != nil {
			return fmt.Errorf("enqueue new-template scans: %w", err)
		}
	}
	return nil
}

// enqueueNewTemplateScans queues scan_new_templates jobs for the templates an
// update added (when nuclei.update.run_new_templates is on). It returns the
// number of jobs newly queued.
func (r *runner) enqueueNewTemplateScans(ctx context.Context, up updater.Update) (int, error) {
	if !r.Config.Nuclei.Update.RunNewTemplates || len(up.NewTemplates) == 0 || r.Delta == nil {
		return 0, nil
	}
	ids, err := r.deltaAssetIDs(ctx)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		r.log.Info("new nuclei templates: no eligible web assets to scan", "templates", len(up.NewTemplates))
		return 0, nil
	}
	queued := 0
	for _, chunk := range slices.Collect(slices.Chunk(up.NewTemplates, deltaTemplateChunk)) {
		n, err := r.enqueueDeltaBatches(ctx, deltaJob{Kind: KindScanNewTemplates, Templates: chunk, Release: up.Version}, ids)
		queued += n
		if err != nil {
			return queued, err
		}
	}
	r.log.Info("new nuclei templates queued for scanning", "templates", len(up.NewTemplates), "assets", len(ids), "jobs", queued)
	return queued, nil
}

// enqueueDeltaBatches splits ids into batches of deltaAssetBatch and enqueues
// one job per batch. It returns the number of jobs newly queued.
func (r *runner) enqueueDeltaBatches(ctx context.Context, base deltaJob, ids []int64) (int, error) {
	tq, ok := r.deltaQueue()
	if !ok {
		return 0, ErrNoQueue
	}
	queued := 0
	for _, batch := range slices.Collect(slices.Chunk(ids, deltaAssetBatch)) {
		j := base
		j.AssetIDs = slices.Clone(batch)
		ok, err := tq.enqueueDelta(ctx, j)
		if err != nil {
			return queued, err
		}
		if ok {
			queued++
		}
	}
	return queued, nil
}

// ---- targets ----------------------------------------------------------------------------

// webTarget is an asset eligible for a template-limited scan and the URL that
// scan hits.
type webTarget struct {
	Asset model.Asset
	URL   string
}

type observationReader interface {
	LatestObservations(ctx context.Context, assetID int64) ([]model.Observation, error)
}

// webTarget decides whether a is scanned by template-limited runs and with
// which URL. URL and web-service assets use the regular nuclei derivation;
// hostname assets are scanned at the URL their latest live http.probe saw.
// The asset must be non-removed, owned, allowed by the scope guard for the
// active tier (freshly classified) and enabled by its profile.
func (r *runner) webTarget(ctx context.Context, a model.Asset) (webTarget, bool) {
	if a.Scope != model.ScopeOwned {
		return webTarget{}, false
	}
	if _, _, why := r.scannable(a, model.TierActive); why != "" {
		return webTarget{}, false
	}
	switch a.Kind {
	case model.KindURL, model.KindService:
		u, err := nuclei.TargetURL(a)
		if err != nil {
			return webTarget{}, false
		}
		return webTarget{Asset: a, URL: u}, true
	case model.KindHostname:
		or, ok := r.Store.(observationReader)
		if !ok {
			return webTarget{}, false
		}
		obs, err := or.LatestObservations(ctx, a.ID)
		if err != nil {
			return webTarget{}, false
		}
		for _, o := range obs {
			if o.Check != "http.probe" {
				continue
			}
			if _, live := o.Data["status"]; !live {
				continue
			}
			if u, _ := o.Data["url"].(string); u != "" {
				return webTarget{Asset: a, URL: u}, true
			}
		}
	}
	return webTarget{}, false
}

// deltaAssetIDs lists the ids of every eligible web asset: owned URL and
// web-service assets, then hostnames with a live http.probe observation whose
// URL no other eligible asset already covers. Sorted, so job args are
// deterministic and River's uniqueness dedupes repeats.
func (r *runner) deltaAssetIDs(ctx context.Context) ([]int64, error) {
	seen := map[string]bool{}
	var ids []int64
	for _, kind := range []model.AssetKind{model.KindURL, model.KindService, model.KindHostname} {
		assets, _, err := r.Store.ListAssets(ctx, store.AssetFilter{Kind: kind, Scope: model.ScopeOwned})
		if err != nil {
			return nil, fmt.Errorf("list %s assets: %w", kind, err)
		}
		for _, a := range assets {
			if a.Kind != kind {
				continue // a store that ignores the filter
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			t, ok := r.webTarget(ctx, a)
			if !ok || seen[t.URL] {
				continue
			}
			seen[t.URL] = true
			ids = append(ids, a.ID)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// ---- run --------------------------------------------------------------------------------

// runDelta executes one template-limited scan batch. Findings are reconciled as
// a PARTIAL run of cve.nuclei: they open and refresh findings but never count
// misses or resolve anything, because only some templates ran.
//
// SAFETY: every asset is re-loaded, re-classified by the scope guard and
// profile-checked here (webTarget), the template list is confined to the active
// set, and Scan re-verifies every target's host as owned before nuclei sees it.
func (r *runner) runDelta(ctx context.Context, j deltaJob) error {
	if r.Delta == nil {
		r.log.Debug("template scan skipped: no scanner configured", "kind", j.Kind)
		return nil
	}
	rel := j.Templates
	if j.Kind == KindScanCVEs {
		found, err := r.Delta.LookupCVEs(j.CVEs)
		if err != nil {
			if errors.Is(err, nuclei.ErrNoTemplates) {
				return fmt.Errorf("%w: %w", errTemplatesNotReady, err)
			}
			return fmt.Errorf("look up templates for %v: %w", j.CVEs, err)
		}
		rel = found
		if len(rel) == 0 {
			r.log.Info("cve scan: no template for the requested CVEs in the current set", "cves", j.CVEs)
			return nil
		}
	}
	if len(rel) == 0 {
		return nil
	}
	abs, err := r.Delta.Resolve(rel)
	if err != nil {
		if errors.Is(err, nuclei.ErrNoTemplates) {
			return fmt.Errorf("%w: %w", errTemplatesNotReady, err)
		}
		return fmt.Errorf("resolve templates: %w", err)
	}
	if len(abs) == 0 {
		// The templates are gone from the active set (a newer release removed
		// them): nothing to run, and nothing to wait for.
		r.log.Info("template scan: none of the templates exist in the active set", "requested", len(rel))
		return nil
	}

	var targets []webTarget
	for _, id := range j.AssetIDs {
		a, err := r.Store.GetAsset(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return fmt.Errorf("load asset %d: %w", id, err)
		}
		if t, ok := r.webTarget(ctx, *a); ok {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return nil
	}

	// One scan slot per host, shared with regular active scans, acquired in a
	// fixed order so two batches can never deadlock each other.
	type slot struct {
		key string
		n   int
	}
	var slots []slot
	seenSlot := map[string]bool{}
	rate := 0.0
	for _, t := range targets {
		prof := ResolveProfile(r.Config, t.Asset, model.TierActive)
		k := string(model.TierActive) + "|" + hostOf(t.Asset)
		if !seenSlot[k] {
			seenSlot[k] = true
			slots = append(slots, slot{k, prof.PerHostConcurrency})
		}
		if prof.RatePerSec > 0 && (rate == 0 || prof.RatePerSec < rate) {
			rate = prof.RatePerSec
		}
	}
	sort.Slice(slots, func(a, b int) bool { return slots[a].key < slots[b].key })
	for _, s := range slots {
		release, err := r.sems.acquire(ctx, s.key, s.n)
		if err != nil {
			return err // shutting down; River retries the job
		}
		defer release()
	}

	req := nuclei.ScanRequest{Templates: abs, RatePerSec: rate}
	byID := map[int64]model.Asset{}
	for _, t := range targets {
		req.Targets = append(req.Targets, nuclei.ScanTarget{ID: t.Asset.ID, URL: t.URL})
		byID[t.Asset.ID] = t.Asset
	}
	start := r.now()
	res, scanErr := r.Delta.Scan(ctx, req)
	d := r.now().Sub(start)
	if errors.Is(scanErr, nuclei.ErrNoTemplates) {
		return fmt.Errorf("%w: %w", errTemplatesNotReady, scanErr)
	}

	var errs []error
	if scanErr != nil {
		errs = append(errs, scanErr)
	}
	refused := map[int64]bool{}
	for _, t := range res.Refused {
		refused[t.ID] = true
		r.recordScan(ctx, store.ScanRun{
			AssetID: t.ID, Check: DeltaCheck, Tier: string(model.TierActive), StartedAt: start,
			Error: SkippedPrefix + "scope: target not verified as owned",
		})
	}
	ids := make([]int64, 0, len(res.Findings))
	for id := range res.Findings {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	processErr := map[int64]error{}
	for _, id := range ids {
		fs := res.Findings[id]
		if len(fs) == 0 {
			continue
		}
		a, ok := byID[id]
		if !ok {
			continue
		}
		if _, err := r.Findings.Process(ctx, a, nuclei.NameActive, &check.Result{Findings: fs, Partial: true}); err != nil {
			processErr[id] = err
			errs = append(errs, fmt.Errorf("process findings for %s: %w", a.Key, err))
		}
	}
	for _, t := range targets {
		if refused[t.Asset.ID] {
			continue
		}
		run := store.ScanRun{
			AssetID: t.Asset.ID, Check: DeltaCheck, Tier: string(model.TierActive), StartedAt: start,
			DurationMS: d.Milliseconds(), Findings: len(res.Findings[t.Asset.ID]),
		}
		switch {
		case processErr[t.Asset.ID] != nil:
			run.Error = processErr[t.Asset.ID].Error()
		case scanErr != nil:
			run.Error = scanErr.Error()
		}
		r.recordScan(ctx, run)
	}
	r.rec.ObserveScan(DeltaCheck, string(model.TierActive), d, errors.Join(errs...))
	r.log.Info("template scan finished", "kind", j.Kind, "templates", len(abs), "targets", res.Scanned,
		"refused", len(res.Refused), "assets_with_findings", len(ids), "err", errors.Join(errs...))
	return errors.Join(errs...)
}

// ---- operator API --------------------------------------------------------------------

// EnqueueCVEScan queues partial scans, over every eligible owned web asset, with
// whichever templates of the node's current set match the CVE ids (by template
// id or classification.cve-id), for example CVE-2025-55182. The template
// lookup happens in the job, on the worker, so a node without templates (an
// api-only replica) can still enqueue. It returns the number of jobs newly
// queued; repeating the call while the same jobs are pending queues nothing.
// Findings follow partial-run semantics: opened and refreshed, never resolved.
func (e *Engine) EnqueueCVEScan(ctx context.Context, cves []string) (queued int, err error) {
	if e.r.Delta == nil {
		return 0, ErrNoTemplateScanning
	}
	norm, err := nuclei.NormalizeCVEs(cves)
	if err != nil {
		return 0, err
	}
	ids, err := e.r.deltaAssetIDs(ctx)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	return e.r.enqueueDeltaBatches(ctx, deltaJob{Kind: KindScanCVEs, CVEs: norm}, ids)
}

// ---- catch-up loop --------------------------------------------------------------------

// guardTiming returns the start delay and cadence of the catch-up loop.
func (e *Engine) guardTiming() (initial, every time.Duration, enabled bool) {
	interval := e.r.Config.Nuclei.Update.Interval
	every = e.o.guardEvery
	if every <= 0 {
		every = min(10*time.Minute, max(interval/2, time.Second))
	}
	initial = e.o.guardInitial
	if initial < 0 {
		return 0, 0, false
	}
	if initial == 0 {
		initial = 30*time.Second + time.Duration(rand.Int64N(int64(30*time.Second))) // #nosec G404 -- start-up jitter, not security sensitive
	}
	return initial, every, true
}

// templateGuard keeps THIS node's templates fresh. The update_templates job
// runs on exactly one worker, so a worker that did not get it (separate
// replicas, separate volumes) would otherwise go stale; it also retries a
// failed update every few minutes instead of waiting a whole interval. The
// check is conditional on staleness, so on a single node where the job keeps
// the templates fresh it never downloads.
func (e *Engine) templateGuard(ctx context.Context, done chan struct{}) {
	defer close(done)
	initial, every, ok := e.guardTiming()
	if !ok {
		return
	}
	interval := e.r.Config.Nuclei.Update.Interval
	maxAge := interval + interval/4 // beyond the job's own jitter
	t := time.NewTimer(initial)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := e.r.updateAndScan(ctx, maxAge); err != nil && ctx.Err() == nil {
			e.r.log.Warn("nuclei template catch-up failed; will retry", "err", err, "retry_in", every)
		}
		t.Reset(every)
	}
}
