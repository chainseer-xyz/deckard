package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/nuclei/updater"
)

var allTiers = []model.Tier{model.TierPassive, model.TierActive, model.TierIntrusive}

type options struct {
	roles          []string
	queueWorkers   map[string]int
	tick           time.Duration
	gaugeEvery     time.Duration
	syncJitter     float64
	runOnceWorkers int
	// guardInitial/guardEvery time the template catch-up loop (0 = defaults,
	// guardInitial < 0 disables it).
	guardInitial time.Duration
	guardEvery   time.Duration
	vi           vulnintelOpts
	// reclaimSpread staggers reclaimed jobs (see WithReclaimSpread).
	reclaimSpread time.Duration
}

// Option customises an Engine.
type Option func(*options)

// WithRoles overrides the roles (default: config server.roles, else all).
func WithRoles(roles ...string) Option { return func(o *options) { o.roles = roles } }

// DefaultQueueWorkers is the max concurrent jobs per queue when none is
// configured. Every queue the engine runs has an entry: it is the engine's
// list of queues. A fresh map each call.
func DefaultQueueWorkers() map[string]int {
	return map[string]int{
		QueueSync: 2, QueuePassive: 10, QueueActive: 4, QueueIntrusive: 1,
		QueueIntel: 8, QueueExpand: 1, QueueMaintenance: 1, QueueDefault: 2,
	}
}

// WithQueueWorkers sets max concurrent jobs per queue (see DefaultQueueWorkers);
// unspecified queues keep their defaults.
func WithQueueWorkers(m map[string]int) Option {
	return func(o *options) {
		for k, v := range m {
			o.queueWorkers[k] = v
		}
	}
}

// WithTickInterval sets how often each tier's due-scan enumeration runs.
func WithTickInterval(d time.Duration) Option { return func(o *options) { o.tick = d } }

// WithGaugeInterval sets the queue-depth reporting period (default 15s).
func WithGaugeInterval(d time.Duration) Option { return func(o *options) { o.gaugeEvery = d } }

// WithSyncJitter sets the +/- fraction of sync.interval randomised per run.
func WithSyncJitter(f float64) Option { return func(o *options) { o.syncJitter = f } }

// WithRunOnceConcurrency bounds parallel scans in RunOnce.
func WithRunOnceConcurrency(n int) Option { return func(o *options) { o.runOnceWorkers = n } }

// WithTemplateGuard times the per-node template catch-up loop: first check
// after initial (negative disables the loop), then every `every`. Defaults:
// 30-60s after start, then min(10m, update.interval/2).
func WithTemplateGuard(initial, every time.Duration) Option {
	return func(o *options) { o.guardInitial, o.guardEvery = initial, every }
}

// WithReclaimSpread sets the window over which jobs reclaimed from a dead
// instance are spread (each is due at a random point in it; default 60s, 0
// makes them all due at once).
func WithReclaimSpread(d time.Duration) Option { return func(o *options) { o.reclaimSpread = d } }

// Engine owns the job system.
type Engine struct {
	d      Deps
	o      options
	r      *runner
	client *river.Client[pgx.Tx] // nil without a pool
	roles  map[string]bool
	// clientID is the River client id, recorded by River in
	// river_job.attempted_by and registered in deckard_instances.
	clientID string
	// timeouts maps each job kind this engine's client works to its
	// worker's timeout.
	timeouts map[string]time.Duration
	// rescueAfter is River's RescueStuckJobsAfter, derived from the workers'
	// timeouts (see rescueMargin).
	rescueAfter time.Duration

	vulnOnce sync.Once
	vuln     *vulnintelJob

	mu      sync.Mutex
	started bool
	stopGau context.CancelFunc
	gauDone chan struct{}

	stopGuard context.CancelFunc
	guardDone chan struct{}

	stopInst context.CancelFunc
	instDone chan struct{}
}

// New validates deps and builds the engine (and, with a Pool, the River
// client). Nothing runs until Start.
func New(d Deps, opts ...Option) (*Engine, error) {
	switch {
	case d.Store == nil:
		return nil, errors.New("engine: Store is required")
	case d.Guard == nil:
		return nil, errors.New("engine: Guard is required")
	case d.Inventory == nil:
		return nil, errors.New("engine: Inventory is required")
	case d.Findings == nil:
		return nil, errors.New("engine: Findings is required")
	}
	o := options{
		queueWorkers: DefaultQueueWorkers(),
		tick:         30 * time.Second,
		gaugeEvery:   15 * time.Second,
		syncJitter:   0.1,
		// A crashed instance's jobs come back together; retrying all of
		// them in the same second is what OOMKilled the replacement pod.
		reclaimSpread: 60 * time.Second,
	}
	for _, f := range opts {
		f(&o)
	}
	if o.reclaimSpread < 0 {
		return nil, errors.New("engine: negative reclaim spread")
	}
	if o.runOnceWorkers < 1 {
		o.runOnceWorkers = 8
	}
	if len(o.roles) == 0 {
		o.roles = d.Config.Server.Roles
	}
	if len(o.roles) == 0 {
		o.roles = []string{RoleAPI, RoleScheduler, RoleWorker}
	}
	roles := map[string]bool{}
	for _, r := range o.roles {
		switch r {
		case RoleAPI, RoleScheduler, RoleWorker:
			roles[r] = true
		default:
			return nil, fmt.Errorf("engine: unknown role %q", r)
		}
	}
	for q, n := range o.queueWorkers {
		if n < 1 {
			return nil, fmt.Errorf("engine: queue %q needs at least 1 worker", q)
		}
	}
	seen := map[string]bool{}
	for _, c := range d.Checks {
		if seen[c.Name()] {
			return nil, fmt.Errorf("engine: duplicate check %q", c.Name())
		}
		seen[c.Name()] = true
	}
	e := &Engine{d: d, o: o, r: newRunner(d), roles: roles}
	if d.Pool != nil {
		c, err := e.newClient()
		if err != nil {
			return nil, err
		}
		e.client = c
		e.r.q = riverQueue{c: c, route: e.r.scanQueue}
	}
	return e, nil
}

// stopCancelWindow is how long Stop waits for cancelled jobs to return once
// the graceful drain deadline has passed.
const stopCancelWindow = 10 * time.Second

// StopOverrun is the most Stop can run past its context's deadline: the cancel
// window plus deregistering the instance. Whoever owns the process lifetime
// (the pod's terminationGracePeriodSeconds) must allow the drain deadline plus
// this, or the process is killed mid-cancel and its jobs stay running.
const StopOverrun = stopCancelWindow + deregisterTimeout

// rescueMargin is how far River's RescueStuckJobsAfter sits above the longest
// worker timeout. River rescues a job that has been running that long even if
// its client is alive, so the value must exceed every worker's Timeout:
// otherwise a slow but healthy job (a 30m scan) is re-run while it is still
// running. Jobs of instances that died are reclaimed within about a minute by
// the instance heartbeat (instances.go); this rescue is the backstop for
// clients that never registered, such as an older deckard mid-rollout.
const rescueMargin = 5 * time.Minute

// workerSet registers River workers and remembers what it registered.
type workerSet struct {
	workers  *river.Workers
	timeouts map[string]time.Duration
	err      error
}

func addWorker[T river.JobArgs](s *workerSet, w river.Worker[T]) {
	river.AddWorker(s.workers, w)
	var args T
	kind := args.Kind()
	d := w.Timeout(&river.Job[T]{})
	switch {
	case d < 0:
		// No timeout: River would rescue (and so re-run) it while it runs.
		s.err = errors.Join(s.err, fmt.Errorf("engine: worker %s has no timeout; the stuck-job rescue needs one", kind))
	case d == 0:
		d = river.JobTimeoutDefault
	}
	s.timeouts[kind] = d
}

// rescueAfter is the longest worker timeout plus rescueMargin.
func (s *workerSet) rescueAfter() time.Duration {
	var longest time.Duration
	for _, d := range s.timeouts {
		longest = max(longest, d)
	}
	return longest + rescueMargin
}

func (e *Engine) newClient() (*river.Client[pgx.Tx], error) {
	ws := &workerSet{workers: river.NewWorkers(), timeouts: map[string]time.Duration{}}
	addWorker(ws, &syncWorker{r: e.r})
	addWorker(ws, &scanWorker{r: e.r})
	addWorker(ws, &scheduleWorker{r: e.r})
	addWorker(ws, &housekeepingWorker{r: e.r})
	addWorker(ws, &expandWorker{r: e.r})
	addWorker(ws, &scheduleExpansionWorker{r: e.r})
	addWorker(ws, &refdataWorker{e: e})
	addWorker(ws, &updateTemplatesWorker{r: e.r})
	addWorker(ws, &scanNewTemplatesWorker{r: e.r})
	addWorker(ws, &scanCVEsWorker{r: e.r})
	addWorker(ws, &vulnintelWorker{e: e})
	if ws.err != nil {
		return nil, ws.err
	}
	e.timeouts = ws.timeouts
	e.rescueAfter = ws.rescueAfter()
	e.clientID = newClientID(time.Now())

	cfg := &river.Config{
		// Explicit (River's default shape) so the instance heartbeat knows
		// which attempted_by entries are ours; see instances.go.
		ID:      e.clientID,
		Workers: ws.workers,
		Logger:  e.r.log,
		// River's default is an hour, so a job orphaned by an instance that
		// never registered blocked its unique successors that long.
		RescueStuckJobsAfter: e.rescueAfter,
		// Default River retry policy: exponential backoff (attempt^4 seconds
		// with jitter); per-kind MaxAttempts are set in jobs.go.
	}
	switch {
	case e.roles[RoleWorker]:
		cfg.Queues = map[string]river.QueueConfig{}
		for q, n := range e.o.queueWorkers {
			cfg.Queues[q] = river.QueueConfig{MaxWorkers: n}
		}
		if !e.roles[RoleScheduler] {
			// River's elected leader inserts the periodic jobs it was
			// configured with. A worker-only node has none, so it must not be
			// elected; a scheduler node supplies leadership and maintenance.
			cfg.LeaderElectionDisabled = true
		}
	case e.roles[RoleScheduler]:
		// River only runs leader election / periodic jobs on clients that
		// execute jobs, so a scheduler-only node gets the small default queue
		// (tick and housekeeping jobs only).
		cfg.Queues = map[string]river.QueueConfig{QueueDefault: {MaxWorkers: 1}}
	}
	if e.roles[RoleScheduler] {
		cfg.PeriodicJobs = e.periodicJobs()
	}
	return river.NewClient(riverpgxv5.New(e.d.Pool), cfg)
}

func (e *Engine) periodicJobs() []*river.PeriodicJob {
	var jobs []*river.PeriodicJob
	for _, s := range e.d.Sources {
		name := s.Name()
		if e.d.Config.Sync.Interval <= 0 {
			break
		}
		jobs = append(jobs, river.NewPeriodicJob(
			jitterSchedule{interval: e.d.Config.Sync.Interval, frac: e.o.syncJitter},
			func() (river.JobArgs, *river.InsertOpts) { return SyncSourceArgs{Source: name}, nil },
			&river.PeriodicJobOpts{ID: "sync:" + name, RunOnStart: true}))
	}
	for _, t := range allTiers {
		tier := t
		jobs = append(jobs, river.NewPeriodicJob(
			river.PeriodicInterval(e.o.tick),
			func() (river.JobArgs, *river.InsertOpts) { return ScheduleTierArgs{Tier: tier}, nil },
			&river.PeriodicJobOpts{ID: "tick:" + string(tier), RunOnStart: true}))
	}
	if e.expansionEnabled() {
		jobs = append(jobs, river.NewPeriodicJob(
			jitterSchedule{interval: e.d.Config.Expansion.Interval, frac: e.o.syncJitter},
			func() (river.JobArgs, *river.InsertOpts) { return ScheduleExpansionArgs{}, nil },
			&river.PeriodicJobOpts{ID: "expansion", RunOnStart: true}))
	}
	jobs = append(jobs, e.refdataPeriodicJobs()...)
	if e.templateUpdateEnabled() {
		// Scheduler role only (this runs only there); a node that executes the
		// maintenance queue picks the job up. Jittered, and once at start.
		jobs = append(jobs, river.NewPeriodicJob(
			jitterSchedule{interval: e.d.Config.Nuclei.Update.Interval, frac: e.o.syncJitter},
			func() (river.JobArgs, *river.InsertOpts) { return UpdateTemplatesArgs{}, nil },
			&river.PeriodicJobOpts{ID: "update_templates", RunOnStart: true}))
	}
	jobs = append(jobs, e.vulnintelPeriodic()...)
	jobs = append(jobs, river.NewPeriodicJob(
		river.PeriodicInterval(time.Minute),
		func() (river.JobArgs, *river.InsertOpts) { return HousekeepingArgs{}, nil },
		&river.PeriodicJobOpts{ID: "housekeeping"}))
	return jobs
}

// Start begins processing. It is a no-op for an api-only instance.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started {
		return errors.New("engine: already started")
	}
	if !e.roles[RoleWorker] && !e.roles[RoleScheduler] {
		return nil
	}
	if e.client == nil {
		return fmt.Errorf("engine: start: %w", ErrNoQueue)
	}
	// Register before River fetches anything, so every job this client runs
	// belongs to a registered, heartbeating instance.
	if err := e.heartbeat(ctx); err != nil {
		return fmt.Errorf("engine: start: %w", err)
	}
	if err := e.client.Start(ctx); err != nil {
		e.deregisterQuietly()
		return fmt.Errorf("engine: start river: %w", err)
	}
	e.started = true
	for k := range e.timeouts {
		e.r.rec.JobsReclaimed(k, 0) // series exist from the start, so increase() sees the first reclaim
	}
	ictx, icancel := context.WithCancel(context.WithoutCancel(ctx))
	e.stopInst, e.instDone = icancel, make(chan struct{})
	go e.instanceLoop(ictx, e.instDone)
	gctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	e.stopGau, e.gauDone = cancel, make(chan struct{})
	go e.gaugeLoop(gctx, e.gauDone)
	if e.roles[RoleWorker] && e.templateUpdateEnabled() {
		tctx, tcancel := context.WithCancel(context.WithoutCancel(ctx))
		e.stopGuard, e.guardDone = tcancel, make(chan struct{})
		go e.templateGuard(tctx, e.guardDone)
	}
	return nil
}

// templateUpdateEnabled reports whether this engine updates nuclei templates.
func (e *Engine) templateUpdateEnabled() bool {
	u := e.d.Config.Nuclei.Update
	return e.d.Templates != nil && u.Enabled && u.Interval > 0
}

// Stop stops fetching new jobs and waits for in-flight ones until ctx expires,
// after which running jobs are cancelled (their contexts are cancelled and
// River retries them on the next start). Once River has stopped cleanly the
// instance is deregistered; if it has not, the row stays and goes stale, so
// peers reclaim whatever is still marked running.
func (e *Engine) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started {
		return nil
	}
	e.started = false
	e.stopGau()
	<-e.gauDone
	if e.stopGuard != nil {
		e.stopGuard()
		<-e.guardDone
		e.stopGuard = nil
	}
	// The heartbeat stops first: from here on the row only says "this client
	// existed", and it is either deleted below or left to go stale.
	e.stopInst()
	<-e.instDone
	err := e.client.Stop(ctx)
	if err != nil && ctx.Err() != nil {
		cctx, cancel := context.WithTimeout(context.Background(), stopCancelWindow)
		defer cancel()
		if cerr := e.client.StopAndCancel(cctx); cerr != nil {
			return errors.Join(err, cerr)
		}
		e.deregisterQuietly()
		return fmt.Errorf("engine: graceful stop deadline hit, in-flight jobs cancelled: %w", err)
	}
	if err == nil {
		e.deregisterQuietly()
	}
	return err
}

// deregisterQuietly removes this instance's row on a fresh, short context (the
// stop context may have expired). A failure only leaves a row that goes stale
// and is pruned; with nothing left running there is nothing to reclaim.
func (e *Engine) deregisterQuietly() {
	ctx, cancel := context.WithTimeout(context.Background(), deregisterTimeout)
	defer cancel()
	if err := e.deregister(ctx); err != nil {
		e.r.log.Warn("engine stop", "err", err)
	}
}

// RunOnce performs one sync of every source, then one scan pass of every due
// asset, synchronously and without River. It uses the same handlers as the
// job workers. Errors from individual sources/scans are joined; the pass
// always completes.
func (e *Engine) RunOnce(ctx context.Context) error {
	return e.RunOnceWith(ctx, RunOnceOptions{})
}

// RunOnceOptions tunes RunOnceWith.
type RunOnceOptions struct {
	// SkipTemplateUpdate skips the nuclei template update that otherwise runs
	// first when nuclei.update is enabled (air-gapped one-shot scans).
	SkipTemplateUpdate bool
}

// RunOnceWith is RunOnce with options. When the template updater is enabled it
// runs first, so a one-off scan uses fresh templates; the templates an update
// added are then run against every eligible web asset after the regular scan
// pass (as a partial run, so nothing is resolved). An update failure is joined
// into the result and the pass continues with the templates already installed.
func (e *Engine) RunOnceWith(ctx context.Context, opts RunOnceOptions) error {
	mq := newMemQueue()
	r := e.r.withQueue(mq)
	var errs []error
	e.refreshRefdata(ctx)
	var upd updater.Update
	var updated bool
	if !opts.SkipTemplateUpdate && e.templateUpdateEnabled() {
		var err error
		if upd, updated, err = r.updateTemplates(ctx, 0); err != nil {
			errs = append(errs, err)
		}
	}
	// Exploit intel first so this pass's findings are enriched from fresh
	// feeds. Failures (e.g. offline) are logged by the job and never fail
	// the pass: enrichment is best-effort.
	_ = e.refreshVulnintel(ctx)
	for _, s := range e.d.Sources {
		if err := r.runSync(ctx, s.Name()); err != nil {
			errs = append(errs, err)
		}
	}
	if err := r.housekeeping(ctx); err != nil {
		errs = append(errs, err)
	}
	for _, t := range allTiers {
		if _, err := r.scheduleTier(ctx, t); err != nil {
			errs = append(errs, err)
		}
	}
	// Expansion first: newly discovered names get their immediate scans queued
	// into the same pass. Failures are joined and never stop the pass.
	if _, err := r.scheduleExpansion(ctx, false); err != nil {
		errs = append(errs, err)
	}
	for _, id := range mq.takeZones() {
		if ctx.Err() != nil {
			break
		}
		if err := r.runExpand(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	// Drain until quiescent: scans can discover assets that queue more scans.
	sem := make(chan struct{}, e.o.runOnceWorkers)
	for ctx.Err() == nil {
		batch := mq.take()
		if len(batch) == 0 {
			break
		}
		var wg sync.WaitGroup
		var emu sync.Mutex
		for _, j := range batch {
			wg.Add(1)
			sem <- struct{}{}
			go func(j scanJob) {
				defer wg.Done()
				defer func() { <-sem }()
				if err := r.runScan(ctx, j); err != nil {
					emu.Lock()
					errs = append(errs, err)
					emu.Unlock()
				}
			}(j)
		}
		wg.Wait()
	}
	// Brand-new templates run against every eligible web asset, whatever its
	// technology tags, once the regular pass (which creates and refreshes the
	// assets and their findings) is done.
	if updated && upd.Changed && ctx.Err() == nil {
		if _, err := r.enqueueNewTemplateScans(ctx, upd); err != nil {
			errs = append(errs, err)
		}
		for _, j := range mq.takeDeltas() {
			if ctx.Err() != nil {
				break
			}
			if err := r.runDelta(ctx, j); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ---- operator actions (api.Actions) --------------------------------------

// RescanAsset queues every applicable check of every tier for the asset now,
// ignoring the due interval but not the scope guard or profile: tiers that are
// out of scope or disabled for the asset are not queued. It returns
// ErrNotScannable when nothing could be queued.
func (e *Engine) RescanAsset(ctx context.Context, assetID int64) error {
	a, err := e.d.Store.GetAsset(ctx, assetID)
	if err != nil {
		return fmt.Errorf("rescan asset %d: %w", assetID, err)
	}
	eligible := 0
	for _, t := range allTiers {
		if _, _, why := e.r.scannable(*a, t); why != "" {
			continue
		}
		for _, c := range e.r.checksFor(*a, t, "") {
			eligible++
			if _, err := e.r.q.enqueueScan(ctx, scanJob{AssetID: a.ID, Tier: t, Check: c.Name()}); err != nil {
				return fmt.Errorf("rescan asset %d: %w", assetID, err)
			}
		}
	}
	if eligible == 0 {
		return fmt.Errorf("rescan asset %d: %w", assetID, ErrNotScannable)
	}
	return nil
}

// TriggerSync queues an immediate sync of the named source.
func (e *Engine) TriggerSync(ctx context.Context, source string) error {
	if _, ok := e.r.sources[source]; !ok {
		return &UnknownSourceError{Name: source}
	}
	if _, err := e.r.q.enqueueSync(ctx, source); err != nil {
		return fmt.Errorf("trigger sync %s: %w", source, err)
	}
	return nil
}

// ---- queue depth gauge ---------------------------------------------------

func (e *Engine) gaugeLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(e.o.gaugeEvery)
	defer t.Stop()
	for {
		e.reportDepth(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (e *Engine) reportDepth(ctx context.Context) {
	rows, err := e.d.Pool.Query(ctx,
		`SELECT queue, count(*) FROM river_job WHERE state IN ('available','retryable') GROUP BY queue`)
	if err != nil {
		if ctx.Err() == nil {
			e.r.log.Warn("queue depth", "err", err)
		}
		return
	}
	defer rows.Close()
	depth := map[string]int{}
	for q := range e.o.queueWorkers {
		depth[q] = 0
	}
	for rows.Next() {
		var q string
		var n int
		if err := rows.Scan(&q, &n); err != nil {
			return
		}
		depth[q] = n
	}
	for q, n := range depth {
		e.r.rec.SetQueueDepth(q, n)
	}
}
