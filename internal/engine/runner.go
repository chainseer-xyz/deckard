package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/inventory"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/store"
)

const defaultCheckTimeout = 2 * time.Minute

// SkippedPrefix starts the Error of a ScanRun that was refused (scope or
// profile) and never touched the network.
const SkippedPrefix = store.SkippedPrefix

// runner holds the job handlers. It is queue-agnostic so River workers and
// RunOnce share one code path.
type runner struct {
	Deps
	log      *slog.Logger
	rec      Recorder
	now      func() time.Time
	q        queue
	checks   []check.Check
	slow     map[string]bool // names of checks that implement check.SlowLookups
	sources  map[string]source.Source
	limiters *limiterSet
	sems     *keyedSem

	ctWarn *zoneWarnThrottle // transient CT warnings, shared by copies

	mu *sync.Mutex
	// last is a small in-process overlay of the attempts this process made, so
	// a tick never re-enqueues what it just ran even if the store read lags.
	last map[ScanKey]store.ScanLast
}

func newRunner(d Deps) *runner {
	r := &runner{
		Deps:     d,
		log:      d.Logger,
		rec:      d.Recorder,
		now:      d.Now,
		checks:   d.Checks,
		slow:     slowChecks(d.Checks),
		sources:  map[string]source.Source{},
		limiters: newLimiterSet(),
		sems:     newKeyedSem(),
		q:        noQueue{},
		last:     map[ScanKey]store.ScanLast{},
		mu:       &sync.Mutex{},
		ctWarn:   &zoneWarnThrottle{},
	}
	if r.log == nil {
		r.log = slog.Default()
	}
	if r.rec == nil {
		r.rec = noopRecorder{}
	}
	if r.now == nil {
		r.now = time.Now
	}
	for _, s := range d.Sources {
		r.sources[s.Name()] = s
	}
	return r
}

// slowChecks names the checks that declare check.SlowLookups.
func slowChecks(checks []check.Check) map[string]bool {
	out := map[string]bool{}
	for _, c := range checks {
		if s, ok := c.(check.SlowLookups); ok && s.SlowLookups() {
			out[c.Name()] = true
		}
	}
	return out
}

// scanQueue is the River queue for a scan job. It is decided here, when the
// job is inserted, and stays with the row: River retries and reclaim of
// orphaned jobs only change its state, so a job always comes back to the queue
// it was routed to. A job that names no check runs every check of its tier and
// follows the tier.
func (r *runner) scanQueue(j scanJob) string {
	return queueForScan(j.Tier, j.Check != "" && r.slow[j.Check])
}

// withQueue returns a shallow copy that enqueues to q.
func (r *runner) withQueue(q queue) *runner {
	c := *r
	c.q = q
	return &c
}

func (r *runner) allowed(kind model.AssetKind, tier model.Tier, class model.ScopeClass) bool {
	if !scope.AllowedFor(kind, tier, class) {
		return false
	}
	if g, ok := r.Guard.(interface {
		AllowedFor(model.AssetKind, model.Tier, model.ScopeClass) bool
	}); ok {
		return g.AllowedFor(kind, tier, class)
	}
	return true
}

// checksFor lists the checks of tier that apply to a (optionally one by name).
func (r *runner) checksFor(a model.Asset, tier model.Tier, name string) []check.Check {
	var out []check.Check
	for _, c := range r.checks {
		if c.Tier() != tier || (name != "" && c.Name() != name) {
			continue
		}
		if c.Applies(a) {
			out = append(out, c)
		}
	}
	return out
}

// scannable reports whether (asset, tier) may be probed right now: the asset
// is live, was not created by the ingest API, its freshly computed class
// permits the tier, and the profile is on. The returned string says why not.
//
// Ingested assets are reported by scanners that run elsewhere; deckard stores
// their findings but never reaches the targets, whatever class the asset is
// labelled with (an operator may allow-list a tool's assets as owned) and
// whatever the guard would say about the key.
func (r *runner) scannable(a model.Asset, tier model.Tier) (model.ScopeClass, Resolved, string) {
	class := r.Guard.Classify(a.Kind, a.Key)
	prof := ResolveProfile(r.Config, a, tier)
	switch {
	case a.RemovedAt != nil:
		return class, prof, "asset removed"
	case model.IsIngestSource(a.Source):
		return class, prof, "ingested asset: findings come from an external scanner, deckard never probes it"
	case !r.allowed(a.Kind, tier, class):
		return class, prof, fmt.Sprintf("scope: %s tier not allowed for %s %s asset", tier, class, a.Kind)
	case !prof.Enabled:
		return class, prof, fmt.Sprintf("profile: %s tier disabled for this asset", tier)
	}
	return class, prof, ""
}

// ---- scan ----------------------------------------------------------------

// runScan executes the checks selected by j against one asset.
//
// SAFETY INVARIANT: Check.Run is reached only after the asset has been
// re-classified by the Guard (ignoring any stored class), scope.AllowedFor
// (and the Guard's own AllowedFor, if any) accepts (kind, tier, class), and the
// resolved profile is enabled. Otherwise a skipped ScanRun is recorded and no
// check, dialer, resolver or HTTP client is ever created. Even once running,
// every network handle given to the check is guard-wrapped with the fresh class.
//
// An owned name whose addresses the tier may not reach (a CDN edge, a
// third-party host) is skipped the same way before anything is dialled (see
// destinationSkip). A skip made no observation: its result never reaches the
// finding processor or the inventory, so it can never refresh, miss, resolve
// or garbage-collect anything.
func (r *runner) runScan(ctx context.Context, j scanJob) error {
	asset, err := r.Store.GetAsset(ctx, j.AssetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			r.log.Debug("scan: asset gone", "asset_id", j.AssetID)
			return nil
		}
		return fmt.Errorf("load asset %d: %w", j.AssetID, err)
	}
	if !j.Tier.Valid() {
		r.log.Warn("scan: invalid tier", "tier", j.Tier)
		return nil
	}
	if err := r.resolveInapplicable(ctx, *asset, j.Tier, j.Check); err != nil {
		return err
	}
	checks := r.checksFor(*asset, j.Tier, j.Check)
	if len(checks) == 0 {
		return nil
	}
	class, prof, why := r.scannable(*asset, j.Tier)
	if why != "" {
		r.log.Info("scan refused", "asset", asset.Key, "tier", j.Tier, "class", class, "reason", why)
		for _, c := range checks {
			r.recordScan(ctx, store.ScanRun{
				AssetID: asset.ID, Check: c.Name(), Tier: string(j.Tier),
				StartedAt: r.now(), Error: SkippedPrefix + why,
			})
		}
		return nil
	}
	if reason, detail := r.destinationSkip(ctx, *asset, j.Tier); reason != "" {
		for _, c := range checks {
			r.skipCheck(ctx, c, *asset, reason, detail)
		}
		return nil
	}
	edges, err := r.Store.Edges(ctx, asset.ID)
	if err != nil {
		return fmt.Errorf("load edges %d: %w", asset.ID, err)
	}
	neigh := make([]check.Neighbour, 0, len(edges))
	for _, e := range edges {
		neigh = append(neigh, check.Neighbour{Asset: e.Other, Relation: e.Type, Outbound: e.Outbound})
	}
	release, err := r.sems.acquire(ctx, string(j.Tier)+"|"+hostOf(*asset), prof.PerHostConcurrency)
	if err != nil {
		return err // shutting down; River retries the job
	}
	defer release()

	limiter := r.limiters.get(j.Tier, prof.RatePerSec)
	var firstErr error
	for _, c := range checks {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := r.runCheck(ctx, c, *asset, neigh, class, limiter); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// destinationVetter is implemented by *scope.Guard (see
// scope.Guard.DestinationSkip). Guards without it (test fakes) never skip.
type destinationVetter interface {
	DestinationSkip(ctx context.Context, tier model.Tier, host string) (reason, detail string)
}

// destinationLookupTimeout bounds the one DNS lookup behind destinationSkip.
const destinationLookupTimeout = 10 * time.Second

// destinationSkip reports whether the checks of tier would only be refused by
// the scope guard for an expected reason (an owned name on shared or external
// addresses, which only the passive tier may reach), so they are skipped
// before anything is dialled. It decides cheaply and early; the guard stays
// the final authority on every connection a check does make.
func (r *runner) destinationSkip(ctx context.Context, a model.Asset, tier model.Tier) (reason, detail string) {
	v, ok := r.Guard.(destinationVetter)
	if !ok || tier == model.TierPassive {
		return "", ""
	}
	host := destHost(a)
	if host == "" {
		return "", ""
	}
	lctx, cancel := context.WithTimeout(ctx, destinationLookupTimeout)
	defer cancel()
	return v.DestinationSkip(lctx, tier, host)
}

// destHost is the name or address a check's connections for a will resolve.
func destHost(a model.Asset) string {
	h := hostOf(a)
	if a.Kind == model.KindService {
		k, _, _ := strings.Cut(h, "/")
		if host, _, err := net.SplitHostPort(k); err == nil {
			return host
		}
	}
	return h
}

// skipCheck records a check skipped before it touched the network: a scan
// run marked store.UnownedDestinationSkip (scheduling treats it as settled,
// findings never see it), the skip counter, and a debug log. It is not a
// failure, so neither the error counter nor the "check failed" warning moves.
func (r *runner) skipCheck(ctx context.Context, c check.Check, a model.Asset, reason, detail string) {
	tier := string(c.Tier())
	r.rec.ObserveSkip(c.Name(), tier, reason)
	r.log.Debug("check skipped", "check", c.Name(), "asset", a.Key, "tier", tier, "reason", reason, "detail", detail)
	r.recordScan(ctx, store.ScanRun{
		AssetID: a.ID, Check: c.Name(), Tier: tier, StartedAt: r.now(),
		Error: store.UnownedDestinationSkip + detail,
	})
}

// runCheck runs one check and records the outcome. Check failures (including
// panics and timeouts) are recorded, not returned: only infrastructure errors
// the job should retry are returned.
func (r *runner) runCheck(ctx context.Context, c check.Check, asset model.Asset, neigh []check.Neighbour,
	class model.ScopeClass, limiter scope.RateLimiter) error {

	tier := c.Tier()
	timeout := r.timeoutFor(c)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer, refusals := trackRefusals(r.Guard.Dialer(tier, class, limiter))
	target := check.Target{
		Asset:      asset,
		Neighbours: neigh,
		Baseline:   map[string]map[string]any{},
		Dialer:     dialer,
		Resolver:   r.Guard.Resolver(tier, class, limiter),
		HTTP:       r.Guard.HTTPClient(tier, class, limiter, scope.WithHTTPTimeout(timeout)),
		Intel:      r.Intel,
		Lookup:     r.Lookup,
		Config:     r.Config.Checks[c.Name()],
	}
	// The scope-guarded rcode-aware DNS client is optional: guards that do not
	// provide one (test fakes) leave Target.DNS nil and checks fall back to Resolver.
	if dg, ok := r.Guard.(interface {
		DNS(model.Tier, model.ScopeClass, scope.RateLimiter) check.DNSQuerier
	}); ok {
		target.DNS = dg.DNS(tier, class, limiter)
	}
	start := r.now()
	var res *check.Result
	var runErr error
	if w, ok := c.(check.WantsOwnedZones); ok && w.WantsOwnedZones() {
		// A check that excludes the estate's own names must not run without
		// the list, or it would report them as somebody else's.
		if zones, err := r.ownedZoneNames(cctx); err != nil {
			runErr = fmt.Errorf("list owned zones: %w", err)
		} else {
			target.OwnedZones = zones
		}
	}
	if w, ok := c.(check.WantsOpenFindings); ok && w.WantsOpenFindings() && runErr == nil {
		// A failed lookup fails the run: a check that re-verifies findings must
		// never run blind, or it could let them resolve unverified.
		if of, err := r.openFindings(cctx, asset.ID, c.Name()); err != nil {
			runErr = fmt.Errorf("load open findings: %w", err)
		} else {
			target.OpenFindings = of
		}
	}
	if b, err := r.Store.GetBaseline(cctx, asset.ID, c.Name()); err == nil && b != nil {
		target.Baseline[c.Name()] = b.Data
	} else if err != nil && !errors.Is(err, store.ErrNotFound) && runErr == nil {
		runErr = fmt.Errorf("load baseline: %w", err)
	}
	if w, ok := c.(check.WantsBaselines); ok && runErr == nil {
		for _, name := range w.BaselineChecks() {
			if name == c.Name() {
				continue
			}
			if b, err := r.Store.GetBaseline(cctx, asset.ID, name); err == nil && b != nil {
				target.Baseline[name] = b.Data
			} else if err != nil && !errors.Is(err, store.ErrNotFound) {
				runErr = fmt.Errorf("load baseline %s: %w", name, err)
				break
			}
		}
	}
	if runErr == nil {
		res, runErr = safeRun(cctx, c, target)
	}
	findings := 0
	if runErr == nil {
		if res == nil {
			res = &check.Result{}
		}
		findings = len(res.Findings)
		if refusals.refused.Load() && !res.Partial {
			// The guard refused at least one connection: what the check did not
			// reach proves nothing, so nothing may be missed or resolved.
			res.Partial = true
			r.log.Debug("check run had scope refusals, treated as partial", "check", c.Name(), "asset", asset.Key)
		}
		if _, err := r.Findings.Process(cctx, asset, c.Name(), res); err != nil {
			runErr = fmt.Errorf("process findings: %w", err)
		} else if res.Partial {
			// Absence proves nothing in a partial run: replacing would remove
			// the derived children it did not see and resolve their findings.
		} else if err := r.replaceDerived(cctx, asset.ID, c.Name(), res); err != nil {
			runErr = fmt.Errorf("replace derived: %w", err)
		}
	}
	d := r.now().Sub(start)
	r.rec.ObserveScan(c.Name(), string(tier), d, runErr)
	run := store.ScanRun{
		AssetID: asset.ID, Check: c.Name(), Tier: string(tier),
		StartedAt: start, DurationMS: d.Milliseconds(), Findings: findings,
	}
	if runErr != nil {
		run.Error = runErr.Error()
		r.log.Warn("check failed", "check", c.Name(), "asset", asset.Key, "err", runErr)
	}
	r.recordScan(ctx, run)
	return nil
}

// ownedZoneNames lists every live owned zone asset, one query.
func (r *runner) ownedZoneNames(ctx context.Context) ([]string, error) {
	assets, _, err := r.Store.ListAssets(ctx, store.AssetFilter{Kind: model.KindZone, Scope: model.ScopeOwned})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(assets))
	for _, a := range assets {
		out = append(out, strings.ToLower(strings.TrimSuffix(a.Key, ".")))
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// unresolvedStatuses are the finding states a re-verifying check must keep
// checking: everything the processor can still resolve.
var unresolvedStatuses = []model.FindingStatus{
	model.StatusOpen, model.StatusAcknowledged, model.StatusSuppressed, model.StatusFalsePositive,
}

// openFindings returns the asset's unresolved findings of one check, one
// indexed query (findings_asset_check_idx), bounded by check.MaxOpenFindings.
func (r *runner) openFindings(ctx context.Context, assetID int64, name string) ([]check.OpenFinding, error) {
	fs, _, err := r.Store.ListFindings(ctx, store.FindingFilter{
		AssetID: assetID, Check: name, Statuses: unresolvedStatuses, Limit: check.MaxOpenFindings,
	})
	if err != nil {
		return nil, err
	}
	out := make([]check.OpenFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, check.OpenFinding{Fingerprint: f.Fingerprint, Severity: f.Severity, Status: f.Status, Evidence: f.Evidence})
	}
	return out, nil
}

// safeRun calls the check, converting a panic into an error so one bad check
// cannot take down the worker.
func safeRun(ctx context.Context, c check.Check, t check.Target) (res *check.Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			res = nil
			slog.Error("check panicked", "check", c.Name(), "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			err = fmt.Errorf("check %s panicked: %v", c.Name(), p)
		}
	}()
	res, err = c.Run(ctx, t)
	if err == nil && ctx.Err() != nil {
		return nil, fmt.Errorf("check %s: %w", c.Name(), ctx.Err())
	}
	return res, err
}

// recordScan persists a ScanRun even when ctx is already cancelled (shutdown).
func (r *runner) recordScan(ctx context.Context, run store.ScanRun) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := r.Store.RecordScan(rctx, run); err != nil {
		r.log.Error("record scan", "err", err, "asset_id", run.AssetID, "check", run.Check)
		return
	}
	r.mu.Lock()
	k := ScanKey{run.AssetID, run.Check}
	l := r.last[k]
	l.AssetID, l.Check = run.AssetID, run.Check
	if run.StartedAt.After(l.LastAttempt) {
		l.LastAttempt = run.StartedAt
	}
	if run.Settled() && run.StartedAt.After(l.LastSuccess) {
		l.LastSuccess = run.StartedAt
	}
	r.last[k] = l
	r.mu.Unlock()
}

// checkTimeout reads checks.<name>.timeout (duration string, time.Duration or
// seconds), default 2m.
func (r *runner) checkTimeout(name string) time.Duration {
	if d, ok := r.configuredTimeout(name); ok {
		return d
	}
	return defaultCheckTimeout
}

// timeoutFor is the deadline of one run of c: checks.<name>.timeout, else the
// check's own default (check.DefaultTimeouter), else 2m.
func (r *runner) timeoutFor(c check.Check) time.Duration {
	// nuclei.check.timeout is the per-request flag consumed by the scanner.
	// Its process deadline is run_timeout, exposed through DefaultTimeout.
	if strings.HasSuffix(c.Name(), ".nuclei") {
		if dt, ok := c.(check.DefaultTimeouter); ok {
			if d := dt.DefaultTimeout(); d > 0 {
				return d
			}
		}
	}
	if d, ok := r.configuredTimeout(c.Name()); ok {
		return d
	}
	if dt, ok := c.(check.DefaultTimeouter); ok {
		if d := dt.DefaultTimeout(); d > 0 {
			return d
		}
	}
	return defaultCheckTimeout
}

func (r *runner) configuredTimeout(name string) (time.Duration, bool) {
	if v, ok := r.Config.Checks[name]["timeout"]; ok {
		switch t := v.(type) {
		case time.Duration:
			if t > 0 {
				return t, true
			}
		case string:
			if d, err := time.ParseDuration(strings.TrimSpace(t)); err == nil && d > 0 {
				return d, true
			}
		case int:
			if t > 0 {
				return time.Duration(t) * time.Second, true
			}
		case int64:
			if t > 0 {
				return time.Duration(t) * time.Second, true
			}
		case float64:
			if t > 0 {
				return time.Duration(t * float64(time.Second)), true
			}
		}
	}
	return 0, false
}

// replaceDerived tells the inventory what a SUCCESSFUL run of check origin
// observed about the scanned asset parentID, including "nothing", so that
// derived assets and relations the check no longer sees (closed ports, removed
// SANs, changed IPs) are garbage-collected. It is never called for a failed,
// panicked or timed-out run: a failed scan must not delete anything. New
// assets in the diff get immediate scans.
func (r *runner) replaceDerived(ctx context.Context, parentID int64, origin string, res *check.Result) error {
	diff, err := r.Inventory.ReplaceDerived(ctx, parentID, origin, res.Discovered, res.Relations)
	if err != nil {
		return err
	}
	r.reportDiff(diff)
	r.enqueueImmediate(ctx, diff.Added, diff.Revived)
	return nil
}

func (r *runner) reportDiff(d store.InventoryDiff) {
	for kind, n := range map[string]int{"added": len(d.Added), "removed": len(d.Removed), "changed": len(d.Changed), "revived": len(d.Revived)} {
		if n > 0 {
			r.rec.InventoryChange(kind, n)
		}
	}
}

// immediateTiers are the tiers an inventory change may trigger. Intrusive is
// deliberately absent: an intrusive probe can disturb a service, so it only ever
// runs on its own schedule or when an operator asks, never as a side effect of
// something merely appearing in the inventory.
var immediateTiers = []model.Tier{model.TierPassive, model.TierActive}

// enqueueImmediate queues scans for assets that just appeared or changed. A
// check is queued when its tier is enabled for the asset, the tier has
// on_inventory_change, the check has not opted out (checks.<name>.on_new_asset)
// and the scope guard allows it (scannable). Active scans keep their normal
// rate limiting and scope guarding in runScan. Failures are logged: the
// periodic tick still catches them.
func (r *runner) enqueueImmediate(ctx context.Context, groups ...[]model.Asset) {
	for _, g := range groups {
		for _, a := range g {
			for _, tier := range immediateTiers {
				if _, _, why := r.scannable(a, tier); why != "" {
					continue
				}
				for _, c := range r.checksFor(a, tier, "") {
					if !resolveFor(r.Config, a, tier, c).OnInventoryChange {
						continue
					}
					if _, err := r.q.enqueueScan(ctx, scanJob{AssetID: a.ID, Tier: tier, Check: c.Name()}); err != nil {
						r.log.Warn("enqueue immediate scan", "asset", a.Key, "tier", tier, "check", c.Name(), "err", err)
					}
				}
			}
		}
	}
}

// ---- sync ----------------------------------------------------------------

// runSync syncs one source. inventory.Sync never marks assets removed on a
// failure. It may return a non-empty diff together with an error (a suspicious
// shrink refused the removals but upserts were applied): the engine still acts
// on that diff, records the sync as failed, and returns the error wrapped so
// the worker can make it permanent for this attempt.
func (r *runner) runSync(ctx context.Context, name string) error {
	src, ok := r.sources[name]
	if !ok {
		r.log.Warn("sync: unknown source (config changed?)", "source", name)
		return nil // not retryable
	}
	start := r.now()
	diff, err := r.Inventory.Sync(ctx, src)
	r.rec.ObserveSync(name, r.now().Sub(start), err == nil)
	shrink := errors.Is(err, inventory.ErrSuspiciousShrink)
	if shrink {
		r.log.Warn("sync: suspicious shrink, removals refused; the next periodic sync re-evaluates",
			"source", name, "reason", err.Error())
	}
	if err != nil && !shrink {
		return fmt.Errorf("sync %s: %w", name, err)
	}
	r.reportDiff(diff)
	r.log.Info("sync complete", "source", name, "added", len(diff.Added), "changed", len(diff.Changed),
		"revived", len(diff.Revived), "removed", len(diff.Removed), "ok", err == nil)
	r.enqueueImmediate(ctx, diff.Added, diff.Changed, diff.Revived) // removed assets are never scanned
	r.expandNewZones(ctx, diff.Added, diff.Revived)
	if err != nil {
		return fmt.Errorf("sync %s: %w", name, err)
	}
	return nil
}

// ---- scheduling ----------------------------------------------------------

// scheduleTier enqueues a scan for every (asset, check) of tier that is due:
// never scanned, or last attempted at least the resolved interval ago. Assets
// the scope guard or profile rule out are skipped here too (and re-checked in
// runScan). Returns the number of jobs newly queued.
func (r *runner) scheduleTier(ctx context.Context, tier model.Tier) (int, error) {
	var tierChecks []check.Check
	for _, c := range r.checks {
		if c.Tier() == tier {
			tierChecks = append(tierChecks, c)
		}
	}
	if len(tierChecks) == 0 {
		return 0, nil
	}
	assets, _, err := r.Store.ListAssets(ctx, store.AssetFilter{})
	if err != nil {
		return 0, fmt.Errorf("list assets: %w", err)
	}
	rows, err := r.Store.LastScans(ctx)
	if err != nil {
		return 0, fmt.Errorf("scan state: %w", err)
	}
	last := make(map[ScanKey]store.ScanLast, len(rows))
	for _, l := range rows {
		last[ScanKey{l.AssetID, l.Check}] = l
	}
	retry := r.errorRetry()
	now := r.now()
	queued := 0
	for _, a := range assets {
		// Tier enabled, scope and removal gate everything first; per-check
		// interval overrides only change cadence afterwards.
		if _, _, why := r.scannable(a, tier); why != "" {
			continue
		} else {
			for _, c := range tierChecks {
				if !c.Applies(a) {
					// Only previously attempted pairs need cleanup. Durable state
					// avoids probing every never-applicable (asset, check) pair.
					if _, known := last[ScanKey{a.ID, c.Name()}]; known {
						if err := r.resolveInapplicable(ctx, a, tier, c.Name()); err != nil {
							return queued, err
						}
					}
					continue
				}
				interval := resolveFor(r.Config, a, tier, c).Interval
				if interval <= 0 {
					continue
				}
				k := ScanKey{a.ID, c.Name()}
				l := last[k]
				r.mu.Lock()
				if o, ok := r.last[k]; ok {
					if o.LastAttempt.After(l.LastAttempt) {
						l.LastAttempt = o.LastAttempt
					}
					if o.LastSuccess.After(l.LastSuccess) {
						l.LastSuccess = o.LastSuccess
					}
				}
				r.mu.Unlock()
				if !isDue(l, now, interval, retry) {
					continue
				}
				ok, err := r.q.enqueueScan(ctx, scanJob{AssetID: a.ID, Tier: tier, Check: c.Name()})
				if err != nil {
					return queued, fmt.Errorf("enqueue scan: %w", err)
				}
				if ok {
					queued++
				}
			}
		}
	}
	if queued > 0 {
		r.log.Debug("scheduled scans", "tier", tier, "queued", queued)
	}
	return queued, nil
}

// isDue reports whether a (asset, check) must run now. It is due when it never
// succeeded or its last success is at least interval old; but a recent failed
// attempt is not retried before min(interval, errRetry) has passed, so a
// broken target is not hammered every tick.
func isDue(l store.ScanLast, now time.Time, interval, errRetry time.Duration) bool {
	if l.LastAttempt.IsZero() && l.LastSuccess.IsZero() {
		return true
	}
	if !l.LastSuccess.IsZero() && now.Sub(l.LastSuccess) < interval {
		return false
	}
	if !l.LastAttempt.IsZero() && l.LastAttempt.After(l.LastSuccess) {
		return now.Sub(l.LastAttempt) >= min(interval, errRetry)
	}
	return true
}

const defaultErrorRetry = 10 * time.Minute

func (r *runner) errorRetry() time.Duration {
	if d := r.Config.Scheduling.ErrorRetry; d > 0 {
		return d
	}
	return defaultErrorRetry
}

// Default retention when the config leaves it unset (tests, library use).
const (
	defaultScanRetention     = 168 * time.Hour
	defaultRelationRetention = 720 * time.Hour
)

// housekeeping expires suppressions and prunes scan history and stale
// relations. Each step runs even if an earlier one failed; errors are joined.
func (r *runner) housekeeping(ctx context.Context) error {
	var errs []error
	now := r.now()
	n, err := r.Store.ExpireSuppressions(ctx, now)
	if err != nil {
		errs = append(errs, fmt.Errorf("expire suppressions: %w", err))
	} else if n > 0 {
		r.log.Info("suppressions expired", "count", n)
	}
	scans := r.Config.Retention.Scans
	if scans <= 0 {
		scans = defaultScanRetention
	}
	if n, err := r.Store.PruneScans(ctx, now.Add(-scans)); err != nil {
		errs = append(errs, fmt.Errorf("prune scans: %w", err))
	} else if n > 0 {
		r.log.Info("scan history pruned", "count", n)
	}
	rels := r.Config.Retention.Relations
	if rels <= 0 {
		rels = defaultRelationRetention
	}
	if n, err := r.Store.PruneRelations(ctx, now.Add(-rels)); err != nil {
		errs = append(errs, fmt.Errorf("prune relations: %w", err))
	} else if n > 0 {
		r.log.Info("stale relations pruned", "count", n)
	}
	return errors.Join(errs...)
}

// permanentSyncError reports whether a sync error must not be retried by the
// job queue: the next periodic sync re-evaluates it.
func permanentSyncError(err error) bool { return errors.Is(err, inventory.ErrSuspiciousShrink) }
