// Package finding turns check output into the finding lifecycle: it learns
// baselines and emits drift, reconciles findings in the store, applies YAML
// suppressions and dispatches notifications.
package finding

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

// Ticker abstracts time.Ticker so tests can drive the dispatcher.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type options struct {
	now            func() time.Time
	newTicker      func(d time.Duration) Ticker
	ignore         map[string][]string
	notifyTimeout  time.Duration
	maxTracked     int
	enricher       *Enricher
	enricherSet    bool
	suppressions   []config.Suppression
	batchSize      int
	intel          vulnintel.Intel
	intelPolicy    IntelPolicy
	intelPolicySet bool
}

// Option configures a Processor or Dispatcher (options that do not apply to
// one of them are ignored).
type Option func(*options)

func buildOptions(opts []Option) options {
	o := options{
		now:           time.Now,
		newTicker:     func(d time.Duration) Ticker { return realTicker{time.NewTicker(d)} },
		notifyTimeout: 30 * time.Second,
		maxTracked:    10000,
		batchSize:     defaultBatchSize,
	}
	for _, f := range opts {
		f(&o)
	}
	return o
}

type realTicker struct{ *time.Ticker }

func (r realTicker) C() <-chan time.Time { return r.Ticker.C }

// WithClock injects the clock.
func WithClock(now func() time.Time) Option { return func(o *options) { o.now = now } }

// WithTicker injects the dispatcher's ticker factory.
func WithTicker(f func(d time.Duration) Ticker) Option { return func(o *options) { o.newTicker = f } }

// WithIgnoreKeys adds per-check volatile observation keys to ignore when
// comparing against the baseline, on top of DefaultIgnoreKeys.
func WithIgnoreKeys(byCheck map[string][]string) Option {
	return func(o *options) { o.ignore = byCheck }
}

// WithNotifyTimeout bounds each notifier call (default 30s).
func WithNotifyTimeout(d time.Duration) Option { return func(o *options) { o.notifyTimeout = d } }

// WithEnricher sets the Dispatcher's context enricher. nil disables
// enrichment; without this option NewDispatcher enriches from its store.
func WithEnricher(e *Enricher) Option {
	return func(o *options) { o.enricher, o.enricherSet = e, true }
}

// WithSuppressions gives the Dispatcher the configured YAML suppressions. It
// evaluates them before notifying and skips matching findings, so a finding
// reconciled as open but not yet suppressed by the Processor is never alerted
// (defence in depth). The lead wires cfg.Suppressions here.
func WithSuppressions(s []config.Suppression) Option {
	return func(o *options) { o.suppressions = s }
}

// WithBatchSize sets the maximum open findings per Notify call (default 100).
func WithBatchSize(n int) Option { return func(o *options) { o.batchSize = n } }

// WithMaxTracked bounds the dispatcher's per-notifier resolved-notice memory.
func WithMaxTracked(n int) Option { return func(o *options) { o.maxTracked = n } }

// ProcessorConfig is the processor's tuning.
type ProcessorConfig struct {
	ResolveAfter int // findings.resolve_after
	StableAfter  int // learning.stable_after
	Suppressions []config.Suppression
	// IgnoreKeys is learning.ignore_keys: extra volatile observation keys to
	// skip when comparing against the baseline, per check name, on top of
	// DefaultIgnoreKeys. The "*" entry applies to every check. The app wires
	// this from cfg.Learning.IgnoreKeys.
	IgnoreKeys map[string][]string
}

// Processor persists one check run for one asset.
type Processor struct {
	st   store.Store
	cfg  ProcessorConfig
	log  *slog.Logger
	opts options
	sup  *Suppressor
}

// NewProcessor builds a Processor. Invalid suppressions never match anything
// (and are logged loudly): call ValidateSuppressions at startup to fail fast.
func NewProcessor(st store.Store, cfg ProcessorConfig, log *slog.Logger, opts ...Option) *Processor {
	if log == nil {
		log = slog.Default()
	}
	sup, err := NewSuppressor(cfg.Suppressions)
	if err != nil {
		log.Error("finding: invalid suppressions ignored entirely", "err", err)
		sup = &Suppressor{}
	}
	if cfg.ResolveAfter < 1 {
		cfg.ResolveAfter = 1
	}
	if cfg.StableAfter < 1 {
		cfg.StableAfter = 3
	}
	return &Processor{st: st, cfg: cfg, log: log, opts: buildOptions(opts), sup: sup}
}

// ignoreFor merges the "*" keys, the configured per-check keys and any
// WithIgnoreKeys option keys for one check.
func (p *Processor) ignoreFor(check string) []string {
	var out []string
	for _, m := range []map[string][]string{p.cfg.IgnoreKeys, p.opts.ignore} {
		out = append(out, m["*"]...)
		out = append(out, m[check]...)
	}
	return out
}

// Process persists one check run for one asset: saves observations, learns or
// updates the baseline and emits drift findings, merges them with res.Findings,
// reconciles via store.ReconcileFindings, applies YAML suppressions and
// returns the lifecycle transitions.
//
// Drift findings are reconciled under check "drift.<observation check>" so
// they open, update and resolve independently of the check's own findings.
// Findings suppressed by config are reported in the result with their
// suppressed status.
func (p *Processor) Process(ctx context.Context, asset model.Asset, checkName string, res *check.Result) (store.ReconcileResult, error) {
	var out store.ReconcileResult
	if res == nil {
		return out, errors.New("process: nil result")
	}
	now := p.opts.now()

	driftBy := map[string][]model.FindingInput{}
	var driftOrder []string
	for _, o := range res.Observations {
		if o.Check == "" {
			o.Check = checkName
		}
		if err := p.st.SaveObservation(ctx, asset.ID, o, now); err != nil {
			return out, fmt.Errorf("save observation %s: %w", o.Check, err)
		}
		prev, err := p.st.GetBaseline(ctx, asset.ID, o.Check)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return out, fmt.Errorf("get baseline %s: %w", o.Check, err)
		}
		step := Step(prev, asset.ID, o.Check, o.Data, LearnParams{StableAfter: p.cfg.StableAfter, Ignore: p.ignoreFor(o.Check)}, now)
		if err := p.st.SaveBaseline(ctx, step.Baseline); err != nil {
			return out, fmt.Errorf("save baseline %s: %w", o.Check, err)
		}
		if step.Adopted {
			p.log.Info("finding: baseline adopted new stable value", "asset", asset.Key, "check", o.Check)
		}
		if _, seen := driftBy[o.Check]; !seen {
			driftOrder = append(driftOrder, o.Check)
		}
		driftBy[o.Check] = DriftFindings(o.Check, step.Drift)
	}

	// The check's own findings, then one reconcile per observed drift check.
	runs := []store.ReconcileInput{{AssetID: asset.ID, Check: checkName, Findings: p.applyIntel(res.Findings), ResolveAfter: p.cfg.ResolveAfter, Now: now, PartialRun: res.Partial}}
	for _, c := range driftOrder {
		runs = append(runs, store.ReconcileInput{AssetID: asset.ID, Check: DriftCheck(c), Findings: driftBy[c], ResolveAfter: p.cfg.ResolveAfter, Now: now})
	}
	for _, in := range runs {
		r, err := p.st.ReconcileFindings(ctx, in)
		if err != nil {
			return out, fmt.Errorf("reconcile %s: %w", in.Check, err)
		}
		out.Opened = append(out.Opened, r.Opened...)
		out.Reopened = append(out.Reopened, r.Reopened...)
		out.Updated = append(out.Updated, r.Updated...)
		out.Resolved = append(out.Resolved, r.Resolved...)
	}

	if err := p.applySuppressions(ctx, asset.ID, &out, now); err != nil {
		return out, err
	}
	return out, nil
}

// applySuppressions suppresses newly open findings that match YAML rules and
// lifts config suppressions that no longer match (rule removed or lapsed).
// Operator decisions are never overridden: only findings that are plainly
// open are suppressed, and only suppressions this package made (marked with
// ConfigNotePrefix) are lifted. Acknowledged and false-positive findings are
// not open, so they are left alone.
func (p *Processor) applySuppressions(ctx context.Context, assetID int64, r *store.ReconcileResult, now time.Time) error {
	for _, list := range []*[]model.Finding{&r.Opened, &r.Reopened, &r.Updated} {
		for i := range *list {
			f := &(*list)[i]
			if f.Status != model.StatusOpen {
				continue
			}
			reason, until, ok := p.sup.Match(*f, now)
			if !ok {
				continue
			}
			note := ConfigNotePrefix + reason
			err := p.st.ChangeFindingStatus(ctx, f.ID, store.StatusChange{Status: model.StatusSuppressed, Until: until, Note: note, Actor: ConfigActor}, now)
			if err != nil {
				return fmt.Errorf("suppress finding %d: %w", f.ID, err)
			}
			f.Status, f.SuppressedUntil, f.SuppressionNote = model.StatusSuppressed, until, note
		}
	}

	sup, _, err := p.st.ListFindings(ctx, store.FindingFilter{AssetID: assetID, Statuses: []model.FindingStatus{model.StatusSuppressed}})
	if err != nil {
		return fmt.Errorf("list suppressed: %w", err)
	}
	for _, f := range sup {
		if !ownedByConfig(f) {
			continue
		}
		if _, _, ok := p.sup.Match(f, now); ok {
			continue
		}
		if err := p.st.ChangeFindingStatus(ctx, f.ID, store.StatusChange{Status: model.StatusOpen, Actor: ConfigActor}, now); err != nil {
			return fmt.Errorf("lift suppression on finding %d: %w", f.ID, err)
		}
		p.log.Info("finding: config suppression lapsed, finding reopened", "finding", f.ID, "asset", f.AssetKey, "check", f.Check)
	}
	return nil
}
