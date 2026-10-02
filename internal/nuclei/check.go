package nuclei

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const (
	// NameActive is the safe (non-intrusive) nuclei check.
	NameActive = "cve.nuclei"
	// NameIntrusive is the opt-in variant that lifts the intrusive exclusion.
	NameIntrusive = "nuclei.intrusive"
)

// ErrOutOfScope is returned when a target fails scope verification; the
// binary is never invoked in that case.
var ErrOutOfScope = errors.New("nuclei: target is not owned scope")

// ErrNoTemplates is returned when a template directory is managed (see
// WithTemplateDir) but holds no usable release yet, for example before the
// first template update succeeded. The binary is not run: an empty scan would
// otherwise be recorded as a clean one.
var ErrNoTemplates = errors.New("nuclei: no templates available yet")

type options struct {
	env         func() ([]string, func(), error)
	templateDir func() (string, error)
}

// Option customises Checks, New and NewScanner.
type Option func(*options)

// WithEnv supplies the per-run process environment for nuclei: extra KEY=VALUE
// pairs (HOME, XDG_*, NUCLEI_CONFIG_DIR, ...) overriding the minimal inherited
// set, and a cleanup called after the run. It is how a read-only root
// filesystem is made workable.
func WithEnv(f func() ([]string, func(), error)) Option { return func(o *options) { o.env = f } }

// WithTemplateDir makes the template directory dynamic (the template updater's
// current release). It overrides nuclei.templates_dir; an error means no
// templates yet and runs fail with ErrNoTemplates.
func WithTemplateDir(f func() (string, error)) Option { return func(o *options) { o.templateDir = f } }

func buildOptions(opts []Option) options {
	var o options
	for _, f := range opts {
		f(&o)
	}
	return o
}

// Checks returns cve.nuclei and nuclei.intrusive, or nothing when nuclei is
// disabled. defaults is the global per-check config map; Target.Config
// overlays it at run time. verify must be fail-closed.
func Checks(cfg config.NucleiConfig, defaults map[string]map[string]any, verify ScopeVerifier, opts ...Option) []check.Check {
	if !cfg.Enabled {
		return nil
	}
	r := ExecRunner{Env: buildOptions(opts).env}
	return []check.Check{
		New(cfg, verify, r, false, defaults[NameActive], opts...),
		New(cfg, verify, r, true, defaults[NameIntrusive], opts...),
	}
}

type nucleiCheck struct {
	cfg       config.NucleiConfig
	verify    ScopeVerifier
	runner    Runner
	intrusive bool
	defaults  map[string]any
	opts      options
	index     templateIndex
}

// New builds a nuclei check. A nil verify refuses every target.
func New(cfg config.NucleiConfig, verify ScopeVerifier, runner Runner, intrusive bool, defaults map[string]any, opts ...Option) check.Check {
	if cfg.Binary == "" {
		cfg.Binary = "nuclei"
	}
	return &nucleiCheck{cfg: cfg, verify: verify, runner: runner, intrusive: intrusive, defaults: defaults, opts: buildOptions(opts)}
}

func (c *nucleiCheck) Name() string {
	if c.intrusive {
		return NameIntrusive
	}
	return NameActive
}

func (c *nucleiCheck) Tier() model.Tier {
	if c.intrusive {
		return model.TierIntrusive
	}
	return model.TierActive
}

// WantsOpenFindings makes the engine pass Target.OpenFindings: a full scan
// re-runs the template behind every unresolved finding (see Run).
func (c *nucleiCheck) WantsOpenFindings() bool { return true }

func (c *nucleiCheck) Applies(a model.Asset) bool { return appliesTo(a) }

func (c *nucleiCheck) runOptions(t check.Target) (runOptions, time.Duration) {
	cfg := map[string]any{}
	for k, v := range c.defaults {
		cfg[k] = v
	}
	for k, v := range t.Config {
		cfg[k] = v
	}
	o := runOptions{
		cfg: c.cfg, intrusive: c.intrusive, lifted: []string{"intrusive"},
		rateLimit:   intOf(cfg["rate_limit"], 50),
		concurrency: intOf(cfg["concurrency"], 10),
		timeoutSec:  secondsOf(cfg["timeout"], 10),
		interactsh:  cfg["interactsh"] == true,
	}
	if l := stringsOf(cfg["lift_exclusions"]); l != nil {
		o.lifted = l
	}
	return o, time.Duration(secondsOf(cfg["run_timeout"], 600)) * time.Second
}

func (c *nucleiCheck) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	if !c.Applies(t.Asset) {
		return nil, fmt.Errorf("%w: asset %s (%s) not applicable", ErrOutOfScope, t.Asset.Key, t.Asset.Scope)
	}
	tg, err := buildTarget(t.Asset)
	if err != nil {
		return nil, err
	}
	if c.verify == nil || !c.verify(ctx, tg.host) {
		return nil, fmt.Errorf("%w: %s", ErrOutOfScope, tg.host)
	}
	opts, runTimeout := c.runOptions(t)
	if c.opts.templateDir != nil {
		dir, derr := c.opts.templateDir()
		if derr != nil {
			return nil, fmt.Errorf("%w: %w", ErrNoTemplates, derr)
		}
		opts.cfg.TemplatesDir = dir
	}
	args, err := buildArgs(tg, t.Asset, opts)
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	out, runErr := c.runner.Run(rctx, c.cfg.Binary, args)
	findings, perr := ParseJSONL(bytes.NewReader(out))
	if perr != nil {
		return nil, perr
	}
	if runErr != nil && len(findings) == 0 {
		return nil, runErr // no usable output: do not report a clean scan
	}
	// A run that died after matching cannot prove the rest absent.
	partial := runErr != nil

	// Re-verify unresolved findings by their own template. The tech selection
	// never runs a template that a targeted scan (new KEV CVE, brand-new
	// template) opened a finding with, so without this a still-vulnerable host
	// would stop matching, accrue misses and be wrongly resolved. Same target,
	// scope verification, rate limits and protocol restriction as above.
	plan, err := c.planReverify(tg, t, opts)
	if err != nil {
		return nil, err
	}
	if len(plan.Files) > 0 {
		ro := opts
		ro.explicit = plan.Files
		rargs, aerr := buildArgs(tg, t.Asset, ro)
		if aerr != nil {
			return nil, aerr
		}
		vctx, vcancel := context.WithTimeout(ctx, runTimeout)
		defer vcancel()
		vout, vErr := c.runner.Run(vctx, c.cfg.Binary, rargs)
		vf, verr := ParseJSONL(bytes.NewReader(vout))
		if verr != nil {
			return nil, verr
		}
		if vErr != nil && len(vf) == 0 {
			return nil, vErr // the verification did not run: no processing at all
		}
		partial = partial || vErr != nil
		seen := make(map[string]bool, len(findings))
		for _, f := range findings {
			seen[f.Key] = true
		}
		for _, f := range vf {
			if !seen[f.Key] {
				seen[f.Key] = true
				findings = append(findings, f)
			}
		}
	}
	for i := range findings {
		findings[i].Check = c.Name()
	}
	return &check.Result{
		Findings: findings,
		Partial:  partial || plan.Unverifiable,
		Observations: []model.ObservationInput{{Check: c.Name(), Data: map[string]any{
			"target": tg.arg, "matches": len(findings), "partial": runErr != nil,
		}}},
	}, nil
}

// planReverify works out the extra templates for the asset's unresolved
// findings. scan_mode all already runs every template and needs no plan.
func (c *nucleiCheck) planReverify(tg target, t check.Target, o runOptions) (reverifyPlan, error) {
	if o.cfg.ScanMode == "all" || len(t.OpenFindings) == 0 {
		return reverifyPlan{}, nil
	}
	root := ""
	if d := o.cfg.TemplatesDir; d != "" {
		root = resolveDir(d)
	}
	plan, err := c.index.planReverify(root, t.OpenFindings, o.tagsFor(t.Asset))
	if err != nil {
		return plan, fmt.Errorf("nuclei: index templates for re-verification: %w", err)
	}
	logMissingOnce(plan.Missing, tg.arg)
	return plan, nil
}

func intOf(v any, def int) int {
	switch n := v.(type) {
	case int:
		if n > 0 {
			return n
		}
	case int64:
		if n > 0 {
			return int(n)
		}
	case float64:
		if n > 0 {
			return int(n)
		}
	case string:
		if i, err := strconv.Atoi(n); err == nil && i > 0 {
			return i
		}
	}
	return def
}

// secondsOf accepts a duration string ("30s"), or a number of seconds.
func secondsOf(v any, def int) int {
	switch d := v.(type) {
	case time.Duration:
		if d > 0 {
			return int(d.Seconds())
		}
	case string:
		if x, err := time.ParseDuration(d); err == nil && x > 0 {
			return int(x.Seconds())
		}
	}
	return intOf(v, def)
}

func stringsOf(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		out := make([]string, 0, len(l))
		for _, e := range l {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}
