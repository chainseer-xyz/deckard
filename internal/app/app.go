// Package app is deckard's composition root: it builds every component from the
// configuration and runs them according to the configured roles.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/check"
	checkall "github.com/chainseer-xyz/deckard/internal/check/all"
	"github.com/chainseer-xyz/deckard/internal/check/exposed"
	netcheck "github.com/chainseer-xyz/deckard/internal/check/net"
	"github.com/chainseer-xyz/deckard/internal/check/tlsconfig"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/engine"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/inventory"
	"github.com/chainseer-xyz/deckard/internal/inventory/expand"
	"github.com/chainseer-xyz/deckard/internal/metrics"
	"github.com/chainseer-xyz/deckard/internal/notify"
	"github.com/chainseer-xyz/deckard/internal/notify/alertmanager"
	"github.com/chainseer-xyz/deckard/internal/notify/heartbeat"
	"github.com/chainseer-xyz/deckard/internal/nuclei"
	"github.com/chainseer-xyz/deckard/internal/plugin"
	"github.com/chainseer-xyz/deckard/internal/scope"
	"github.com/chainseer-xyz/deckard/internal/source"
	_ "github.com/chainseer-xyz/deckard/internal/source/all" // registers route53, gcpdns, aws and kubernetes
	"github.com/chainseer-xyz/deckard/internal/source/registry"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

// Options carries build-time information and test seams.
type Options struct {
	Version string
	Commit  string
	Getenv  func(string) string
	// ExtraChecks are appended to the built-in checks (test seam).
	ExtraChecks []check.Check
	// VulnintelOptions, when set, adjusts the exploit-intel service options
	// (feed URLs, HTTP client; test seam so tests never reach the internet).
	VulnintelOptions func(*vulnintel.Options)
}

// App owns the running components.
type App struct {
	cfg     *config.Config
	log     *slog.Logger
	opts    Options
	st      *postgres.Store
	pool    *pgxpool.Pool
	guard   *scope.Guard
	metrics *metrics.Metrics
	vuln    *vulnintel.Service
	inv     *inventory.Service
	proc    *finding.Processor
	disp    *finding.Dispatcher
	hb      *heartbeat.Pinger // nil unless notify.heartbeat.url is set
	eng     *engine.Engine
	api     *api.Server
	sources []source.Source
	nw      *nucleiWiring
}

// New connects to the database and builds every component. It does not
// migrate or start anything.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger, opts Options) (*App, error) {
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	if cfg.Database.URL == "" {
		return nil, errors.New("database.url is required (or DECKARD_DATABASE__URL)")
	}
	if err := finding.ValidateSuppressions(cfg.Suppressions); err != nil {
		return nil, fmt.Errorf("suppressions: %w", err)
	}

	a := &App{cfg: cfg, log: log, opts: opts}
	var err error
	if a.st, err = postgres.New(ctx, cfg.Database.URL, cfg.Database.MaxConns); err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	// One pool serves the store and the job queue; the store owns it.
	a.pool = a.st.Pool()
	if err := a.build(); err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

func (a *App) build() error {
	cfg := a.cfg
	a.metrics = metrics.New(a.opts.Version, a.opts.Commit)
	a.metrics.RegisterState(a.st, 15*time.Second)
	expected := map[string]time.Duration{}
	for tool, tc := range cfg.Ingest.Tools {
		if tc.ExpectedInterval > 0 {
			expected[tool] = tc.ExpectedInterval
		}
	}
	a.metrics.RegisterIngest(a.st, metrics.IngestOptions{
		Expected: expected, MaxScopesPerTool: cfg.Ingest.MaxScopesPerTool, TTL: 15 * time.Second, Logger: a.log,
	})
	g, err := scope.NewGuard(cfg.Scope, scope.WithLogger(a.log), scope.WithRefusalObserver(a.metrics.ScopeRefusal))
	if err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	a.guard = g

	for _, sc := range cfg.Sources {
		s, err := registry.Build(sc, cfg.Scope, a.opts.Getenv, a.log)
		if err != nil {
			return fmt.Errorf("source %q: %w", sc.Name, err)
		}
		a.sources = append(a.sources, s)
	}

	a.inv = inventory.New(a.st, g, a.log)
	procIntel, engIntel, err := a.buildVulnintel()
	if err != nil {
		return fmt.Errorf("vulnintel: %w", err)
	}
	a.proc = finding.NewProcessor(a.st, finding.ProcessorConfig{
		ResolveAfter: cfg.Findings.ResolveAfter,
		StableAfter:  cfg.Learning.StableAfter,
		Suppressions: cfg.Suppressions,
		IgnoreKeys:   cfg.Learning.IgnoreKeys,
	}, a.log, procIntel...)

	notifiers, err := a.notifiers()
	if err != nil {
		return err
	}
	// The dispatcher also evaluates the configured suppressions before
	// notifying (defence in depth against the reconcile-then-suppress window).
	a.disp = finding.NewDispatcher(a.st, notifiers, cfg.Notify.Alertmanager.Resend, a.log,
		finding.WithSuppressions(cfg.Suppressions))

	if hc := cfg.Notify.Heartbeat; hc.Enabled() {
		a.hb, err = heartbeat.New(hc, a.st, a.log,
			heartbeat.WithRecorder(a.metrics.HeartbeatResult),
			heartbeat.WithUserAgent("deckard/"+a.opts.Version))
		if err != nil {
			return err
		}
		a.metrics.InitHeartbeat(heartbeat.ResultOK, heartbeat.ResultError, heartbeat.ResultUnhealthy)
	}

	expander, err := a.expander()
	if err != nil {
		return err
	}
	rd, err := a.buildRefdata()
	if err != nil {
		return err
	}
	var refresher engine.Refresher // stays a nil interface when disabled
	if rd != nil {
		refresher = rd
	}
	if nw := a.nuclei(); nw.upd != nil {
		a.checkUpdateDir(nw.cfg.Update.Dir) // startup only: never from tests that just build checks
	}
	ic, err := a.buildIntel()
	if err != nil {
		return fmt.Errorf("intel: %w", err)
	}
	templates, delta := a.engineTemplates()
	a.eng, err = engine.New(engine.Deps{
		Refdata:   refresher,
		Config:    *cfg,
		Store:     a.st,
		Guard:     g,
		Inventory: a.inv,
		Findings:  a.proc,
		Recorder:  a.metrics,
		Checks:    a.checks(),
		Sources:   a.sources,
		Pool:      a.pool,
		Logger:    a.log,
		Expander:  expander,
		Templates: templates,
		Delta:     delta,
		Intel:     ic,
		Lookup:    a.buildLookup(),
	}, append([]engine.Option{engine.WithRoles(cfg.Server.Roles...), engine.WithQueueWorkers(queueWorkers(cfg))}, engIntel...)...)
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}

	a.api = api.New(api.Deps{
		Store:       a.st,
		Auth:        cfg.Auth,
		AuthOptions: auth.Options{Getenv: a.opts.Getenv, Logger: a.log},
		BaseURL:     cfg.Server.BaseURL,
		Actions:     engineActions{a.eng},
		Logger:      a.log,
		Registry:    a.metrics.Registry(),
		Broadcaster: api.NewBroadcaster(),
		Ingester:    a.proc,
		Ingest:      cfg.Ingest,
	})
	return nil
}

func (a *App) notifiers() ([]notify.Notifier, error) {
	var out []notify.Notifier
	am := a.cfg.Notify.Alertmanager
	if len(am.URLs) == 0 {
		a.log.Warn("no notifier configured: findings are stored and shown in the UI but no alerts are sent; set notify.alertmanager.urls")
		return out, nil
	}
	n, err := alertmanager.New(am, a.opts.Getenv, a.log, alertmanager.WithBaseURL(a.cfg.Server.BaseURL))
	if err != nil {
		return nil, fmt.Errorf("alertmanager: %w", err)
	}
	return append(out, n), nil
}

// checks assembles every built-in check plus nuclei and exec plugins. Checks
// that start their own network connections (nuclei, plugins) only ever receive
// targets the guard classifies as owned.
func (a *App) checks() []check.Check {
	verify := a.guard.VerifyOwnedTarget
	cs := checkall.Checks(a.cfg.Checks) // passive tier
	cs = append(cs, netcheck.Checks(a.cfg.Checks)...)
	cs = append(cs, tlsconfig.Checks(a.cfg.Checks)...)
	cs = append(cs, exposed.Checks(a.cfg.Checks)...)
	nw := a.nuclei()
	cs = append(cs, nuclei.Checks(nw.cfg, a.cfg.Checks, nuclei.ScopeVerifier(verify), nw.opts...)...)
	cs = append(cs, plugin.Checks(a.cfg.Plugins, plugin.ScopeVerifier(verify))...)
	return append(cs, a.opts.ExtraChecks...)
}

// Migrate applies the application and job-queue schemas and then rebuilds the
// scope classifier's owned zones/prefixes from the database (C11), so a
// process that has not synced yet (restart, worker-only replica, one-shot
// scan) still knows what the operator's sources declared. Every entry point
// that may start scanning goes through Migrate first.
func (a *App) Migrate(ctx context.Context) error {
	if err := a.st.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate store: %w", err)
	}
	if err := engine.Migrate(ctx, a.pool); err != nil {
		return fmt.Errorf("migrate job queue: %w", err)
	}
	if err := a.inv.Rehydrate(ctx); err != nil {
		return fmt.Errorf("rehydrate classifier: %w", err)
	}
	return nil
}

// inventoryRefresh is how often scanning roles re-read the classifier state
// from the database, so replicas that did not sync follow dropped zones.
const inventoryRefresh = 5 * time.Minute

// Close releases database resources. The pool belongs to the store, so
// closing the store closes it.
func (a *App) Close() {
	if a.st != nil {
		a.st.Close()
	}
}

// queueWorkers maps scheduling.queue_workers onto the engine's queue names.
func queueWorkers(cfg *config.Config) map[string]int {
	out := map[string]int{}
	for _, q := range []string{engine.QueueSync, engine.QueuePassive, engine.QueueActive,
		engine.QueueIntrusive, engine.QueueDefault, engine.QueueExpand, engine.QueueIntel, engine.QueueMaintenance} {
		if n, ok := cfg.Scheduling.QueueWorkers[q]; ok {
			out[q] = n
		}
	}
	return out
}

// Engine exposes the engine for one-shot commands and tests.
// expander builds the discovery expander (crt.sh + DNS bruteforce), or nil
// when both are disabled so nothing is ever scheduled.
func (a *App) expander() (engine.Expander, error) {
	x := a.cfg.Expansion
	if !x.CTLogs && !x.DNSBruteforce {
		return nil, nil
	}
	e := &engine.DefaultExpander{}
	if x.CTLogs {
		e.CT = engine.NewCT("deckard/" + a.opts.Version + " (defensive attack-surface monitor; queries only the operator's own zones)")
	}
	if x.DNSBruteforce {
		words, err := expand.LoadWordlist(x.Wordlist)
		if err != nil {
			return nil, fmt.Errorf("expansion: %w", err)
		}
		e.Words = words
	}
	return e, nil
}

func (a *App) Engine() *engine.Engine { return a.eng }

// Dispatcher exposes the notification dispatcher for one-shot commands.
func (a *App) Dispatcher() *finding.Dispatcher { return a.disp }

// Inventory exposes the inventory service for one-shot commands.
func (a *App) Inventory() *inventory.Service { return a.inv }

// Sources returns the configured sources.
func (a *App) Sources() []source.Source { return a.sources }

// Stats returns the current inventory and findings summary.
func (a *App) Stats(ctx context.Context) (store.Stats, error) { return a.st.Stats(ctx) }
