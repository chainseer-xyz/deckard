package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/metrics"
)

const shutdownGrace = 30 * time.Second

func (a *App) hasRole(role string) bool { return slices.Contains(a.cfg.Server.Roles, role) }

// Serve runs the configured roles until ctx is cancelled or a component fails,
// then shuts down gracefully. It migrates the database first so a fresh
// deployment needs no separate step.
func (a *App) Serve(ctx context.Context) error {
	if err := a.Migrate(ctx); err != nil {
		return err
	}
	if err := a.api.Err(); err != nil {
		return fmt.Errorf("auth configuration: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mopts []metrics.Option
	if env := a.cfg.Server.MetricsTokenEnv; env != "" {
		tok := strings.TrimSpace(a.opts.Getenv(env))
		if tok == "" {
			return fmt.Errorf("server.metrics_token_env %q is set but the environment variable is empty", env)
		}
		mopts = append(mopts, metrics.WithToken(tok))
	}

	var wg sync.WaitGroup
	errc := make(chan error, 4)
	run := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}

	// Metrics are served by every role so workers can be scraped too.
	run("metrics", func(c context.Context) error {
		return metrics.Serve(c, a.cfg.Server.MetricsAddr, a.metrics.Registry(), mopts...)
	})
	if a.hasRole("api") {
		run("api", func(c context.Context) error {
			return a.api.ListenAndServe(c, a.cfg.Server.HTTPAddr)
		})
	}
	if a.hasRole("scheduler") || a.hasRole("worker") {
		// River treats a cancelled start context as stop-and-cancel, which would
		// abort in-flight jobs the moment shutdown begins. Start it detached and
		// drain it explicitly with eng.Stop and the shutdownGrace below.
		if err := a.eng.Start(context.WithoutCancel(ctx)); err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("engine: %w", err)
		}
	}
	if a.hasRole("scheduler") || a.hasRole("worker") {
		run("inventory-refresh", func(c context.Context) error {
			a.inv.RunRefresh(c, inventoryRefresh)
			return nil
		})
	}
	if a.hasRole("scheduler") || a.hasRole("worker") {
		// Every node that scans refreshes its own in-memory datasets: the
		// River job runs on whichever node picks it up, which would leave the
		// others on stale data.
		run("refdata-refresh", func(c context.Context) error {
			a.eng.RunRefdataLoop(c)
			return nil
		})
	}
	if a.hasRole("scheduler") {
		run("dispatcher", func(c context.Context) error {
			a.disp.Run(c)
			return nil
		})
	}

	a.log.Info("deckard started",
		"version", a.opts.Version, "roles", a.cfg.Server.Roles,
		"http", a.cfg.Server.HTTPAddr, "metrics", a.cfg.Server.MetricsAddr,
		"sources", len(a.sources))

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
		a.log.Error("component failed, shutting down", "error", runErr)
	}
	cancel()

	stopCtx, stop := context.WithTimeout(context.Background(), shutdownGrace)
	defer stop()
	if a.hasRole("scheduler") || a.hasRole("worker") {
		if err := a.eng.Stop(stopCtx); err != nil {
			a.log.Warn("engine stop", "error", err)
		}
	}
	wg.Wait()
	a.log.Info("deckard stopped")
	return runErr
}
