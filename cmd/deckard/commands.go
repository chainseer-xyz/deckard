package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/chainseer-xyz/deckard/internal/app"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/engine"
	"github.com/chainseer-xyz/deckard/internal/logging"
)

// commonFlagsWith parses --config, loads the configuration and registers any
// extra flags the command needs.
func commonFlagsWith(name string, args []string, stderr io.Writer, extra func(*flag.FlagSet)) (*config.Config, int) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", os.Getenv("DECKARD_CONFIG"), "YAML config file")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, 2
	}
	cfg, err := config.Load(*path, os.Environ())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return nil, 1
	}
	return cfg, 0
}

// withApp loads config, builds the app and runs fn with a signal-aware context.
func withApp(name string, args []string, stdout, stderr io.Writer, fn func(context.Context, *app.App, io.Writer) error) int {
	return withAppFlags(name, args, nil, stdout, stderr, fn)
}

// withAppFlags is withApp with extra command flags.
func withAppFlags(name string, args []string, extra func(*flag.FlagSet), stdout, stderr io.Writer, fn func(context.Context, *app.App, io.Writer) error) int {
	cfg, code := commonFlagsWith(name, args, stderr, extra)
	if cfg == nil {
		return code
	}
	log := logging.New(cfg.Log, stdout)
	// Libraries (River's migrator, the stdlib log package) write through the
	// default logger; make it the same JSON handler so stdout is uniformly JSON.
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, cfg, log, app.Options{Version: version, Commit: commit})
	if err != nil {
		log.Error("startup failed", "error", err)
		_, _ = fmt.Fprintln(stderr, "deckard:", err)
		return 1
	}
	defer a.Close()
	if err := fn(ctx, a, stdout); err != nil {
		log.Error(name+" failed", "error", err)
		_, _ = fmt.Fprintln(stderr, "deckard:", err)
		return 1
	}
	return 0
}

func runServe(args []string, stdout, stderr io.Writer) int {
	return withApp("serve", args, stdout, stderr, func(ctx context.Context, a *app.App, _ io.Writer) error {
		return a.Serve(ctx)
	})
}

func runMigrate(args []string, stdout, stderr io.Writer) int {
	return withApp("migrate", args, stdout, stderr, func(ctx context.Context, a *app.App, out io.Writer) error {
		if err := a.Migrate(ctx); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(out, "migrations applied")
		return nil
	})
}

// runSync performs one inventory sync of every source and prints a summary.
func runSync(args []string, stdout, stderr io.Writer) int {
	return withApp("sync", args, stdout, stderr, func(ctx context.Context, a *app.App, out io.Writer) error {
		if err := a.Migrate(ctx); err != nil {
			return err
		}
		var failed int
		for _, src := range a.Sources() {
			d, err := a.Inventory().Sync(ctx, src)
			if err != nil {
				failed++
				_, _ = fmt.Fprintf(out, "%s: FAILED: %v\n", src.Name(), err)
				continue
			}
			_, _ = fmt.Fprintf(out, "%s: added=%d changed=%d removed=%d revived=%d\n",
				src.Name(), len(d.Added), len(d.Changed), len(d.Removed), len(d.Revived))
		}
		if failed > 0 {
			return fmt.Errorf("%d of %d sources failed", failed, len(a.Sources()))
		}
		return nil
	})
}

// runScan syncs, scans every due asset once, sends notifications and prints
// stats. Unless --no-update is given it first refreshes the nuclei templates
// (when nuclei.update is enabled) and the reference data (takeover
// fingerprints, shared ranges), so a one-off scan also uses fresh data; a
// failed refresh falls back to the last good or embedded copy. Use --no-update
// on an air-gapped host.
func runScan(args []string, stdout, stderr io.Writer) int {
	var noUpdate bool
	extra := func(fs *flag.FlagSet) {
		fs.BoolVar(&noUpdate, "no-update", false, "skip the nuclei template update and reference data refresh that run before the scan")
	}
	return withAppFlags("scan", args, extra, stdout, stderr, func(ctx context.Context, a *app.App, out io.Writer) error {
		if noUpdate {
			a.DisableRefdataUpdate()
		}
		if err := a.Migrate(ctx); err != nil {
			return err
		}
		if err := a.Engine().RunOnceWith(ctx, engine.RunOnceOptions{SkipTemplateUpdate: noUpdate}); err != nil {
			return err
		}
		if err := a.Dispatcher().Flush(ctx); err != nil {
			_, _ = fmt.Fprintln(stderr, "deckard: notify:", err)
		}
		st, err := a.Stats(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(st)
	})
}
