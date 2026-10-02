package app_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/app"
	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// slowCheck is a passive check that is deliberately slow and ignores ctx, so
// it only ever finishes if the engine lets in-flight jobs drain (C7).
type slowCheck struct {
	started  chan struct{}
	hold     time.Duration
	finished atomic.Bool
}

func (c *slowCheck) Name() string               { return "test.slow" }
func (c *slowCheck) Tier() model.Tier           { return model.TierPassive }
func (c *slowCheck) Applies(a model.Asset) bool { return a.Kind == model.KindIP }
func (c *slowCheck) Run(context.Context, check.Target) (*check.Result, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	time.Sleep(c.hold)
	c.finished.Store(true)
	return &check.Result{}, nil
}

// TestServeShutdownLetsInFlightScanFinish: cancelling Serve's context must not
// cancel running jobs; Engine.Stop gets the 30s grace to drain them.
func TestServeShutdownLetsInFlightScanFinish(t *testing.T) {
	cfg := testConfig(t, "", 1)
	slow := &slowCheck{started: make(chan struct{}, 1), hold: 2 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a := newApp(t, ctx, cfg, app.Options{ExtraChecks: []check.Check{slow}})

	sctx, stopServe := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- a.Serve(sctx) }()

	select {
	case <-slow.started:
	case err := <-done:
		t.Fatalf("Serve returned early: %v", err)
	case <-time.After(60 * time.Second):
		t.Fatal("slow check never started")
	}
	stopServe() // shutdown begins while the check is mid-run

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("Serve did not return")
	}
	if !slow.finished.Load() {
		t.Fatal("in-flight check was abandoned: Serve returned before it finished")
	}
	runs, err := openDB(t, ctx, cfg.Database.URL).ListScans(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range runs {
		if r.Check == "test.slow" {
			if r.Error != "" {
				t.Fatalf("in-flight scan was cancelled by shutdown: %q", r.Error)
			}
			return
		}
	}
	t.Fatalf("no scan run recorded for the in-flight check: %+v", runs)
}
