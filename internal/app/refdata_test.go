package app

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/metrics"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

func refdataApp(t *testing.T, mut func(*config.Config)) *App {
	t.Helper()
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Refdata.Dir = t.TempDir()
	mut(cfg)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	g, err := scope.NewGuard(cfg.Scope, scope.WithLogger(log))
	if err != nil {
		t.Fatal(err)
	}
	return &App{cfg: cfg, log: log, guard: g, metrics: metrics.New("test", "none"), opts: Options{Version: "test"}}
}

func TestBuildRefdataDisabledIsAirGapped(t *testing.T) {
	a := refdataApp(t, func(c *config.Config) { c.Refdata.Enabled = false })
	m, err := a.buildRefdata()
	if m != nil || err != nil {
		t.Fatalf("m=%v err=%v", m, err)
	}
}

func TestBuildRefdataInitialisesOfflineFromEmbedded(t *testing.T) {
	a := refdataApp(t, func(c *config.Config) {})
	m, err := a.buildRefdata()
	if err != nil || m == nil {
		t.Fatalf("m=%v err=%v", m, err)
	}
	if got := strings.Join(m.Names(), ","); got != "shared_ranges,takeover_fingerprints" {
		t.Errorf("datasets = %s", got)
	}
}

func TestBuildRefdataDatasetSelection(t *testing.T) {
	a := refdataApp(t, func(c *config.Config) { c.Refdata.Datasets.SharedRanges = false })
	m, err := a.buildRefdata()
	if err != nil || strings.Join(m.Names(), ",") != "takeover_fingerprints" {
		t.Fatalf("m=%v err=%v", m, err)
	}
}
