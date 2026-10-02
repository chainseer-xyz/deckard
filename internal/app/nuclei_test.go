package app

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/metrics"
	"github.com/chainseer-xyz/deckard/internal/nuclei/fakenuclei"
	"github.com/chainseer-xyz/deckard/internal/nuclei/updater"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

func nucleiApp(t *testing.T, mut func(*config.Config)) (*App, *bytes.Buffer) {
	t.Helper()
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	bin := fakenuclei.Install(t, fakenuclei.Conf{})
	cfg.Nuclei.Binary = bin.Path
	cfg.Nuclei.Update.Dir = filepath.Join(t.TempDir(), "nt")
	cfg.Nuclei.TemplatesDir = "" // re-derive below
	if mut != nil {
		mut(cfg)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	g, err := scope.NewGuard(cfg.Scope, scope.WithLogger(log))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Nuclei.TemplatesDir == "" && cfg.Nuclei.Update.Enabled {
		cfg.Nuclei.TemplatesDir = cfg.Nuclei.UpdateCurrentDir()
	}
	return &App{cfg: cfg, guard: g, log: log, metrics: metrics.New("test", "x")}, &logs
}

func TestNucleiWiringDefaultUsesTheUpdater(t *testing.T) {
	a, _ := nucleiApp(t, nil)
	nw := a.nuclei()
	if nw.upd == nil || nw.scanner == nil || len(nw.opts) != 2 || nw.env == nil || !nw.cfg.Enabled {
		t.Fatalf("wiring = %+v", nw)
	}
	tm, ds := a.engineTemplates()
	if tm == nil || ds == nil {
		t.Fatal("engine must receive the updater and the scanner")
	}
	if a.nuclei() != nw {
		t.Error("wiring must be built once")
	}
	names := map[string]bool{}
	for _, c := range a.checks() {
		names[c.Name()] = true
	}
	if !names["cve.nuclei"] {
		t.Error("cve.nuclei not registered")
	}
}

func TestNucleiWiringOptOutAndCustomTemplates(t *testing.T) {
	// Air-gapped: updater off, operator-mounted templates; scans still work.
	a, _ := nucleiApp(t, func(c *config.Config) {
		c.Nuclei.Update.Enabled = false
		c.Nuclei.TemplatesDir = "/mnt/templates"
	})
	nw := a.nuclei()
	if nw.upd != nil || nw.scanner == nil || nw.opts != nil || nw.cfg.TemplatesDir != "/mnt/templates" {
		t.Fatalf("opt-out wiring = %+v", nw)
	}
	if tm, ds := a.engineTemplates(); tm != nil || ds == nil {
		t.Errorf("engine collaborators: templates=%v scanner=%v", tm, ds)
	}

	// Updater enabled but templates_dir pointed elsewhere: the updater would
	// update a directory nothing reads, so it is switched off, loudly.
	a, logs := nucleiApp(t, func(c *config.Config) { c.Nuclei.TemplatesDir = "/mnt/templates" })
	nw = a.nuclei()
	if nw.upd != nil || nw.cfg.Update.Enabled || nw.scanner == nil {
		t.Fatalf("custom templates_dir wiring = %+v", nw)
	}
	if !strings.Contains(logs.String(), "template updater is not used") {
		t.Errorf("no warning logged: %s", logs.String())
	}
}

func TestNucleiWiringDisabledOrMissingBinary(t *testing.T) {
	a, _ := nucleiApp(t, func(c *config.Config) { c.Nuclei.Enabled = false })
	if nw := a.nuclei(); nw.upd != nil || nw.scanner != nil {
		t.Errorf("nuclei disabled: %+v", nw)
	}
	if tm, ds := a.engineTemplates(); tm != nil || ds != nil {
		t.Error("nothing to hand the engine when nuclei is disabled")
	}
	a, logs := nucleiApp(t, func(c *config.Config) { c.Nuclei.Binary = "definitely-not-an-installed-binary-xyz" })
	if nw := a.nuclei(); nw.upd != nil || nw.scanner != nil || nw.cfg.Enabled {
		t.Errorf("missing binary: %+v", nw)
	}
	if !strings.Contains(logs.String(), "binary not found") {
		t.Errorf("no warning: %s", logs.String())
	}
}

// The template age gauge is correct straight after a restart: the persisted
// updater state seeds the metrics at startup.
func TestNucleiWiringSeedsTemplateMetricsFromState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nt")
	bin := fakenuclei.Install(t, fakenuclei.Conf{})
	tree := t.TempDir()
	fakenuclei.WriteTree(t, tree, fakenuclei.BulkTemplates(30)...)
	bin.Set(func(c *fakenuclei.Conf) { c.Tree, c.Version = tree, "v7" })
	u, err := updater.New(updater.Config{Dir: dir, Binary: bin.Path, MinTemplates: 20, MinHTTPTemplates: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	a, _ := nucleiApp(t, func(c *config.Config) {
		c.Nuclei.Binary = bin.Path
		c.Nuclei.Update.Dir = dir
	})
	a.nuclei()
	fams, err := a.metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, f := range fams {
		if strings.HasPrefix(f.GetName(), "deckard_nuclei_template") {
			for _, m := range f.GetMetric() {
				if m.GetGauge() != nil {
					got[f.GetName()] = m.GetGauge().GetValue()
				}
			}
		}
	}
	if got["deckard_nuclei_template_count"] != 30 {
		t.Errorf("template count gauge = %v, want 30 (%v)", got["deckard_nuclei_template_count"], got)
	}
	if age, ok := got["deckard_nuclei_templates_age_seconds"]; !ok || age < 0 || age > float64(time.Hour/time.Second) {
		t.Errorf("age gauge = %v ok=%v", age, ok)
	}
}
