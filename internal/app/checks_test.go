package app

import (
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

// Every check documented in the spec must be wired into the composition root;
// a package that exists but is not registered silently never runs.
func TestAllDocumentedChecksAreRegistered(t *testing.T) {
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Refdata.Enabled = false // hermetic: tests never reach the public dataset sources
	g, err := scope.NewGuard(cfg.Scope, scope.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Nuclei.Binary = os.Args[0] // any executable on disk: the check registers only when the binary exists
	a := &App{cfg: cfg, guard: g, log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	byName := map[string]model.Tier{}
	for _, c := range a.checks() {
		if _, dup := byName[c.Name()]; dup {
			t.Errorf("check %q registered twice", c.Name())
		}
		byName[c.Name()] = c.Tier()
	}

	want := map[string]model.Tier{
		"dns.dangling":       model.TierPassive,
		"dns.takeover":       model.TierPassive,
		"dns.hygiene":        model.TierPassive,
		"tls.cert":           model.TierPassive,
		"http.probe":         model.TierPassive,
		"http.headers":       model.TierPassive,
		"origin.exposed":     model.TierPassive,
		"origin.correlation": model.TierPassive,
		"domain.lookalike":   model.TierPassive,
		"net.ports":          model.TierActive,
		"net.services":       model.TierActive,
		"tls.config":         model.TierActive,
		"http.exposed":       model.TierActive,
		"cve.nuclei":         model.TierActive,
	}
	for name, tier := range want {
		got, ok := byName[name]
		if !ok {
			t.Errorf("check %q is not registered", name)
			continue
		}
		if got != tier {
			t.Errorf("check %q has tier %s, want %s", name, got, tier)
		}
	}
}

// The slim image has no nuclei binary: the app must skip cve.nuclei with a
// warning instead of registering a check that fails on every scan.
func TestMissingNucleiBinaryDisablesOnlyThatCheck(t *testing.T) {
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Refdata.Enabled = false // hermetic: tests never reach the public dataset sources
	cfg.Nuclei.Binary = "definitely-not-an-installed-binary-xyz"
	g, err := scope.NewGuard(cfg.Scope, scope.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: cfg, guard: g, log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	names := map[string]bool{}
	for _, c := range a.checks() {
		names[c.Name()] = true
	}
	if names["cve.nuclei"] {
		t.Error("cve.nuclei must not be registered when the nuclei binary is missing")
	}
	if !names["net.ports"] || !names["dns.dangling"] {
		t.Error("other checks must be unaffected by a missing nuclei binary")
	}
}
