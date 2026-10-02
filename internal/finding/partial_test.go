package finding_test

import (
	"context"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// A delta run (check.Result.Partial) observes only some templates, so it must
// never resolve a finding the full scan opened, however low resolve_after is.
func TestPartialRunCannotResolveExistingFinding(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	a := newAsset(t, st, "www.example.com")
	clk := &clock{epoch}
	p := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 1, StableAfter: 2}, quiet, finding.WithClock(clk.now))
	full := func(fs ...model.FindingInput) store.ReconcileResult {
		t.Helper()
		clk.advance(time.Minute)
		r, err := p.Process(ctx, a, "cve.nuclei", &check.Result{Findings: fs})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	delta := func(fs ...model.FindingInput) store.ReconcileResult {
		t.Helper()
		clk.advance(time.Minute)
		r, err := p.Process(ctx, a, "cve.nuclei", &check.Result{Findings: fs, Partial: true})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	old := model.FindingInput{Key: "CVE-2024-0001", Severity: model.SeverityHigh, Title: "old"}
	fresh := model.FindingInput{Key: "CVE-2025-55182", Severity: model.SeverityCritical, Title: "fresh"}

	if r := full(old); len(r.Opened) != 1 {
		t.Fatalf("setup: %+v", titles(r.Opened))
	}
	for i := 0; i < 3; i++ {
		if r := delta(); len(r.Resolved) != 0 {
			t.Fatalf("delta run resolved %v", titles(r.Resolved))
		}
	}
	if r := delta(fresh); len(r.Opened) != 1 || len(r.Resolved) != 0 {
		t.Fatalf("delta with a hit: opened %v resolved %v", titles(r.Opened), titles(r.Resolved))
	}
	open, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: a.ID, Statuses: []model.FindingStatus{model.StatusOpen}})
	if err != nil || len(open) != 2 {
		t.Fatalf("open findings = %d err %v, want 2", len(open), err)
	}
	for _, f := range open {
		if f.MissedRuns != 0 {
			t.Errorf("%s MissedRuns = %d, want 0", f.Title, f.MissedRuns)
		}
	}
	// The next full scan (old fixed, fresh still present) resolves normally.
	if r := full(fresh); len(r.Resolved) != 1 || r.Resolved[0].Title != "old" {
		t.Fatalf("full run resolved %v, want old", titles(r.Resolved))
	}
}
