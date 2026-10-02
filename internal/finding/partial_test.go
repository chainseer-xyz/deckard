package finding_test

import (
	"context"
	"encoding/json"
	"errors"
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

// A partial run proves presence, not absence — and drift findings encode
// absence. A partial port scan that simply did not cover a port must not
// resolve the "port added" drift finding a full scan opened.
func TestPartialRunCannotResolveDriftFinding(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	a := newAsset(t, st, "www.example.com")
	clk := &clock{epoch}
	p := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 1, StableAfter: 2}, quiet, finding.WithClock(clk.now))

	step := func(r *check.Result) store.ReconcileResult {
		t.Helper()
		clk.advance(time.Minute)
		out, err := p.Process(ctx, a, "net.ports", r)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	step(portRes(80)) // learning
	step(portRes(80)) // stable at {80}
	r := step(portRes(80, 8080))
	if len(r.Opened) != 1 {
		t.Fatalf("drift setup: opened %v, want the added-port drift", titles(r.Opened))
	}

	partial := portRes(80) // the partial scan did not cover 8080
	partial.Partial = true
	if r := step(partial); len(r.Resolved) != 0 {
		t.Fatalf("partial run resolved %v, want none", titles(r.Resolved))
	}
	open, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: a.ID, Statuses: []model.FindingStatus{model.StatusOpen}})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("open findings after partial run = %v, want the drift finding still open", titles(open))
	}
	if open[0].MissedRuns != 0 {
		t.Errorf("drift finding MissedRuns = %d after a partial run, want 0", open[0].MissedRuns)
	}
}

// Baselines encode absence, so observations from a partial run must neither
// seed, advance nor adopt them: two partial runs that each missed a port
// would otherwise make the shrunken set the new baseline and turn the port's
// return into a false "added" alert.
func TestPartialRunDoesNotAdvanceBaseline(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	a := newAsset(t, st, "www.example.com")
	clk := &clock{epoch}
	p := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 1, StableAfter: 2}, quiet, finding.WithClock(clk.now))

	step := func(r *check.Result) {
		t.Helper()
		clk.advance(time.Minute)
		if _, err := p.Process(ctx, a, "net.ports", r); err != nil {
			t.Fatal(err)
		}
	}

	// Seeding: a partial first observation must not create a baseline.
	first := portRes(80)
	first.Partial = true
	step(first)
	if _, err := st.GetBaseline(ctx, a.ID, "net.ports"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("baseline after partial first run: err = %v, want ErrNotFound", err)
	}

	step(portRes(80, 443))
	step(portRes(80, 443)) // stable at {80, 443}

	// Adoption: repeated identical partial observations must not become the
	// new baseline, however often they repeat.
	for i := 0; i < 3; i++ {
		shrunk := portRes(80)
		shrunk.Partial = true
		step(shrunk)
	}
	b, err := st.GetBaseline(ctx, a.ID, "net.ports")
	if err != nil {
		t.Fatal(err)
	}
	if !b.Stable {
		t.Fatalf("baseline no longer stable after partial runs: %+v", b)
	}
	// Normalize sorts set members by canonical JSON string, hence [443,80].
	got, _ := json.Marshal(b.Data["open_ports"])
	if string(got) != "[443,80]" {
		t.Fatalf("baseline open_ports = %s after partial runs, want [443,80]", got)
	}
}
