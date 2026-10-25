package finding_test

import (
	"context"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func ingestRun(clk *clock, digest string, complete bool, items ...store.IngestItem) store.IngestInput {
	return store.IngestInput{
		Tool: "prowler", Scope: "aws:123456789012:us-west-2", Check: "ext.prowler", Source: "ingest:prowler",
		AssetScope: model.ScopeExternal, Complete: complete, ObservedAt: clk.now(), Digest: digest, Items: items,
	}
}

func crItem(i int, fi model.FindingInput) store.IngestItem {
	return store.IngestItem{Index: i, AssetKind: model.KindCloudResource, AssetKey: "arn:aws:s3:::" + fi.Key, Finding: fi}
}

// Ingested findings go through the same suppression and intel rules as
// built-in checks, and the processor supplies resolve_after and the clock.
func TestProcessorIngestAppliesSuppressionsIntelAndResolveAfter(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	clk := &clock{epoch}
	intel := newFakeIntel()
	intel.addKEV("CVE-2021-44228")
	sups := []config.Suppression{{Match: `check=ext.prowler title="Bucket*"`, Reason: "accepted risk"}}
	p := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 2, StableAfter: 2, Suppressions: sups}, quiet,
		finding.WithClock(clk.now), finding.WithIntel(intel))

	bucket := model.FindingInput{Key: "bucket", Severity: model.SeverityHigh, Title: "Bucket is public"}
	cve := cveInput(model.SeverityLow)
	cve.Check = ""
	r, err := p.Ingest(ctx, ingestRun(clk, "1", true, crItem(0, bucket), crItem(1, cve)))
	if err != nil || len(r.Opened) != 2 {
		t.Fatalf("first run: %+v %v", r, err)
	}
	byTitle := map[string]model.Finding{}
	for _, f := range r.Opened {
		byTitle[f.Title] = f
	}
	if f := byTitle["Bucket is public"]; f.Status != model.StatusSuppressed || f.SuppressionNote != finding.ConfigNotePrefix+"accepted risk" {
		t.Fatalf("config suppression not applied: %+v", f)
	}
	if f := byTitle["Log4Shell"]; f.Severity != model.SeverityCritical || !contains(f.Tags, "kev") {
		t.Fatalf("intel not applied: %+v", f)
	}

	// The rule is removed: the next ingest lifts the config suppression.
	p2 := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 2, StableAfter: 2}, quiet, finding.WithClock(clk.now))
	clk.advance(time.Hour)
	if _, err := p2.Ingest(ctx, ingestRun(clk, "2", true, crItem(0, bucket), crItem(1, cve))); err != nil {
		t.Fatal(err)
	}
	if f, _ := st.GetFinding(ctx, byTitle["Bucket is public"].ID); f.Status != model.StatusOpen {
		t.Fatalf("lapsed config suppression kept: %s", f.Status)
	}

	// resolve_after = 2 comes from the processor: one complete miss is pending.
	clk.advance(time.Hour)
	r, err = p2.Ingest(ctx, ingestRun(clk, "3", true, crItem(1, cve)))
	if err != nil || r.Pending != 1 || len(r.Resolved) != 0 {
		t.Fatalf("one miss: pending %d resolved %d err %v", r.Pending, len(r.Resolved), err)
	}
	// A replay of that run changes nothing and skips suppression work.
	r, err = p2.Ingest(ctx, ingestRun(clk, "3", true, crItem(1, cve)))
	if err != nil || !r.Replay {
		t.Fatalf("replay: %+v %v", r, err)
	}
	clk.advance(time.Hour)
	r, err = p2.Ingest(ctx, ingestRun(clk, "4", true, crItem(1, cve)))
	if err != nil || len(r.Resolved) != 1 || r.Resolved[0].Title != "Bucket is public" {
		t.Fatalf("second miss: %+v %v", r, err)
	}
}

func TestProcessorIngestControlSuppressionPreservesStoredDecisions(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	clk := &clock{epoch}
	items := []store.IngestItem{
		crItem(0, model.FindingInput{Key: "cpu", Severity: model.SeverityHigh, Title: "CPU limits", Evidence: map[string]any{"control_id": "C-0270"}}),
		crItem(1, model.FindingInput{Key: "memory", Severity: model.SeverityHigh, Title: "Misleading title (C-0270)", Evidence: map[string]any{"control_id": "C-0271"}}),
		crItem(2, model.FindingInput{Key: "title-only", Severity: model.SeverityHigh, Title: "Title only (C-0270)"}),
		crItem(3, model.FindingInput{Key: "manual", Severity: model.SeverityHigh, Title: "Operator decision", Evidence: map[string]any{"control_id": "C-0270"}}),
	}
	for i := range items {
		items[i].AssetKey = "k8s://fixture/apps/v1/default/Deployment/control-fixture"
	}
	run := func(p *finding.Processor, digest string) store.IngestResult {
		t.Helper()
		clk.advance(time.Minute)
		result, err := p.Ingest(ctx, store.IngestInput{
			Tool: "kubescape", Scope: "k8s:fixture", Check: "ext.kubescape", Source: "ingest:kubescape",
			AssetScope: model.ScopeExternal, Complete: false, ObservedAt: clk.now(), Digest: digest, Items: items,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	plain := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 2}, quiet, finding.WithClock(clk.now))
	initial := run(plain, "before-rule")
	if len(initial.Opened) != 4 {
		t.Fatalf("expected four durable findings: %+v", initial)
	}
	byTitle := map[string]model.Finding{}
	for _, f := range initial.Opened {
		byTitle[f.Title] = f
	}
	manual := byTitle["Operator decision"]
	if err := st.ChangeFindingStatus(ctx, manual.ID, store.StatusChange{
		Status: model.StatusSuppressed, Note: "reviewed by operator", Actor: "alice",
	}, clk.now()); err != nil {
		t.Fatal(err)
	}
	until := clk.now().Add(24 * time.Hour)
	configured := finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 2, Suppressions: []config.Suppression{{
		Match: "check=ext.kubescape control_id=C-0270", Reason: "CPU limits intentionally omitted", Until: &until,
	}}}, quiet, finding.WithClock(clk.now))
	observed := run(configured, "fresh-observation")
	if len(observed.Resolved) != 0 || len(observed.Updated) != 3 {
		t.Fatalf("fresh additive observation must retain the existing records: %+v", observed)
	}
	for title, original := range byTitle {
		stored, err := st.GetFinding(ctx, original.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.ID != original.ID || stored.Fingerprint != original.Fingerprint || stored.ResolvedAt != nil {
			t.Fatalf("finding identity or lifecycle changed: %+v", stored)
		}
		switch title {
		case "CPU limits":
			if stored.Status != model.StatusSuppressed || stored.SuppressionNote != finding.ConfigNotePrefix+"CPU limits intentionally omitted" || stored.SuppressedUntil == nil || !stored.SuppressedUntil.Equal(until) || stored.Evidence["control_id"] != "C-0270" {
				t.Fatalf("structured suppression must preserve evidence and recorded reason/expiry: %+v", stored)
			}
		case "Operator decision":
			if stored.Status != model.StatusSuppressed || stored.SuppressionNote != "reviewed by operator" || stored.SuppressedUntil != nil {
				t.Fatalf("config must preserve the operator decision: %+v", stored)
			}
		default:
			if stored.Status != model.StatusOpen {
				t.Fatalf("wrong or absent control must stay open: %+v", stored)
			}
		}
	}
	run(plain, "rule-removed")
	for title, want := range map[string]model.FindingStatus{"CPU limits": model.StatusOpen, "Operator decision": model.StatusSuppressed} {
		stored, err := st.GetFinding(ctx, byTitle[title].ID)
		if err != nil || stored.Status != want {
			t.Fatalf("rule removal must distinguish config and manual decisions for %s: %+v %v", title, stored, err)
		}
	}
}
