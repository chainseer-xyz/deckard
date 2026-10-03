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
