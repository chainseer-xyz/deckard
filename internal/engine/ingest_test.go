package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

// TestIngestedAssetsAreNeverProbed is the ingest safety invariant: an asset
// created by the ingest API is never scheduled, rescanned or scanned, even
// when it is labelled owned (an allow-listed tool), every tier is enabled, a
// check (say an exec plugin with applies.kind: cloud_resource) applies to it,
// and the guard would classify its key as owned.
func TestIngestedAssetsAreNeverProbed(t *testing.T) {
	ingested := model.Asset{ID: 1, Kind: model.KindCloudResource, Key: "arn:aws:s3:::example", Source: model.IngestSource("prowler"), Scope: model.ScopeOwned}
	// A hostname too: the scheduler must not care about the kind.
	ingestedHost := model.Asset{ID: 2, Kind: model.KindHostname, Key: "www.example.com", Source: model.IngestSource("prowler"), Scope: model.ScopeOwned}
	checks := []*fakeCheck{
		{name: "plugin.passive", tier: model.TierPassive},
		{name: "plugin.active", tier: model.TierActive},
		{name: "plugin.intrusive", tier: model.TierIntrusive},
	}
	h := newHarness(func(c *testCfg) { c.Profiles.Intrusive.Enabled = true },
		[]model.Asset{ingested, ingestedHost}, checks[0], checks[1], checks[2])
	// fakeGuard classifies every key as owned: only the source can refuse.
	ctx := context.Background()

	for _, tier := range allTiers {
		if n, err := h.r.scheduleTier(ctx, tier); err != nil || n != 0 {
			t.Fatalf("scheduleTier(%s) queued %d (err %v), want 0", tier, n, err)
		}
	}
	if keys := h.q.keys(); len(keys) != 0 {
		t.Fatalf("queued scans for ingested assets: %v", keys)
	}

	e := &Engine{d: h.r.Deps, r: h.r}
	for _, a := range []model.Asset{ingested, ingestedHost} {
		if err := e.RescanAsset(ctx, a.ID); !errors.Is(err, ErrNotScannable) {
			t.Fatalf("RescanAsset(%s) = %v, want ErrNotScannable", a.Key, err)
		}
		// A job that reached a worker anyway (enqueued before the asset was
		// ingested, or forged) is refused before any check runs.
		for _, tier := range allTiers {
			if err := h.r.runScan(ctx, scanJob{AssetID: a.ID, Tier: tier}); err != nil {
				t.Fatalf("runScan: %v", err)
			}
		}
	}
	if keys := h.q.keys(); len(keys) != 0 {
		t.Fatalf("rescan queued scans: %v", keys)
	}
	for _, c := range checks {
		if n := c.calls.Load(); n != 0 {
			t.Fatalf("%s ran %d times against an ingested asset", c.name, n)
		}
	}
	if n := h.g.built.Load(); n != 0 {
		t.Fatalf("%d network handles built for ingested assets", n)
	}
	if len(h.proc.calls) != 0 {
		t.Fatal("findings processed for an ingested asset")
	}
	runs := h.st.runs()
	if len(runs) != 6 {
		t.Fatalf("want 6 skipped runs (2 assets x 3 tiers), got %d", len(runs))
	}
	for _, r := range runs {
		if !strings.HasPrefix(r.Error, SkippedPrefix+"ingested asset") {
			t.Fatalf("run not skipped as ingested: %+v", r)
		}
	}

	// The same assets from a regular source are scheduled, so the refusal
	// above is the source rule and not a broken harness.
	plain := ingested
	plain.Source = "aws"
	h2 := newHarness(nil, []model.Asset{plain}, checks[0])
	if n, _ := h2.r.scheduleTier(ctx, model.TierPassive); n != 1 {
		t.Fatalf("control: queued %d, want 1", n)
	}
}

// The real guard never classifies a cloud resource as owned, whatever the
// scope config says, so even without the source rule no tier may probe the
// only kind ingest creates.
func TestCloudResourcesAreNeverProbableByTheGuard(t *testing.T) {
	g, err := scope.NewGuard(config.ScopeConfig{Include: []string{"*.example.com", "example.com", "203.0.113.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"arn:aws:s3:::example", "www.example.com", "203.0.113.7", "github.com/example/repo"} {
		cls := g.Classify(model.KindCloudResource, key)
		for _, tier := range allTiers {
			if scope.AllowedFor(model.KindCloudResource, tier, cls) {
				t.Errorf("cloud_resource %q (class %s) is probable at tier %s", key, cls, tier)
			}
		}
	}
}
