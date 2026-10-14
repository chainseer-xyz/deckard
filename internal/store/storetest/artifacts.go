package storetest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// RunArtifacts checks the same artifact ingest contract against real and fake
// stores. An empty vulnerability list must still retain useful inventory.
func RunArtifacts(t *testing.T, factory Factory) {
	t.Run("clean inventory, replay and independent CVE lifecycle", func(t *testing.T) {
		ctx := context.Background()
		s := factory(t)
		digest := "sha256:" + strings.Repeat("a", 64)
		purl := "pkg:apk/alpine/openssl@3.5.1-r0"
		now := time.Date(2026, 10, 14, 1, 0, 0, 0, time.UTC)
		in := store.IngestInput{Tool: "trivy", Scope: digest, Check: model.IngestCheck("trivy"), Source: model.IngestSource("trivy"),
			AssetScope: model.ScopeExternal, ObservedAt: now, Now: now, Complete: true, ResolveAfter: 2, Digest: "first",
			Artifacts: []model.AssetInput{
				{Kind: model.KindContainerImage, Key: digest, Attrs: map[string]any{"digest": digest}},
				{Kind: model.KindPackage, Key: purl, Attrs: map[string]any{"purl": purl}},
			}, Relations: []model.RelationInput{{FromKind: model.KindContainerImage, FromKey: digest, ToKind: model.KindPackage, ToKey: purl, Type: model.RelContains}}}
		apply := func() store.IngestResult {
			t.Helper()
			result, err := s.IngestFindings(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			return result
		}
		apply()
		image, err := s.GetAssetByKey(ctx, model.KindContainerImage, digest)
		if err != nil || image.Scope != model.ScopeExternal || image.Attrs["digest"] != digest {
			t.Fatalf("image: %+v, %v", image, err)
		}
		edges, err := s.Edges(ctx, image.ID)
		if err != nil || len(edges) != 1 {
			t.Fatalf("edges: %+v, %v", edges, err)
		}
		if result := apply(); !result.Replay {
			t.Fatal("same artifact report was not a replay")
		}
		in.Digest, in.ObservedAt, in.Now = "with-cve", now.Add(time.Minute), now.Add(time.Minute)
		in.Items = []store.IngestItem{{Index: 0, AssetKind: model.KindContainerImage, AssetKey: digest, Finding: model.FindingInput{Key: "CVE-2026-0001", Title: "Vulnerable OpenSSL", Severity: model.SeverityHigh}}}
		if result := apply(); len(result.Opened) != 1 {
			t.Fatalf("CVE not opened: %+v", result)
		}
		// A clean SBOM is a separate producer; its empty findings prove nothing
		// about vulnerability coverage, even if a client sets Complete.
		in.Tool, in.Source, in.Check = "cyclonedx", model.IngestSource("cyclonedx"), model.IngestCheck("cyclonedx")
		in.Items, in.Digest = nil, "sbom"
		apply()
		findings, _, err := s.ListFindings(ctx, store.FindingFilter{Check: "ext.trivy"})
		if err != nil || len(findings) != 1 || findings[0].Status != model.StatusOpen || findings[0].MissedRuns != 0 {
			t.Fatalf("SBOM changed CVEs: %+v, %v", findings, err)
		}
		in.Artifacts, in.Relations, in.Digest = nil, nil, "empty-sbom"
		in.ObservedAt, in.Now = now.Add(2*time.Minute), now.Add(2*time.Minute)
		apply()
		if _, err := s.GetAssetByKey(ctx, model.KindPackage, purl); err != nil {
			t.Fatal("empty SBOM removed package", err)
		}
		edges, err = s.Edges(ctx, image.ID)
		if err != nil || len(edges) != 1 {
			t.Fatalf("empty SBOM removed immutable contents: %+v, %v", edges, err)
		}
	})
}
