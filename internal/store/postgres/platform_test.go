package postgres_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestExactARNCorrelationPreservesLifecycle(t *testing.T) {
	for _, scannerFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "inventory first", true: "scanner first"}[scannerFirst], func(t *testing.T) {
			s := newMigratedStore(t)
			ctx := context.Background()
			now := time.Date(2026, 10, 14, 1, 0, 0, 0, time.UTC)
			arn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/example/123"
			key := "aws:elbv2:us-east-1:example"
			asset := store.AssetUpsert{AssetInput: model.AssetInput{Kind: model.KindCloudResource, Key: key, Source: "aws", Attrs: map[string]any{"arn": arn, "aws.account": "123456789012", "aws.region": "us-east-1"}}, Scope: model.ScopeExternal}
			in := ingestInput("aws:123456789012:us-east-1", now, true, "a")
			in.Items[0].AssetKey = arn
			applyInventory := func() {
				t.Helper()
				if _, err := s.ApplySnapshot(ctx, "aws", []store.AssetUpsert{asset}, nil, now); err != nil {
					t.Fatal(err)
				}
			}
			if !scannerFirst {
				applyInventory()
			}
			result, err := s.IngestFindings(ctx, in)
			if err != nil || len(result.Opened) != 1 {
				t.Fatalf("ingest: %+v %v", result, err)
			}
			findingID := result.Opened[0].ID
			if scannerFirst {
				applyInventory()
				in.Digest, in.ObservedAt, in.Now = "next", now.Add(time.Minute), now.Add(time.Minute)
				if _, err := s.IngestFindings(ctx, in); err != nil {
					t.Fatal(err)
				}
			}
			native, err := s.GetAssetByKey(ctx, model.KindCloudResource, key)
			if err != nil {
				t.Fatal(err)
			}
			findings, _, err := s.ListFindings(ctx, store.FindingFilter{Check: "ext.prowler"})
			if err != nil || len(findings) != 1 || findings[0].ID != findingID || findings[0].AssetID != native.ID || findings[0].Status != model.StatusOpen {
				t.Fatalf("correlation lost lifecycle: %+v %v", findings, err)
			}
			applyInventory()
			findings, _, _ = s.ListFindings(ctx, store.FindingFilter{Check: "ext.prowler"})
			if findings[0].Status != model.StatusOpen {
				t.Fatal("inventory scope healed metadata finding")
			}
			if native.Scope != model.ScopeExternal || native.Source != "aws" || native.Attrs["arn"] != arn {
				t.Fatal("correlation changed authority", native)
			}
			if scannerFirst {
				legacy, _ := s.GetAssetByKey(ctx, model.KindCloudResource, arn)
				edges, err := s.Edges(ctx, legacy.ID)
				if err != nil || len(edges) != 1 || edges[0].Type != model.RelAliasTo || edges[0].Other.ID != native.ID {
					t.Fatalf("missing legacy identity link: %+v %v", edges, err)
				}
			}
		})
	}
}

func TestARNCorrelationRefusesAmbiguityAndContradictions(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(map[bool]string{false: "contradictory account", true: "multiple authoritative IDs"}[ambiguous], func(t *testing.T) {
			ctx := context.Background()
			s := newMigratedStore(t)
			now := time.Now().UTC()
			arn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/example/123"
			assets := []store.AssetUpsert{{AssetInput: model.AssetInput{Kind: model.KindCloudResource, Key: "native:first", Attrs: map[string]any{"arn": arn}}, Scope: model.ScopeExternal}}
			if ambiguous {
				second := assets[0]
				second.Key = "native:second"
				assets = append(assets, second)
			}
			if _, err := s.ApplySnapshot(ctx, "aws", assets, nil, now); err != nil {
				t.Fatal(err)
			}
			in := ingestInput("account", now, true, "a")
			in.Items[0].AssetKey = arn
			if !ambiguous {
				in.Items[0].Finding.Evidence = map[string]any{"account": "999999999999"}
			}
			result, err := s.IngestFindings(ctx, in)
			if err != nil || len(result.Opened) != 1 || result.Opened[0].AssetKey != arn {
				t.Fatalf("unsafe match: %+v %v", result, err)
			}
		})
	}
}

func TestArtifactInventoryDoesNotResolveScannerFindings(t *testing.T) {
	ctx := context.Background()
	s := newMigratedStore(t)
	now := time.Now().UTC()
	digest := "sha256:" + strings.Repeat("b", 64)
	in := ingestInput(digest, now, true, "cve")
	in.Tool, in.Source, in.Check = "trivy", model.IngestSource("trivy"), model.IngestCheck("trivy")
	in.Items[0].AssetKind, in.Items[0].AssetKey = model.KindContainerImage, digest
	in.Artifacts = []model.AssetInput{{Kind: model.KindContainerImage, Key: digest, Attrs: map[string]any{"digest": digest}}}
	if _, err := s.IngestFindings(ctx, in); err != nil {
		t.Fatal(err)
	}
	image, _ := s.GetAssetByKey(ctx, model.KindContainerImage, digest)
	upsert := store.AssetUpsert{AssetInput: model.AssetInput{Kind: model.KindContainerImage, Key: digest, Attrs: map[string]any{"digest": digest}}, Scope: model.ScopeExternal}
	for i := range 3 {
		if _, err := s.ApplySnapshot(ctx, "kubernetes", []store.AssetUpsert{upsert}, nil, now.Add(time.Duration(i+1)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ApplySnapshot(ctx, "kubernetes", nil, nil, now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	current, _ := s.GetAsset(ctx, image.ID)
	findings, _, err := s.ListFindings(ctx, store.FindingFilter{Check: "ext.trivy"})
	if current.RemovedAt != nil || err != nil || len(findings) != 1 || findings[0].Status != model.StatusOpen {
		t.Fatalf("inventory erased artifact/CVE: %+v %+v %v", current, findings, err)
	}
}

func TestArtifactIngestRollbackIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := newMigratedStore(t)
	now := time.Now().UTC()
	in := ingestInput("rollback", now, true, "bad\x00key")
	in.Artifacts = []model.AssetInput{{Kind: model.KindContainerImage, Key: "sha256:" + strings.Repeat("c", 64), Attrs: map[string]any{"digest": "retained only on commit"}}}
	if _, err := s.IngestFindings(ctx, in); err == nil {
		t.Fatal("expected invalid finding write")
	}
	assets, _, err := s.ListAssets(ctx, store.AssetFilter{})
	if err != nil || len(assets) != 0 {
		t.Fatalf("rollback left artifact: %+v %v", assets, err)
	}
}

func TestArtifactFactsEmitChangeWithoutReplacingAuthority(t *testing.T) {
	ctx := context.Background()
	s := newMigratedStore(t)
	now := time.Now().UTC()
	digest := "sha256:" + strings.Repeat("e", 64)
	upsert := store.AssetUpsert{AssetInput: model.AssetInput{Kind: model.KindContainerImage, Key: digest, Attrs: map[string]any{"digest": digest, "cluster": "native"}}, Scope: model.ScopeExternal}
	if _, err := s.ApplySnapshot(ctx, "kubernetes", []store.AssetUpsert{upsert}, nil, now); err != nil {
		t.Fatal(err)
	}
	in := ingestInput(digest, now.Add(time.Minute), true)
	in.Tool, in.Check, in.Source = "trivy", model.IngestCheck("trivy"), model.IngestSource("trivy")
	in.Artifacts = []model.AssetInput{{Kind: model.KindContainerImage, Key: digest, Attrs: map[string]any{"digest": digest, "scanner_version": "0.60.0"}}}
	if _, err := s.IngestFindings(ctx, in); err != nil {
		t.Fatal(err)
	}
	image, err := s.GetAssetByKey(ctx, model.KindContainerImage, digest)
	if err != nil || image.Source != "kubernetes" || image.Attrs["cluster"] != "native" || image.SourceFacts[in.Source].Attrs["scanner_version"] != "0.60.0" {
		t.Fatalf("authority lost: %+v %v", image, err)
	}
	events, err := s.ListEvents(ctx, now.Add(time.Second), 100)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for _, event := range events {
		if event.Type == "asset_changed" && event.Subject == digest {
			changed = true
		}
	}
	if !changed {
		t.Fatalf("no asset_changed event: %+v", events)
	}
}
