package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestRuntimeIncidentsLinkExactWorkloadsWithoutDependingOnTheirLifetime(t *testing.T) {
	for _, scannerFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "inventory first", true: "event first"}[scannerFirst], func(t *testing.T) {
			ctx := context.Background()
			s := newMigratedStore(t)
			now := time.Now().UTC()
			native := runtimePod("native:pod-a")
			in := runtimeDetection(now)
			addPod := func() {
				t.Helper()
				if _, err := s.ApplySnapshot(ctx, "cluster", []store.AssetUpsert{native}, nil, now); err != nil {
					t.Fatal(err)
				}
			}
			if !scannerFirst {
				addPod()
			}
			result, err := s.IngestFindings(ctx, in)
			if err != nil || len(result.Opened) != 1 {
				t.Fatalf("detection: %+v, %v", result, err)
			}
			id, assetID := result.Opened[0].ID, result.Opened[0].AssetID
			if scannerFirst {
				addPod()
				in.Digest = "inventory-now-present"
				in.Now, in.ObservedAt = now.Add(time.Minute), now.Add(time.Minute)
				if _, err := s.IngestFindings(ctx, in); err != nil {
					t.Fatal(err)
				}
			}
			pod, err := s.GetAssetByKey(ctx, model.KindWorkload, native.Key)
			if err != nil {
				t.Fatal(err)
			}
			edges, err := s.Edges(ctx, assetID)
			if err != nil || len(edges) != 1 || edges[0].Other.ID != pod.ID || edges[0].Type != model.RelTargets {
				t.Fatalf("exact workload association missing: %+v, %v", edges, err)
			}
			if _, err := s.ApplySnapshot(ctx, "cluster", nil, nil, now.Add(2*time.Minute)); err != nil {
				t.Fatal(err)
			}
			f, err := s.GetFinding(ctx, id)
			if err != nil || f.AssetID != assetID || f.Status != model.StatusOpen {
				t.Fatalf("Pod retirement healed or moved runtime incident: %+v, %v", f, err)
			}
			a, err := s.GetAsset(ctx, assetID)
			if err != nil || a.RemovedAt != nil || a.Scope != model.ScopeExternal {
				t.Fatalf("runtime attachment lost or gained ownership: %+v, %v", a, err)
			}
		})
	}
}

func TestRuntimeCorrelationRefusesAmbiguousOrConflictingAuthority(t *testing.T) {
	for _, conflict := range []string{"multiple pods", "conflicting source", "ingest source", "different scope"} {
		t.Run(conflict, func(t *testing.T) {
			ctx := context.Background()
			s := newMigratedStore(t)
			now := time.Now().UTC()
			assets := []store.AssetUpsert{runtimePod("native:pod-a")}
			source := "cluster"
			if conflict == "multiple pods" {
				assets = append(assets, runtimePod("native:pod-b"))
			}
			if conflict == "ingest source" {
				source = model.IngestSource("tetragon")
			}
			if _, err := s.ApplySnapshot(ctx, source, assets, nil, now); err != nil {
				t.Fatal(err)
			}
			if conflict == "conflicting source" {
				other := runtimePod("native:pod-a")
				other.Attrs["cluster_id"] = "uid:another-cluster"
				if _, err := s.ApplySnapshot(ctx, "other-cluster", []store.AssetUpsert{other}, nil, now); err != nil {
					t.Fatal(err)
				}
			}
			in := runtimeDetection(now)
			if conflict == "different scope" {
				in.Scope = "k8s:uid:different-cluster"
			}
			result, err := s.IngestFindings(ctx, in)
			if err != nil || len(result.Opened) != 1 {
				t.Fatalf("detection: %+v, %v", result, err)
			}
			edges, err := s.Edges(ctx, result.Opened[0].AssetID)
			if err != nil || len(edges) != 0 {
				t.Fatalf("unproven workload identity linked: %+v, %v", edges, err)
			}
		})
	}
}

func runtimePod(key string) store.AssetUpsert {
	return store.AssetUpsert{AssetInput: model.AssetInput{Kind: model.KindWorkload, Key: key,
		Attrs: map[string]any{"provider": "kubernetes", "k8s_kind": "Pod", "cluster_id": "uid:22222222-2222-4222-8222-222222222222",
			"namespace": "default", "uid": "11111111-1111-4111-8111-111111111111"}}, Scope: model.ScopeExternal}
}

func runtimeDetection(now time.Time) store.IngestInput {
	return store.IngestInput{Tool: "tetragon", Check: model.IngestCheck("tetragon"), Source: model.IngestSource("tetragon"),
		Scope: "k8s:uid:22222222-2222-4222-8222-222222222222", AssetScope: model.ScopeExternal, Now: now, ObservedAt: now, Digest: "detection",
		Items: []store.IngestItem{{Index: 0, AssetKind: model.KindCloudResource, AssetKey: "runtime:pod-a",
			Finding: model.FindingInput{Key: "policy:pod-a", Title: "Runtime detection", Severity: model.SeverityHigh,
				Evidence: map[string]any{"runtime_cluster_id": "uid:22222222-2222-4222-8222-222222222222", "runtime_namespace": "default",
					"runtime_pod_uid": "11111111-1111-4111-8111-111111111111", "runtime_last_seen": now.Format(time.RFC3339Nano)}}}}}
}
