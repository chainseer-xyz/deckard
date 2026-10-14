package kubernetes

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/inventory"
	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

func TestTopologyUnresolvedRuntimeIdentityCannotRetirePreviousImageEdge(t *testing.T) {
	ctx := context.Background()
	st := pgtest.New(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	guard, err := scope.NewGuard(config.ScopeConfig{}, scope.WithLogger(log))
	if err != nil {
		t.Fatal(err)
	}
	inv := inventory.New(st, guard, log)
	pod := topologyPod("web", "front-1", "pod-uid")
	cs := topologyClient("cluster-a", pod)
	src := NewWithClusters("k8s-topology", []Cluster{{Name: "prod", Client: cs}}, log, WithTopology(true))
	if _, err := inv.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	image, err := st.GetAssetByKey(ctx, model.KindContainerImage, topologyDigest)
	if err != nil {
		t.Fatal(err)
	}
	assertPreviousImage := func() {
		t.Helper()
		current, err := st.GetAsset(ctx, image.ID)
		if err != nil || current.RemovedAt != nil {
			t.Fatalf("unknown runtime image identity retired prior digest: %+v %v", current, err)
		}
		edges, err := st.Edges(ctx, image.ID)
		if err != nil || len(edges) != 1 || edges[0].Type != model.RelRuns || edges[0].Other.Kind != model.KindWorkload {
			t.Fatalf("unknown runtime identity removed prior runs edge: %+v %v", edges, err)
		}
	}
	assertPreviousImage()
	pod.Status.ContainerStatuses[0].ImageID = "containerd://sha256:" + strings.Repeat("b", 64)
	if _, err := cs.CoreV1().Pods("web").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := inv.Sync(ctx, src); err != nil {
			t.Fatal(err)
		}
		assertPreviousImage()
	}
	// A later confirmed manifest is real replacement evidence, not a gap.
	replacement := "sha256:" + strings.Repeat("b", 64)
	pod.Status.ContainerStatuses[0].ImageID = "registry.example.com/team/app@" + replacement
	if _, err := cs.CoreV1().Pods("web").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	current, err := st.GetAsset(ctx, image.ID)
	if err != nil || current.RemovedAt == nil {
		t.Fatalf("confirmed replacement did not retire source-only old image: %+v %v", current, err)
	}
	next, err := st.GetAssetByKey(ctx, model.KindContainerImage, replacement)
	if err != nil || next.RemovedAt != nil {
		t.Fatalf("confirmed replacement missing: %+v %v", next, err)
	}
	edges, err := st.Edges(ctx, next.ID)
	if err != nil || len(edges) != 1 || edges[0].Type != model.RelRuns {
		t.Fatalf("replacement runs edge missing: %+v %v", edges, err)
	}
}
