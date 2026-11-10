package kubernetes

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
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
	oldPod := topologyPod("web", "retired-1", "old-pod-uid")
	oldPod.Status.ContainerStatuses[0].ImageID = "registry.example.com/team/old@sha256:" + strings.Repeat("c", 64)
	cs := topologyClient("cluster-a", pod, oldPod)
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
	oldWorkload, err := st.GetAssetByKey(ctx, model.KindWorkload, resourceKey("uid:cluster-a", "web", "pod", "old-pod-uid"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.CoreV1().Pods("web").Delete(ctx, oldPod.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	pod.Status.ContainerStatuses[0].ImageID = "containerd://sha256:" + strings.Repeat("b", 64)
	if _, err := cs.CoreV1().Pods("web").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := inv.Sync(ctx, src); err != nil {
			t.Fatal(err)
		}
		assertPreviousImage()
		retired, err := st.GetAsset(ctx, oldWorkload.ID)
		if err != nil || retired.RemovedAt == nil {
			t.Fatalf("unrelated retired Pod retained by runtime image gap: %+v %v", retired, err)
		}
	}
	// Missing status in another phase is still not replacement evidence for
	// the same exact Pod UID. Normal Pending Pods need no warning or Partial.
	statuses := pod.Status.ContainerStatuses
	pod.Status.Phase, pod.Status.ContainerStatuses = corev1.PodPending, nil
	if _, err := cs.CoreV1().Pods("web").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Sync(ctx, src); err != nil {
		t.Fatal(err)
	}
	assertPreviousImage()
	pod.Status.Phase, pod.Status.ContainerStatuses = corev1.PodRunning, statuses
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
	if err != nil || current.RemovedAt != nil {
		t.Fatalf("confirmed replacement retired immutable image history: %+v %v", current, err)
	}
	oldEdges, err := st.Edges(ctx, image.ID)
	if err != nil || len(oldEdges) != 0 {
		t.Fatalf("confirmed replacement retained obsolete runs edge: %+v %v", oldEdges, err)
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
