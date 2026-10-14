package imagecollector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

const testScope = "k8s:uid:11111111-1111-4111-8111-111111111111:runtime-images"

func digest(n int) string    { return fmt.Sprintf("sha256:%064x", n) }
func reference(n int) string { return "registry.example.com/app@" + digest(n) }
func pod(name string, n int) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "apps", UID: types.UID("pod-" + name)},
		Spec:   corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "app", Image: "app:mutable"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ImageID: "docker-pullable://" + reference(n)}}}}
}

func node() *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node"}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OperatingSystem: "linux", Architecture: "arm64"}}}
}

type scannerFunc func(context.Context, Target) ([]byte, error)

func (f scannerFunc) Scan(ctx context.Context, target Target) ([]byte, error) { return f(ctx, target) }
func native(target Target) []byte {
	return []byte(fmt.Sprintf(`{"SchemaVersion":2,"ArtifactType":"container_image","Metadata":{"RepoDigests":[%q]},"Results":[]}`, target.Reference))
}

func TestCollectAllLiveImagesOnceWithExplicitPlatform(t *testing.T) {
	p := pod("app", 1)
	p.Spec.InitContainers = []corev1.Container{{Name: "init"}}
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", ImageID: reference(2)}}
	p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug"}}}
	p.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "debug", ImageID: reference(3)}}
	client := fake.NewClientset(node(), p, pod("replica", 1))
	var scanned []Target
	scanner := scannerFunc(func(_ context.Context, target Target) ([]byte, error) {
		scanned = append(scanned, target)
		if target.Platform != "linux/arm64" || strings.Contains(target.Reference, "://") {
			t.Fatalf("unsafe target: %+v", target)
		}
		return native(target), nil
	})
	req, err := Collect(context.Background(), client.CoreV1(), Options{Namespaces: []string{"apps"}, ClusterScope: testScope, WithScanner: scanner})
	if err != nil {
		t.Fatal(err)
	}
	if req.Complete || req.Tool != "trivy" || req.Scope != testScope || len(scanned) != 3 || len(req.Artifacts) != 3 || req.Findings == nil {
		t.Fatalf("unexpected aggregate: %+v scanned%v", req, scanned)
	}
	for _, a := range req.Artifacts {
		if a.Kind != model.KindContainerImage {
			t.Fatal(a)
		}
	}
}

func TestCollectRefusesUnknownOrIncompleteRuntimeIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Pod, *corev1.Node)
	}{
		{"mutable tag", func(p *corev1.Pod, _ *corev1.Node) { p.Status.ContainerStatuses[0].ImageID = "app:mutable" }},
		{"bare config digest", func(p *corev1.Pod, _ *corev1.Node) { p.Status.ContainerStatuses[0].ImageID = digest(1) }},
		{"missing status", func(p *corev1.Pod, _ *corev1.Node) { p.Status.ContainerStatuses = nil }},
		{"pending unbound", func(p *corev1.Pod, _ *corev1.Node) { p.Spec.NodeName = ""; p.Status.Phase = corev1.PodPending }},
		{"unsupported architecture", func(_ *corev1.Pod, n *corev1.Node) { n.Status.NodeInfo.Architecture = "s390x" }},
		{"unknown operating system", func(_ *corev1.Pod, n *corev1.Node) { n.Status.NodeInfo.OperatingSystem = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, n := pod("app", 1), node()
			tc.mutate(p, n)
			calls := 0
			client := fake.NewClientset(p, n)
			req, err := Collect(context.Background(), client.CoreV1(), Options{Namespaces: []string{"apps"}, ClusterScope: testScope, WithScanner: scannerFunc(func(_ context.Context, target Target) ([]byte, error) { calls++; return native(target), nil })})
			if err == nil || req != nil || calls != 0 {
				t.Fatalf("incomplete inventory scanned/exported: req%v err%v calls%d", req, err, calls)
			}
		})
	}
}

func TestCollectFailureOrDigestMismatchProducesNoEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name string
		scan scannerFunc
	}{
		{"scanner error", func(context.Context, Target) ([]byte, error) { return nil, errors.New("native failure") }},
		{"invalid JSON", func(context.Context, Target) ([]byte, error) { return []byte("bad"), nil }},
		{"different manifest", func(_ context.Context, target Target) ([]byte, error) {
			target.Reference = reference(2)
			return native(target), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientset(node(), pod("app", 1))
			req, err := Collect(context.Background(), client.CoreV1(), Options{Namespaces: []string{"apps"}, ClusterScope: testScope, WithScanner: tc.scan})
			if err == nil || req != nil {
				t.Fatalf("exported failure: %v %v", req, err)
			}
		})
	}
}

func TestCollectInventoryChangeDuringScanCannotResolve(t *testing.T) {
	client := fake.NewClientset(node(), pod("app", 1))
	scanner := scannerFunc(func(_ context.Context, target Target) ([]byte, error) {
		_, err := client.CoreV1().Pods("apps").Update(context.Background(), pod("app", 2), metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return native(target), nil
	})
	req, err := Collect(context.Background(), client.CoreV1(), Options{Namespaces: []string{"apps"}, ClusterScope: testScope, WithScanner: scanner})
	if err == nil || req != nil {
		t.Fatalf("changed snapshot exported complete: %v %v", req, err)
	}
}

func TestCollectRequiresExplicitScopeAndNamespaceAuthority(t *testing.T) {
	for _, options := range []Options{
		{ClusterScope: testScope},
		{Namespaces: []string{"apps"}},
		{Namespaces: []string{"apps"}, AllNamespaces: true, ClusterScope: testScope},
		{Namespaces: []string{"*"}, ClusterScope: testScope},
		{Namespaces: []string{"apps"}, ClusterScope: "k8s:mutable-name:runtime-images"},
	} {
		if _, err := Collect(context.Background(), fake.NewClientset().CoreV1(), options); err == nil {
			t.Fatalf("invalid authority accepted: %+v", options)
		}
	}
}

func TestCollectImageLimitAndAPIDenialFailBeforeScanning(t *testing.T) {
	objects := []runtime.Object{node()}
	for i := 1; i <= 65; i++ {
		objects = append(objects, pod(fmt.Sprint(i), i))
	}
	client := fake.NewClientset(objects...)
	if req, err := Collect(context.Background(), client.CoreV1(), Options{Namespaces: []string{"apps"}, ClusterScope: testScope}); err == nil || req != nil {
		t.Fatal("image limit exported")
	}
	denied := fake.NewClientset()
	denied.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("forbidden") })
	if req, err := Collect(context.Background(), denied.CoreV1(), Options{Namespaces: []string{"apps"}, ClusterScope: testScope}); err == nil || req != nil {
		t.Fatal("denied snapshot exported")
	}
}

func TestCollectPaginatesBothInventoriesAndRejectsStalledContinuation(t *testing.T) {
	client := fake.NewClientset(node())
	pages := 0
	client.PrependReactor("list", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		pages++
		opts := action.(ktesting.ListActionImpl).ListOptions
		if opts.Limit != 500 || action.GetNamespace() != "apps" {
			t.Fatal("unbounded or unscoped list")
		}
		if opts.Continue == "" {
			return true, &corev1.PodList{ListMeta: metav1.ListMeta{Continue: "page2"}, Items: []corev1.Pod{*pod("app", 1)}}, nil
		}
		return true, &corev1.PodList{Items: []corev1.Pod{*pod("replica", 1)}}, nil
	})
	scanner := scannerFunc(func(_ context.Context, target Target) ([]byte, error) { return native(target), nil })
	if _, err := Collect(context.Background(), client.CoreV1(), Options{Namespaces: []string{"apps"}, ClusterScope: testScope, WithScanner: scanner}); err != nil {
		t.Fatal(err)
	}
	if pages != 4 {
		t.Fatalf("both snapshots not paginated: %d", pages)
	}
	client.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.PodList{ListMeta: metav1.ListMeta{Continue: "stuck"}}, nil
	})
	if req, err := Collect(context.Background(), client.CoreV1(), Options{Namespaces: []string{"apps"}, ClusterScope: testScope, WithScanner: scanner}); err == nil || req != nil {
		t.Fatal("stalled continuation accepted")
	}
}

func TestAggregateBodyIsLocallyValid(t *testing.T) {
	client := fake.NewClientset(node(), pod("app", 1))
	req, err := Collect(context.Background(), client.CoreV1(), Options{Namespaces: []string{"apps"}, ClusterScope: testScope, WithScanner: scannerFunc(func(_ context.Context, target Target) ([]byte, error) { return native(target), nil })})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = json.Marshal(req); err != nil {
		t.Fatal(err)
	}
}

func TestNamespaceFilterChangesNeverCertifyAbsence(t *testing.T) {
	client := fake.NewClientset(node(), pod("app", 1))
	scanner := scannerFunc(func(_ context.Context, target Target) ([]byte, error) { return native(target), nil })
	for _, ns := range []string{"apps", "edge"} {
		req, err := Collect(context.Background(), client.CoreV1(), Options{Namespaces: []string{ns}, ClusterScope: testScope, WithScanner: scanner})
		if err != nil || req.Complete {
			t.Fatalf("namespace change can resolve: req%+v err%v", req, err)
		}
	}
	request, err := Collect(context.Background(), client.CoreV1(), Options{AllNamespaces: true, ClusterScope: testScope, WithScanner: scanner})
	if err != nil || !request.Complete {
		t.Fatalf("explicit stable cluster-wide inventory is not complete: %v %v", request, err)
	}
}

func TestCollectPodAndNodeCapsRefuseBeforeNativeScanner(t *testing.T) {
	for _, resource := range []string{"pods", "nodes"} {
		client := fake.NewClientset(node())
		client.PrependReactor("list", resource, func(ktesting.Action) (bool, runtime.Object, error) {
			if resource == "pods" {
				return true, &corev1.PodList{Items: make([]corev1.Pod, MaxPods+1)}, nil
			}
			return true, &corev1.NodeList{Items: make([]corev1.Node, MaxNodes+1)}, nil
		})
		if req, err := Collect(context.Background(), client.CoreV1(), Options{AllNamespaces: true, ClusterScope: testScope}); err == nil || req != nil {
			t.Fatalf("%s cap did not fail closed", resource)
		}
	}
}

func TestCollectAggregateArtifactOverflowFailsInsteadOfTruncating(t *testing.T) {
	client := fake.NewClientset(node(), pod("one", 1), pod("two", 2))
	part := 0
	scanner := scannerFunc(func(_ context.Context, target Target) ([]byte, error) {
		packages := make([]map[string]any, 2500)
		for i := range packages {
			packages[i] = map[string]any{"Identifier": map[string]string{"PURL": fmt.Sprintf("pkg:apk/alpine/package%d@1.0", part*2500+i)}}
		}
		part++
		document := map[string]any{"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": map[string]any{"RepoDigests": []string{target.Reference}}, "Results": []map[string]any{{"Target": "fixture", "Class": "os-pkgs", "Type": "alpine", "Packages": packages}}}
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return raw, nil
	})
	req, err := Collect(context.Background(), client.CoreV1(), Options{AllNamespaces: true, ClusterScope: testScope, WithScanner: scanner})
	if err == nil || req != nil || !strings.Contains(err.Error(), "cardinality") || part != 2 {
		t.Fatalf("aggregate overflow was truncated/exported: %v %v part%d", req, err, part)
	}
}

func TestEncodeRejectsAggregateBodyOverTenMiB(t *testing.T) {
	now := time.Now().UTC()
	req := &ingest.Request{Tool: "trivy", Scope: testScope, ObservedAt: &now, Complete: true,
		Artifacts: []ingest.Artifact{{Kind: model.KindContainerImage, Key: digest(1)}}, Findings: make([]ingest.Finding, ingest.MaxFindings)}
	for i := range req.Findings {
		req.Findings[i] = ingest.Finding{Key: fmt.Sprint(i), Asset: ingest.Asset{Kind: model.KindContainerImage, Key: digest(1)}, Title: "size bound", Severity: model.SeverityInfo, Description: strings.Repeat("a", 2500)}
	}
	if raw, err := Encode(req); err == nil || raw != nil || !strings.Contains(err.Error(), "10 MiB") {
		t.Fatalf("oversized body emitted: %d bytes %v", len(raw), err)
	}
}

func TestCollectorInitContainerDoesNotMisclassifyUnstartedUploaderAsRuntimeImage(t *testing.T) {
	p := pod("collector", 1)
	p.Status.ContainerStatuses[0].ImageID = ""
	p.Status.ContainerStatuses[0].State.Waiting = &corev1.ContainerStateWaiting{Reason: "PodInitializing"}
	p.Spec.InitContainers = []corev1.Container{{Name: "scanner", Image: "scanner:immutable"}}
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "scanner", ImageID: reference(1), State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}
	client := fake.NewClientset(node(), p)
	scanner := scannerFunc(func(_ context.Context, target Target) ([]byte, error) { return native(target), nil })
	req, err := Collect(context.Background(), client.CoreV1(), Options{AllNamespaces: true, ClusterScope: testScope, WithScanner: scanner})
	if err != nil || !req.Complete || len(req.Artifacts) != 1 {
		t.Fatalf("collector can never scan itself: req%+v err%v", req, err)
	}
}

func TestUnstartedContainerTransitionOrSpecChangeInvalidatesSnapshot(t *testing.T) {
	for _, change := range []string{"started", "spec changed"} {
		t.Run(change, func(t *testing.T) {
			p := pod("collector", 1)
			p.Status.ContainerStatuses[0].ImageID = ""
			p.Status.ContainerStatuses[0].State.Waiting = &corev1.ContainerStateWaiting{Reason: "PodInitializing"}
			p.Spec.InitContainers = []corev1.Container{{Name: "scanner"}}
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "scanner", ImageID: reference(1)}}
			client := fake.NewClientset(node(), p)
			scanner := scannerFunc(func(_ context.Context, target Target) ([]byte, error) {
				if change == "started" {
					p.Status.ContainerStatuses[0].ImageID = reference(2)
					p.Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
				} else {
					p.Spec.Containers[0].Image = "a-new-future-image:tag"
				}
				if _, err := client.CoreV1().Pods("apps").Update(context.Background(), p, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				return native(target), nil
			})
			req, err := Collect(context.Background(), client.CoreV1(), Options{AllNamespaces: true, ClusterScope: testScope, WithScanner: scanner})
			if err == nil || req != nil {
				t.Fatal("unstarted runtime transition exported complete")
			}
		})
	}
}
