package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"

	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestTopologyHTTPRouteBackendsAreNamespaceLocalServices(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fields  map[string]any
		want    bool
		partial bool
	}{
		{name: "default Service reference", want: true},
		{name: "explicit local namespace", fields: map[string]any{"namespace": "web"}, want: true},
		{name: "explicit core Service", fields: map[string]any{"kind": "Service", "group": ""}, want: true},
		{name: "cross namespace ungranted", fields: map[string]any{"namespace": "other"}, partial: true},
		{name: "other API group", fields: map[string]any{"group": "example.com"}},
		{name: "malformed explicit group", fields: map[string]any{"group": int64(7)}, partial: true},
		{name: "other object kind", fields: map[string]any{"kind": "Secret"}},
		{name: "disabled backend", fields: map[string]any{"weight": int64(0)}},
		{name: "unknown service port", fields: map[string]any{"port": int64(8443)}},
		{name: "missing service", fields: map[string]any{"name": "missing"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := map[string]any{"name": "front", "port": int64(443)}
			for key, value := range tc.fields {
				ref[key] = value
			}
			route := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
				"metadata": map[string]any{"namespace": "web", "name": "public"},
				"spec":     map[string]any{"hostnames": []any{"app.example.com"}, "rules": []any{map[string]any{"backendRefs": []any{ref}}}},
			}}
			d, err := runTopology(t, Cluster{Name: "prod", Client: topologyClient("cluster-a", topologyService("web", "front"), topologyService("other", "front")), Dynamic: newDyn(route)})
			if err != nil {
				t.Fatal(err)
			}
			local, _ := topologyAsset(d, model.KindCloudResource, "web", "front")
			foreign, _ := topologyAsset(d, model.KindCloudResource, "other", "front")
			if local.Key == "" || foreign.Key == "" {
				t.Fatal("missing Service resource nodes")
			}
			if got := hasRel(d, model.KindHostname, "app.example.com", local.Kind, local.Key, model.RelTargets); got != tc.want {
				t.Errorf("local Service target=%v, want %v", got, tc.want)
			}
			if hasRel(d, model.KindHostname, "app.example.com", foreign.Kind, foreign.Key, model.RelTargets) {
				t.Error("route crossed a namespace without ReferenceGrant verification")
			}
			if d.Partial != tc.partial {
				t.Errorf("Partial=%v, want %v: %v", d.Partial, tc.partial, d.PartialReasons)
			}
		})
	}
}

func TestTopologyRuntimeImageIDRequiresRepositoryManifestReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   string
		want bool
	}{
		{"Docker pullable reference", "docker-pullable://registry.example.com/team/app@" + topologyDigest, true},
		{"repository manifest reference", "registry.example.com/team/app@" + topologyDigest, true},
		{"bare runtime config digest", topologyDigest, false},
		{"containerd runtime config digest", "containerd://" + topologyDigest, false},
		{"Docker runtime config digest", "docker://" + topologyDigest, false},
		{"unresolved tag", "registry.example.com/team/app:latest", false},
		{"missing runtime ID", "", false},
		{"malformed digest", "registry.example.com/team/app@sha256:abcd", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := topologyPod("web", "front-1", "pod-uid")
			pod.Status.ContainerStatuses[0].ImageID = tc.id
			d, err := runTopology(t, Cluster{Name: "prod", Client: topologyClient("cluster-a", pod)})
			if err != nil {
				t.Fatal(err)
			}
			if got := has(d, model.KindContainerImage, topologyDigest); got != tc.want {
				t.Errorf("immutable image exists=%v, want %v", got, tc.want)
			}
			if d.Partial == tc.want {
				t.Errorf("running Pod with unsupported runtime identity must be partial; Partial=%v supported=%v", d.Partial, tc.want)
			}
			workload, _ := topologyAsset(d, model.KindWorkload, "web", "front-1")
			if got := hasRel(d, workload.Kind, workload.Key, model.KindContainerImage, topologyDigest, model.RelRuns); got != tc.want {
				t.Errorf("runs edge exists=%v, want %v", got, tc.want)
			}
			encoded := workload.Attrs["containers"].([]map[string]any)
			if len(encoded) != 1 || encoded[0]["image"] != "registry.example.com/team/app:latest" {
				t.Error("declared mutable reference must remain visible as metadata")
			}
		})
	}
}

func TestTopologyInitAndEphemeralRuntimeImagesDeduplicateByDigest(t *testing.T) {
	pod := topologyPod("web", "front-1", "pod-uid")
	pod.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "registry.example.com/team/setup:v1"}}
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "registry.example.com/team/debug:v1"}}}
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", ImageID: "registry.example.com/team/setup@" + topologyDigest}}
	pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "debug", ImageID: "registry.example.com/team/debug@" + topologyDigest}}
	d, err := runTopology(t, Cluster{Name: "prod", Client: topologyClient("cluster-a", pod)})
	if err != nil {
		t.Fatal(err)
	}
	images, runs := 0, 0
	for _, asset := range d.Assets {
		if asset.Kind == model.KindContainerImage {
			images++
		}
	}
	for _, edge := range d.Relations {
		if edge.Type == model.RelRuns {
			runs++
		}
	}
	if images != 1 || runs != 1 {
		t.Fatalf("same digest in three runtime containers produced images=%d runs=%d", images, runs)
	}
}

func TestTopologyPendingPodWithoutImageIsNormalButRunningStatusGapIsPartial(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodPending, corev1.PodRunning} {
		t.Run(string(phase), func(t *testing.T) {
			pod := topologyPod("web", "front-1", "pod-uid")
			pod.Status.Phase, pod.Status.ContainerStatuses = phase, nil
			d, err := runTopology(t, Cluster{Name: "prod", Client: topologyClient("cluster-a", pod)})
			if err != nil {
				t.Fatal(err)
			}
			if d.Partial != (phase == corev1.PodRunning) || has(d, model.KindContainerImage, topologyDigest) {
				t.Fatalf("phase=%s completeness=%v images=%+v", phase, d.Partial, d.Assets)
			}
		})
	}
}

func TestTopologyWorkloadIdentitySurvivesContextAndNameChangesButNotRecreation(t *testing.T) {
	key := func(contextName, clusterUID, podName, podUID string) string {
		t.Helper()
		d, err := runTopology(t, Cluster{Name: contextName, Client: topologyClient(clusterUID, topologyPod("web", podName, podUID))})
		if err != nil {
			t.Fatal(err)
		}
		pod, ok := topologyAsset(d, model.KindWorkload, "web", podName)
		if !ok {
			t.Fatal("missing workload")
		}
		return pod.Key
	}
	original := key("old-context", "cluster-a", "old-name", "pod-uid")
	if renamed := key("new-context", "cluster-a", "new-name", "pod-uid"); renamed != original {
		t.Fatal("context or display name changed immutable workload identity")
	}
	if recreated := key("old-context", "cluster-a", "old-name", "replacement-uid"); recreated == original {
		t.Fatal("a recreated Pod reused the retired workload identity")
	}
	if elsewhere := key("old-context", "cluster-b", "old-name", "pod-uid"); elsewhere == original {
		t.Fatal("equal object UID in a different cluster merged workloads")
	}
}

func TestTopologyClusterIdentityDoesNotMergeEqualContextNames(t *testing.T) {
	d, err := runTopology(t,
		Cluster{Name: "prod", Client: topologyClient("cluster-a", topologyService("web", "front"), topologyPod("web", "same", "pod-uid"))},
		Cluster{Name: "prod", Client: topologyClient("cluster-b", topologyService("web", "front"), topologyPod("web", "same", "pod-uid"))},
	)
	if err != nil {
		t.Fatal(err)
	}
	services, pods := map[string]bool{}, map[string]bool{}
	for _, asset := range d.Assets {
		if asset.Kind == model.KindCloudResource {
			services[asset.Key] = true
		}
		if asset.Kind == model.KindWorkload && asset.Attrs["k8s_kind"] == "Pod" {
			pods[asset.Key] = true
		}
	}
	if len(services) != 2 || len(pods) != 2 {
		t.Fatalf("cross-cluster identities merged: services=%d pods=%d", len(services), len(pods))
	}
}

func TestTopologyFallbackIdentityIsPartialAndNotEquivalentToNamespaceUID(t *testing.T) {
	cs := topologyClient("cluster-a", topologyPod("web", "front-1", "pod-uid"))
	deny := true
	cs.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
		if deny {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "kube-system", errors.New("rbac"))
		}
		return false, nil, nil
	})
	fallback, err := runTopology(t, Cluster{Name: "prod", Client: cs})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := topologyAsset(fallback, model.KindWorkload, "web", "front-1")
	if !fallback.Partial || !strings.Contains(first.Key, "configured:") {
		t.Fatalf("missing explicit partial fallback identity: %+v", fallback)
	}
	deny = false
	complete, err := runTopology(t, Cluster{Name: "renamed-context", Client: cs})
	if err != nil {
		t.Fatal(err)
	}
	second, _ := topologyAsset(complete, model.KindWorkload, "web", "front-1")
	if complete.Partial || first.Key == second.Key || !strings.Contains(second.Key, "uid:") {
		t.Fatal("fallback and immutable cluster identity were incorrectly treated as equivalent")
	}
}

func TestTopologyPodsAndEndpointSlicesFollowPagination(t *testing.T) {
	cs := topologyClient("cluster-a", topologyService("web", "one"), topologyService("web", "two"))
	for _, resource := range []string{"pods", "endpointslices"} {
		cs.PrependReactor("list", resource, func(action ktesting.Action) (bool, runtime.Object, error) {
			opts := action.(ktesting.ListActionImpl).ListOptions
			if opts.Limit != pageSize {
				t.Errorf("%s limit=%d, want %d", action.GetResource(), opts.Limit, pageSize)
			}
			name, uid, next := "one", "pod-1", "second"
			if opts.Continue == "second" {
				name, uid, next = "two", "pod-2", ""
			}
			if action.GetResource().Resource == "pods" {
				return true, &corev1.PodList{ListMeta: metav1.ListMeta{Continue: next}, Items: []corev1.Pod{*topologyPod("web", name, uid)}}, nil
			}
			return true, &discoveryv1.EndpointSliceList{ListMeta: metav1.ListMeta{Continue: next}, Items: []discoveryv1.EndpointSlice{*topologySlice("web", name, name, uid)}}, nil
		})
	}
	d, err := runTopology(t, Cluster{Name: "prod", Client: cs})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		svc, _ := topologyAsset(d, model.KindCloudResource, "web", name)
		pod, _ := topologyAsset(d, model.KindWorkload, "web", name)
		if svc.Key == "" || pod.Key == "" || !hasRel(d, svc.Kind, svc.Key, pod.Kind, pod.Key, model.RelTargets) {
			t.Errorf("missing paginated service→Pod chain for %s", name)
		}
	}
}

func TestTopologyLaterPodPageFailureRetainsPositivePartialResults(t *testing.T) {
	cs := topologyClient("cluster-a", topologyService("web", "front"))
	cs.PrependReactor("list", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		if action.(ktesting.ListActionImpl).ListOptions.Continue != "" {
			return true, nil, errors.New("upstream stopped mid-page")
		}
		return true, &corev1.PodList{ListMeta: metav1.ListMeta{Continue: "next"}, Items: []corev1.Pod{*topologyPod("web", "first", "pod-uid")}}, nil
	})
	d, err := runTopology(t, Cluster{Name: "prod", Client: cs})
	if err != nil || !d.Partial {
		t.Fatalf("later metadata page failure should be partial, not complete/fatal: %v %+v", err, d)
	}
	if _, ok := topologyAsset(d, model.KindWorkload, "web", "first"); !ok {
		t.Fatal("successful first-page observations were lost")
	}
}

func TestTopologyEmptySelectorsAndCrossNamespaceEndpointRefsNeverTargetPods(t *testing.T) {
	svc := topologyService("web", "front")
	svc.Spec.Selector = nil
	slice := topologySlice("web", "front", "front-1", "pod-uid")
	slice.Endpoints[0].TargetRef.Namespace = "other"
	d, err := runTopology(t, Cluster{Name: "prod", Client: topologyClient("cluster-a", svc, topologyPod("web", "front-1", "pod-uid"), slice)})
	if err != nil {
		t.Fatal(err)
	}
	for _, edge := range d.Relations {
		if edge.FromKind == model.KindCloudResource && edge.ToKind == model.KindWorkload && edge.Type == model.RelTargets {
			t.Fatalf("empty selector or foreign EndpointSlice target matched a Pod: %+v", edge)
		}
	}
}

func TestTopologyContextCancellationReturnsNoSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cs := topologyClient("cluster-a", topologyService("web", "front"))
	cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		cancel()
		return true, nil, context.Canceled
	})
	s := NewWithClusters("k8s-topology", []Cluster{{Name: "prod", Client: cs}}, nil, WithTopology(true))
	d, err := s.Discover(ctx)
	if d != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation must discard snapshot: %+v %v", d, err)
	}
}

func TestTopologyWorkloadWithoutUIDIsIncompleteNotNameJoined(t *testing.T) {
	pod := topologyPod("web", "front-1", "")
	pod.OwnerReferences[0].UID = types.UID("owner-uid")
	d, err := runTopology(t, Cluster{Name: "prod", Client: topologyClient("cluster-a", pod)})
	if err != nil || !d.Partial {
		t.Fatalf("missing UID must be incomplete: %+v %v", d, err)
	}
	if _, ok := topologyAsset(d, model.KindWorkload, "web", "front-1"); ok {
		t.Fatal("missing Pod UID fell back to a reusable display name")
	}
}

func TestTopologyResourceKeysUseURIPathForOpaqueClusterIdentity(t *testing.T) {
	key := resourceKey("uid:cluster-a", "web", "pod", "pod-uid")
	parsed, err := url.Parse(key)
	if err != nil || parsed.Scheme != "k8s" || parsed.Host != "cluster" || parsed.User != nil {
		t.Fatalf("cluster identity is not a hostname or port: %q (%v)", key, err)
	}
}

func TestTopologyIngressAndHTTPRouteBackendsFollowPagination(t *testing.T) {
	cs := topologyClient("cluster-a", topologyService("web", "front"))
	ingressCalls, routeCalls := 0, 0
	cs.PrependReactor("list", "ingresses", func(action ktesting.Action) (bool, runtime.Object, error) {
		ingressCalls++
		if ingressCalls > 3 {
			return true, nil, errors.New("Ingress fixture pagination exceeded its call budget")
		}
		opts := action.(ktesting.ListActionImpl).ListOptions
		if opts.Limit != pageSize {
			t.Errorf("Ingress limit=%d", opts.Limit)
		}
		name, next := "ingress-first", "next"
		if opts.Continue != "" {
			name, next = "ingress-second", ""
		}
		return true, &networkingv1.IngressList{ListMeta: metav1.ListMeta{Continue: next}, Items: []networkingv1.Ingress{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: name},
			Spec:       networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{Host: name + ".example.com", IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "front", Port: networkingv1.ServiceBackendPort{Number: 443}}}}}}}}}},
		}}}, nil
	})
	// The dynamic fake's root-list action drops Limit/Continue in client-go
	// v0.37.1. Exercise the real dynamic HTTP client for its pagination contract.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routeCalls++
		if routeCalls > 3 {
			http.Error(w, "HTTPRoute fixture pagination exceeded its call budget", http.StatusInternalServerError)
			return
		}
		if r.URL.Path != "/apis/gateway.networking.k8s.io/v1/httproutes" || r.URL.Query().Get("limit") != "500" {
			t.Errorf("unexpected paginated HTTPRoute request: %s", r.URL)
		}
		name, next := "route-first", "next"
		if r.URL.Query().Get("continue") != "" {
			name, next = "route-second", ""
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRouteList", "metadata": map[string]any{"continue": next}, "items": []any{map[string]any{
			"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
			"metadata": map[string]any{"namespace": "web", "name": name},
			"spec":     map[string]any{"hostnames": []any{name + ".example.com"}, "rules": []any{map[string]any{"backendRefs": []any{map[string]any{"name": "front", "port": 443}}}}},
		}}}); err != nil {
			t.Errorf("encode HTTPRoute fixture: %v", err)
		}
	}))
	defer server.Close()
	dyn, err := dynamic.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	d, err := runTopology(t, Cluster{Name: "prod", Client: cs, Dynamic: dyn})
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := topologyAsset(d, model.KindCloudResource, "web", "front")
	for _, prefix := range []string{"ingress-first", "ingress-second", "route-first", "route-second"} {
		if !hasRel(d, model.KindHostname, prefix+".example.com", svc.Kind, svc.Key, model.RelTargets) {
			t.Errorf("lost paginated backend relationship for %s", prefix)
		}
	}
}

func TestPaginationRejectsRepeatedContinuationToken(t *testing.T) {
	calls := 0
	err := paginate(func(metav1.ListOptions) (string, error) {
		calls++
		if calls > 3 {
			return "", errors.New("fixture call budget exhausted")
		}
		return "same", nil
	})
	if err == nil || !strings.Contains(err.Error(), "continuation") || calls != 2 {
		t.Fatalf("repeated token must stop before retrying forever: calls=%d err=%v", calls, err)
	}
}
