package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

var topologyDigest = "sha256:" + strings.Repeat("a", 64)

func topologyClient(clusterUID string, objects ...runtime.Object) *k8sfake.Clientset {
	objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(clusterUID)}})
	return k8sfake.NewSimpleClientset(objects...)
}

func topologyPod(ns, name, uid string) *corev1.Pod {
	controller := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid), Labels: map[string]string{"app": "front"},
			Annotations:     map[string]string{"private": "fixture-do-not-copy"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "front-rs", UID: "rs-uid", Controller: &controller}}},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "registry.example.com/team/app:latest", Env: []corev1.EnvVar{{Name: "PRIVATE", Value: "fixture-do-not-copy"}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.8", ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ImageID: "docker-pullable://registry.example.com/team/app@" + topologyDigest}}},
	}
}

func topologyService(ns, name string) *corev1.Service {
	svc := lbSvc(ns, name, "192.0.2.10", "", 443)
	svc.UID = types.UID(ns + "-" + name + "-uid")
	svc.Spec.Selector = map[string]string{"app": "front"}
	svc.Spec.ClusterIP = "10.96.0.10"
	return svc
}

func topologySlice(ns, service, podName, podUID string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: service + "-endpoints", Namespace: ns, Labels: map[string]string{discoveryv1.LabelServiceName: service}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.8"}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: ns, Name: podName, UID: types.UID(podUID)}}},
	}
}

func runTopology(t *testing.T, clusters ...Cluster) (*source.Discovery, error) {
	t.Helper()
	return NewWithClusters("k8s-topology", clusters, slog.New(slog.NewTextHandler(io.Discard, nil)), WithTopology(true)).Discover(context.Background())
}

func topologyAsset(d *source.Discovery, kind model.AssetKind, namespace, name string) (model.AssetInput, bool) {
	for _, a := range d.Assets {
		if a.Kind == kind && a.Attrs["namespace"] == namespace && a.Attrs["name"] == name {
			return a, true
		}
	}
	return model.AssetInput{}, false
}

func TestTopologyOptInDefaultDoesNotReadWorkloads(t *testing.T) {
	cs := topologyClient("cluster-a", topologyService("web", "front"), topologyPod("web", "front-1", "pod-uid"))
	d, err := run(t, cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range d.Assets {
		if a.Kind == model.KindWorkload || a.Kind == model.KindContainerImage || a.Kind == model.KindCloudResource {
			t.Fatalf("topology is not opt-in: %+v", a)
		}
	}
	for _, action := range cs.Actions() {
		switch action.GetResource().Resource {
		case "pods", "endpointslices", "namespaces":
			t.Fatalf("topology disabled still reads %s", action.GetResource())
		}
	}
}

func TestTopologyServicePodDigestChainAndSafeMetadata(t *testing.T) {
	cs := topologyClient("cluster-a", topologyService("web", "front"), topologyPod("web", "front-1", "pod-uid"), topologySlice("web", "front", "front-1", "pod-uid"))
	d, err := runTopology(t, Cluster{Name: "prod", Client: cs})
	if err != nil {
		t.Fatal(err)
	}
	if d.Partial {
		t.Fatalf("complete topology marked partial: %v", d.PartialReasons)
	}
	svc, ok := topologyAsset(d, model.KindCloudResource, "web", "front")
	if !ok {
		t.Fatal("missing Kubernetes Service inventory node")
	}
	pod, ok := topologyAsset(d, model.KindWorkload, "web", "front-1")
	if !ok {
		t.Fatal("missing Pod inventory node")
	}
	owner, ok := topologyAsset(d, model.KindWorkload, "web", "front-rs")
	if !ok {
		t.Fatal("missing controller owner inventory node")
	}
	for _, edge := range []model.RelationInput{
		{FromKind: model.KindService, FromKey: "192.0.2.10:443/tcp", ToKind: svc.Kind, ToKey: svc.Key, Type: model.RelTargets},
		{FromKind: svc.Kind, FromKey: svc.Key, ToKind: pod.Kind, ToKey: pod.Key, Type: model.RelTargets},
		{FromKind: owner.Kind, FromKey: owner.Key, ToKind: pod.Kind, ToKey: pod.Key, Type: model.RelContains},
		{FromKind: pod.Kind, FromKey: pod.Key, ToKind: model.KindContainerImage, ToKey: topologyDigest, Type: model.RelRuns},
	} {
		if !hasRel(d, edge.FromKind, edge.FromKey, edge.ToKind, edge.ToKey, edge.Type) {
			t.Errorf("missing topology edge: %+v", edge)
		}
	}
	if !has(d, model.KindContainerImage, topologyDigest) {
		t.Error("missing immutable image identity")
	}
	for _, a := range d.Assets {
		if a.Kind == model.KindIP && (a.Key == "10.0.0.8" || a.Key == "10.96.0.10") {
			t.Errorf("internal address became a probeable IP: %+v", a)
		}
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "fixture-do-not-copy") || strings.Contains(string(encoded), "annotations") || strings.Contains(string(encoded), "PRIVATE") {
		t.Fatal("secret-bearing Pod metadata copied into inventory")
	}
}

func TestTopologySelectorsStayWithinServiceNamespace(t *testing.T) {
	cs := topologyClient("cluster-a", topologyService("web", "front"), topologyPod("web", "same", "pod-a"), topologyPod("other", "same", "pod-b"))
	d, err := runTopology(t, Cluster{Name: "prod", Client: cs})
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := topologyAsset(d, model.KindCloudResource, "web", "front")
	want, _ := topologyAsset(d, model.KindWorkload, "web", "same")
	other, _ := topologyAsset(d, model.KindWorkload, "other", "same")
	if svc.Key == "" || want.Key == "" || other.Key == "" {
		t.Fatal("topology nodes missing")
	}
	if !hasRel(d, svc.Kind, svc.Key, want.Kind, want.Key, model.RelTargets) || hasRel(d, svc.Kind, svc.Key, other.Kind, other.Key, model.RelTargets) {
		t.Fatal("selector did not preserve namespace boundary")
	}
}

func TestTopologyEndpointSliceUsesUIDNotReusedPodName(t *testing.T) {
	svc := topologyService("web", "front")
	cs := topologyClient("cluster-a", svc, topologyPod("web", "front-1", "new-pod"), topologySlice("web", "front", "front-1", "retired-pod"))
	d, err := runTopology(t, Cluster{Name: "prod", Client: cs})
	if err != nil {
		t.Fatal(err)
	}
	service, _ := topologyAsset(d, model.KindCloudResource, "web", "front")
	pod, _ := topologyAsset(d, model.KindWorkload, "web", "front-1")
	if service.Key == "" || pod.Key == "" {
		t.Fatal("topology nodes missing")
	}
	if hasRel(d, service.Kind, service.Key, pod.Kind, pod.Key, model.RelTargets) {
		t.Fatal("stale endpoint UID was replaced by matching name or selector")
	}
}

func TestTopologyAdditionalReadFailuresArePartial(t *testing.T) {
	for _, resource := range []string{"pods", "endpointslices", "namespaces"} {
		t.Run(resource, func(t *testing.T) {
			cs := topologyClient("cluster-a", topologyService("web", "front"), topologyPod("web", "front-1", "pod-uid"))
			verb := "list"
			if resource == "namespaces" {
				verb = "get"
			}
			cs.PrependReactor(verb, resource, func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: resource}, "", errors.New("rbac"))
			})
			d, err := runTopology(t, Cluster{Name: "prod", Client: cs})
			if err != nil || d == nil {
				t.Fatalf("optional metadata read lost ordinary discovery: %v", err)
			}
			if !d.Partial || len(d.PartialReasons) == 0 || !has(d, model.KindService, "192.0.2.10:443/tcp") {
				t.Fatalf("denied topology read must retain endpoints and mark partial: %+v", d)
			}
		})
	}
}

func TestTopologyIngressBackendsIncludeClusterIPServices(t *testing.T) {
	svc := topologyService("web", "front")
	svc.Spec.Type = corev1.ServiceTypeClusterIP
	svc.Status.LoadBalancer.Ingress = nil
	ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "public"}, Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{Host: "app.example.com", IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "front", Port: networkingv1.ServiceBackendPort{Number: 443}}}}}}}}}}}
	d, err := runTopology(t, Cluster{Name: "prod", Client: topologyClient("cluster-a", svc, ing)})
	if err != nil {
		t.Fatal(err)
	}
	service, _ := topologyAsset(d, model.KindCloudResource, "web", "front")
	if service.Key == "" || !hasRel(d, model.KindHostname, "app.example.com", service.Kind, service.Key, model.RelTargets) {
		t.Fatal("Ingress backend did not link to its internal Service resource")
	}
	if has(d, model.KindIP, "10.96.0.10") {
		t.Fatal("ClusterIP became a probeable asset")
	}
}
