package kubernetes

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

var _ source.Source = (*Source)(nil)

func lbSvc(ns, name, ip, host string, ports ...int32) *corev1.Service {
	s := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
	}
	for _, p := range ports {
		s.Spec.Ports = append(s.Spec.Ports, corev1.ServicePort{Port: p, Protocol: corev1.ProtocolTCP})
	}
	if ip != "" || host != "" {
		s.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: ip, Hostname: host}}
	}
	return s
}

func npSvc(name string, nodePort int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{{Port: 80, NodePort: nodePort, Protocol: corev1.ProtocolTCP}}},
	}
}

func node(name string, addrs ...corev1.NodeAddress) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: corev1.NodeStatus{Addresses: addrs}}
}

func newDyn(objs ...runtime.Object) *dynfake.FakeDynamicClient {
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{httpRouteGVR: "HTTPRouteList"}, objs...)
}

func run(t *testing.T, cs *k8sfake.Clientset, dyn *dynfake.FakeDynamicClient) (*source.Discovery, error) {
	t.Helper()
	c := Cluster{Name: "ctx-a", Client: cs}
	if dyn != nil {
		c.Dynamic = dyn
	}
	return NewWithClusters("k8s-prod", []Cluster{c}, slog.New(slog.NewTextHandler(io.Discard, nil))).Discover(context.Background())
}

func has(d *source.Discovery, k model.AssetKind, key string) bool {
	for _, a := range d.Assets {
		if a.Kind == k && a.Key == key {
			return true
		}
	}
	return false
}

func hasRel(d *source.Discovery, fk model.AssetKind, f string, tk model.AssetKind, to string, t model.RelationType) bool {
	for _, r := range d.Relations {
		if r.FromKind == fk && r.FromKey == f && r.ToKind == tk && r.ToKey == to && r.Type == t {
			return true
		}
	}
	return false
}

func TestLoadBalancerServices(t *testing.T) {
	cs := k8sfake.NewSimpleClientset(
		lbSvc("web", "front", "192.0.2.10", "", 80, 443),
		lbSvc("web", "v6", "2001:db8::5", "", 443),
		lbSvc("web", "elb", "", "My-LB.elb.example.com", 8443),
		lbSvc("web", "pending", "", "", 80),
	)
	d, err := run(t, cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"192.0.2.10:80/tcp", "192.0.2.10:443/tcp", "[2001:db8::5]:443/tcp", "my-lb.elb.example.com:8443/tcp"} {
		if !has(d, model.KindService, k) {
			t.Errorf("missing service %s", k)
		}
	}
	if !hasRel(d, model.KindIP, "192.0.2.10", model.KindService, "192.0.2.10:443/tcp", model.RelExposes) ||
		!hasRel(d, model.KindHostname, "my-lb.elb.example.com", model.KindService, "my-lb.elb.example.com:8443/tcp", model.RelExposes) {
		t.Errorf("exposes relations missing: %+v", d.Relations)
	}
	if len(d.Assets) != 3+4 { // ips/hostname + services
		for _, a := range d.Assets {
			t.Log(a.Kind, a.Key)
		}
		t.Errorf("pending LB must be skipped; got %d assets", len(d.Assets))
	}
	for _, a := range d.Assets {
		if a.Source != "k8s-prod" || a.Attrs["cluster"] != "ctx-a" || a.Attrs["name"] == "" {
			t.Errorf("traceability attrs: %+v", a)
		}
	}
}

func TestNodePortOnlyOnExternallyAddressableNodes(t *testing.T) {
	cs := k8sfake.NewSimpleClientset(
		npSvc("np", 30080),
		node("pub", corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "10.0.0.1"}, corev1.NodeAddress{Type: corev1.NodeExternalIP, Address: "198.51.100.7"}),
		node("priv", corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "10.0.0.2"}),
	)
	d, err := run(t, cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !has(d, model.KindService, "198.51.100.7:30080/tcp") || !has(d, model.KindIP, "198.51.100.7") {
		t.Errorf("external node missing: %+v", d.Assets)
	}
	for _, a := range d.Assets {
		if a.Key == "10.0.0.1:30080/tcp" || a.Key == "10.0.0.2:30080/tcp" || a.Key == "10.0.0.1" || a.Key == "10.0.0.2" {
			t.Errorf("internal node leaked: %+v", a)
		}
	}
}

func TestNodesForbiddenSkipsNodePort(t *testing.T) {
	cs := k8sfake.NewSimpleClientset(npSvc("np", 30080))
	cs.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "nodes"}, "", errors.New("rbac"))
	})
	d, err := run(t, cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Partial || len(d.PartialReasons) != 1 {
		t.Errorf("skipped NodePort discovery must be partial: %v %v", d.Partial, d.PartialReasons)
	}
}

func TestIngressAndHTTPRoute(t *testing.T) {
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "site"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{Host: "App.Example.com"}, {Host: ""}},
			TLS:   []networkingv1.IngressTLS{{Hosts: []string{"app.example.com", "*.example.com"}}},
		},
		Status: networkingv1.IngressStatus{LoadBalancer: networkingv1.IngressLoadBalancerStatus{
			Ingress: []networkingv1.IngressLoadBalancerIngress{{IP: "192.0.2.20"}, {Hostname: "lb.elb.example.com"}},
		}},
	}
	route := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]any{"namespace": "web", "name": "r1"},
		"spec":     map[string]any{"hostnames": []any{"Route.example.com"}},
	}}
	d, err := run(t, k8sfake.NewSimpleClientset(ing), newDyn(route))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"app.example.com", "*.example.com", "route.example.com", "lb.elb.example.com"} {
		if !has(d, model.KindHostname, h) {
			t.Errorf("missing hostname %s", h)
		}
	}
	if !hasRel(d, model.KindHostname, "app.example.com", model.KindIP, "192.0.2.20", model.RelResolvesTo) ||
		!hasRel(d, model.KindHostname, "*.example.com", model.KindHostname, "lb.elb.example.com", model.RelResolvesTo) {
		t.Errorf("relations: %+v", d.Relations)
	}
	if has(d, model.KindHostname, "") {
		t.Error("empty host emitted")
	}
}

func TestOptionalKindsSkippedAndErrorsFatal(t *testing.T) {
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "x"}, "", errors.New("rbac"))
	boom := errors.New("apiserver exploded")
	tests := []struct {
		name    string
		kind    string // "services","ingresses" or "httproutes"
		err     error
		wantErr bool
		partial bool // a feature was skipped because access was denied
	}{
		{"services forbidden is fatal", "services", forbidden, true, false},
		{"services error is fatal", "services", boom, true, false},
		{"ingress forbidden skipped", "ingresses", forbidden, false, true},
		{"ingress error fatal", "ingresses", boom, true, false},
		{"httproutes forbidden skipped", "httproutes", forbidden, false, true},
		{"httproutes CRD absent silent", "httproutes", apierrors.NewNotFound(httpRouteGVR.GroupResource(), ""), false, false},
		{"httproutes error fatal", "httproutes", boom, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := k8sfake.NewSimpleClientset(lbSvc("a", "b", "192.0.2.1", "", 80))
			dyn := newDyn()
			react := func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, tc.err }
			if tc.kind == "httproutes" {
				dyn.PrependReactor("list", "httproutes", react)
			} else {
				cs.PrependReactor("list", tc.kind, react)
			}
			d, err := run(t, cs, dyn)
			if tc.wantErr {
				if err == nil || d != nil {
					t.Fatalf("want error and nil discovery, got %v %v", d, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !has(d, model.KindService, "192.0.2.1:80/tcp") {
				t.Error("services lost when optional kind skipped")
			}
			if d.Partial != tc.partial || tc.partial != (len(d.PartialReasons) > 0) {
				t.Errorf("Partial=%v reasons=%v, want partial=%v", d.Partial, d.PartialReasons, tc.partial)
			}
		})
	}
}

func TestServicePagination(t *testing.T) {
	cs := k8sfake.NewSimpleClientset()
	pages := map[string][]corev1.Service{
		"":   {*lbSvc("a", "s1", "192.0.2.1", "", 80)},
		"p2": {*lbSvc("a", "s2", "192.0.2.2", "", 80)},
	}
	next := map[string]string{"": "p2", "p2": ""}
	var limits []int64
	cs.PrependReactor("list", "services", func(a ktesting.Action) (bool, runtime.Object, error) {
		o := a.(ktesting.ListActionImpl).ListOptions
		limits = append(limits, o.Limit)
		return true, &corev1.ServiceList{Items: pages[o.Continue], ListMeta: metav1.ListMeta{Continue: next[o.Continue]}}, nil
	})
	d, err := run(t, cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !has(d, model.KindService, "192.0.2.1:80/tcp") || !has(d, model.KindService, "192.0.2.2:80/tcp") {
		t.Errorf("pagination not followed: %+v", d.Assets)
	}
	if len(limits) != 2 || limits[0] != pageSize {
		t.Errorf("limits %v", limits)
	}
}

func TestMultipleClustersFailureIsAtomic(t *testing.T) {
	good := k8sfake.NewSimpleClientset(lbSvc("a", "b", "192.0.2.1", "", 80))
	bad := k8sfake.NewSimpleClientset()
	bad.PrependReactor("list", "services", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("unreachable")
	})
	s := NewWithClusters("k", []Cluster{{Name: "good", Client: good}, {Name: "bad", Client: bad}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d, err := s.Discover(context.Background())
	if err == nil || d != nil {
		t.Fatalf("want error, nil discovery; got %v %v", d, err)
	}
}
