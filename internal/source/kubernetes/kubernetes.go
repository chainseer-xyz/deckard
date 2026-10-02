// Package kubernetes discovers externally reachable assets from one or more
// Kubernetes clusters: LoadBalancer/NodePort Services, Ingress hosts and
// Gateway API HTTPRoute hostnames.
package kubernetes

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

const pageSize = 500

var httpRouteGVR = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}

// Cluster is one reachable cluster (kubeconfig context or in-cluster).
type Cluster struct {
	Name    string // context name, or "in-cluster"
	Client  k8s.Interface
	Dynamic dynamic.Interface
}

// Source implements source.Source for Kubernetes.
type Source struct {
	name     string
	clusters []Cluster
	log      *slog.Logger
}

// NewWithClusters builds a Source around explicit clusters (used by tests).
func NewWithClusters(name string, clusters []Cluster, log *slog.Logger) *Source {
	if log == nil {
		log = slog.Default()
	}
	return &Source{name: name, clusters: clusters, log: log}
}

// New builds a Source from config. No cluster is contacted until Discover.
func New(cfg config.SourceConfig, log *slog.Logger) (source.Source, error) {
	var clusters []Cluster
	if cfg.InCluster {
		rc, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("kubernetes %q: in-cluster config: %w", cfg.Name, err)
		}
		c, err := clusterFromRest("in-cluster", rc)
		if err != nil {
			return nil, fmt.Errorf("kubernetes %q: %w", cfg.Name, err)
		}
		clusters = append(clusters, c)
	} else {
		ctxs := cfg.Contexts
		if len(ctxs) == 0 {
			ctxs = []string{""} // current context
		}
		for _, cx := range ctxs {
			rules := clientcmd.NewDefaultClientConfigLoadingRules()
			if cfg.Kubeconfig != "" {
				rules.ExplicitPath = cfg.Kubeconfig
			}
			cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: cx})
			rc, err := cc.ClientConfig()
			if err != nil {
				return nil, fmt.Errorf("kubernetes %q: context %q: %w", cfg.Name, cx, err)
			}
			label := cx
			if label == "" {
				raw, err := cc.RawConfig()
				if err != nil {
					return nil, fmt.Errorf("kubernetes %q: read kubeconfig: %w", cfg.Name, err)
				}
				label = raw.CurrentContext
			}
			c, err := clusterFromRest(label, rc)
			if err != nil {
				return nil, fmt.Errorf("kubernetes %q: context %q: %w", cfg.Name, cx, err)
			}
			clusters = append(clusters, c)
		}
	}
	return NewWithClusters(cfg.Name, clusters, log), nil
}

func clusterFromRest(name string, rc *rest.Config) (Cluster, error) {
	cs, err := k8s.NewForConfig(rc)
	if err != nil {
		return Cluster{}, err
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return Cluster{}, err
	}
	return Cluster{Name: name, Client: cs, Dynamic: dyn}, nil
}

// Constructor matches the registry constructor signature.
func Constructor(cfg config.SourceConfig, _ config.ScopeConfig, _ func(string) string, log *slog.Logger) (source.Source, error) {
	return New(cfg, log)
}

// Name returns the configured instance name.
func (s *Source) Name() string { return s.name }

// Type returns "kubernetes".
func (s *Source) Type() string { return "kubernetes" }

// Discover walks every cluster. Any non-skippable failure aborts with an
// error and no partial result.
func (s *Source) Discover(ctx context.Context) (*source.Discovery, error) {
	b := newBuilder(s.name)
	for _, c := range s.clusters {
		if err := s.discoverCluster(ctx, b, c); err != nil {
			return nil, fmt.Errorf("kubernetes %q: cluster %q: %w", s.name, c.Name, err)
		}
	}
	return b.result(), nil
}

// skippable reports whether err on an optional resource kind should be a
// warning rather than a failure.
func skippable(err error) bool {
	return apierrors.IsForbidden(err) || apierrors.IsNotFound(err) || meta.IsNoMatchError(err)
}

func (s *Source) discoverCluster(ctx context.Context, b *builder, c Cluster) error {
	// Services are mandatory.
	var svcs []corev1.Service
	if err := paginate(func(o metav1.ListOptions) (string, error) {
		l, err := c.Client.CoreV1().Services(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		svcs = append(svcs, l.Items...)
		return l.Continue, nil
	}); err != nil {
		return fmt.Errorf("list services: %w", err)
	}

	var nodePortSvcs []corev1.Service
	for _, svc := range svcs {
		switch svc.Spec.Type {
		case corev1.ServiceTypeLoadBalancer:
			s.loadBalancer(b, c.Name, svc)
		case corev1.ServiceTypeNodePort:
			nodePortSvcs = append(nodePortSvcs, svc)
		}
	}
	if len(nodePortSvcs) > 0 {
		if err := s.nodePorts(ctx, b, c, nodePortSvcs); err != nil {
			return err
		}
	}
	if err := s.ingresses(ctx, b, c); err != nil {
		return err
	}
	return s.httpRoutes(ctx, b, c)
}

func paginate(page func(metav1.ListOptions) (string, error)) error {
	opts := metav1.ListOptions{Limit: pageSize}
	for {
		next, err := page(opts)
		if err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		opts.Continue = next
	}
}

func objAttrs(cluster, ns, name string, extra map[string]any) map[string]any {
	a := map[string]any{"cluster": cluster, "namespace": ns, "name": name}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func proto(p corev1.Protocol) string {
	if p == "" {
		return "tcp"
	}
	return strings.ToLower(string(p))
}

func (s *Source) loadBalancer(b *builder, cluster string, svc corev1.Service) {
	ings := svc.Status.LoadBalancer.Ingress
	if len(ings) == 0 {
		s.log.Info("kubernetes: skipping pending LoadBalancer service", "source", s.name, "cluster", cluster, "namespace", svc.Namespace, "name", svc.Name)
		return
	}
	for _, ing := range ings {
		var fromKind model.AssetKind
		var addr string
		switch {
		case ing.IP != "":
			ip, ok := b.ip(ing.IP, objAttrs(cluster, svc.Namespace, svc.Name, nil))
			if !ok {
				s.log.Warn("kubernetes: unparsable LB ip", "ip", ing.IP)
				continue
			}
			fromKind, addr = model.KindIP, ip
		case ing.Hostname != "":
			addr = normalizeHost(ing.Hostname)
			b.asset(model.KindHostname, addr, objAttrs(cluster, svc.Namespace, svc.Name, nil))
			fromKind = model.KindHostname
		default:
			continue
		}
		for _, p := range svc.Spec.Ports {
			key := net.JoinHostPort(addr, strconv.Itoa(int(p.Port))) + "/" + proto(p.Protocol)
			b.asset(model.KindService, key, objAttrs(cluster, svc.Namespace, svc.Name, map[string]any{
				"port": int(p.Port), "protocol": proto(p.Protocol), "service_type": "LoadBalancer", "port_name": p.Name,
			}))
			b.rel(fromKind, addr, model.KindService, key, model.RelExposes)
		}
	}
}

func (s *Source) nodePorts(ctx context.Context, b *builder, c Cluster, svcs []corev1.Service) error {
	type nodeIP struct{ node, ip string }
	var ips []nodeIP
	err := paginate(func(o metav1.ListOptions) (string, error) {
		l, err := c.Client.CoreV1().Nodes().List(ctx, o)
		if err != nil {
			return "", err
		}
		for _, n := range l.Items {
			for _, a := range n.Status.Addresses {
				if a.Type == corev1.NodeExternalIP {
					ips = append(ips, nodeIP{n.Name, a.Address})
				}
			}
		}
		return l.Continue, nil
	})
	if err != nil {
		if apierrors.IsForbidden(err) {
			s.log.Warn("kubernetes: not permitted to list nodes; skipping NodePort services", "source", s.name, "cluster", c.Name, "err", err)
			b.skip(fmt.Sprintf("cluster %s: nodes forbidden, NodePort services skipped", c.Name))
			return nil
		}
		return fmt.Errorf("list nodes: %w", err)
	}
	for _, n := range ips {
		ip, ok := b.ip(n.ip, map[string]any{"cluster": c.Name, "node": n.node})
		if !ok {
			s.log.Warn("kubernetes: unparsable node external ip", "node", n.node, "ip", n.ip)
			continue
		}
		for _, svc := range svcs {
			for _, p := range svc.Spec.Ports {
				if p.NodePort == 0 {
					continue
				}
				key := net.JoinHostPort(ip, strconv.Itoa(int(p.NodePort))) + "/" + proto(p.Protocol)
				b.asset(model.KindService, key, objAttrs(c.Name, svc.Namespace, svc.Name, map[string]any{
					"port": int(p.NodePort), "protocol": proto(p.Protocol), "service_type": "NodePort", "node": n.node, "port_name": p.Name,
				}))
				b.rel(model.KindIP, ip, model.KindService, key, model.RelExposes)
			}
		}
	}
	return nil
}

func (s *Source) ingresses(ctx context.Context, b *builder, c Cluster) error {
	err := paginate(func(o metav1.ListOptions) (string, error) {
		l, err := c.Client.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for _, ing := range l.Items {
			attrs := objAttrs(c.Name, ing.Namespace, ing.Name, map[string]any{"via": "ingress"})
			var hosts []string
			for _, r := range ing.Spec.Rules {
				hosts = append(hosts, r.Host)
			}
			for _, t := range ing.Spec.TLS {
				hosts = append(hosts, t.Hosts...)
			}
			for _, h := range hosts {
				h = normalizeHost(h)
				if h == "" {
					continue
				}
				b.asset(model.KindHostname, h, attrs)
				for _, lb := range ing.Status.LoadBalancer.Ingress {
					switch {
					case lb.IP != "":
						if ip, ok := b.ip(lb.IP, attrs); ok {
							b.rel(model.KindHostname, h, model.KindIP, ip, model.RelResolvesTo)
						}
					case lb.Hostname != "":
						lh := normalizeHost(lb.Hostname)
						b.asset(model.KindHostname, lh, attrs)
						b.rel(model.KindHostname, h, model.KindHostname, lh, model.RelResolvesTo)
					}
				}
			}
		}
		return l.Continue, nil
	})
	if err != nil {
		if skippable(err) {
			s.log.Warn("kubernetes: skipping ingresses", "source", s.name, "cluster", c.Name, "err", err)
			if !apierrors.IsNotFound(err) && !meta.IsNoMatchError(err) { // kind absent is not a gap
				b.skip(fmt.Sprintf("cluster %s: ingresses skipped (access denied)", c.Name))
			}
			return nil
		}
		return fmt.Errorf("list ingresses: %w", err)
	}
	return nil
}

func (s *Source) httpRoutes(ctx context.Context, b *builder, c Cluster) error {
	if c.Dynamic == nil {
		return nil
	}
	err := paginate(func(o metav1.ListOptions) (string, error) {
		l, err := c.Dynamic.Resource(httpRouteGVR).Namespace(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for _, item := range l.Items {
			hosts, _, _ := unstructured.NestedStringSlice(item.Object, "spec", "hostnames")
			attrs := objAttrs(c.Name, item.GetNamespace(), item.GetName(), map[string]any{"via": "httproute"})
			for _, h := range hosts {
				if h = normalizeHost(h); h != "" {
					b.asset(model.KindHostname, h, attrs)
				}
			}
		}
		return l.GetContinue(), nil
	})
	if err != nil {
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			return nil // Gateway API CRDs not installed
		case apierrors.IsForbidden(err):
			s.log.Warn("kubernetes: not permitted to list httproutes", "source", s.name, "cluster", c.Name, "err", err)
			b.skip(fmt.Sprintf("cluster %s: httproutes skipped (access denied)", c.Name))
			return nil
		}
		return fmt.Errorf("list httproutes: %w", err)
	}
	return nil
}

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

type builder struct {
	source   string
	assets   map[string]*model.AssetInput
	order    []string
	rels     map[model.RelationInput]bool
	relOrder []model.RelationInput
	partial  []string
}

// skip records a feature that could not be read (access denied), making the
// discovery partial.
func (b *builder) skip(reason string) { b.partial = append(b.partial, reason) }

func newBuilder(src string) *builder {
	return &builder{source: src, assets: map[string]*model.AssetInput{}, rels: map[model.RelationInput]bool{}}
}

func (b *builder) asset(kind model.AssetKind, key string, attrs map[string]any) {
	id := string(kind) + "\x00" + key
	if _, ok := b.assets[id]; ok {
		return // first sighting keeps its traceability attrs
	}
	cp := make(map[string]any, len(attrs))
	for k, v := range attrs {
		cp[k] = v
	}
	b.assets[id] = &model.AssetInput{Kind: kind, Key: key, Source: b.source, Attrs: cp}
	b.order = append(b.order, id)
}

// ip normalises and registers an IP asset, returning its canonical key.
func (b *builder) ip(raw string, attrs map[string]any) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	key := addr.Unmap().String()
	b.asset(model.KindIP, key, attrs)
	return key, true
}

func (b *builder) rel(fk model.AssetKind, fkey string, tk model.AssetKind, tkey string, t model.RelationType) {
	r := model.RelationInput{FromKind: fk, FromKey: fkey, ToKind: tk, ToKey: tkey, Type: t}
	if !b.rels[r] {
		b.rels[r] = true
		b.relOrder = append(b.relOrder, r)
	}
}

func (b *builder) result() *source.Discovery {
	d := &source.Discovery{Relations: b.relOrder, Partial: len(b.partial) > 0, PartialReasons: b.partial}
	for _, id := range b.order {
		d.Assets = append(d.Assets, *b.assets[id])
	}
	return d
}
