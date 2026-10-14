package kubernetes

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/distribution/reference"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/chainseer-xyz/deckard/internal/model"
)

type serviceExposure struct{ namespace, name, key string }
type namespacedName struct{ namespace, name string }
type namespacedUID struct{ namespace, uid string }

// discoverTopology records API-reported metadata only. In particular, PodIPs,
// ClusterIPs, endpoint addresses, annotations and environment variables never
// become scan targets or inventory attributes.
func (s *Source) discoverTopology(ctx context.Context, b *builder, c Cluster, services []corev1.Service, ingresses []networkingv1.Ingress, routes []unstructured.Unstructured, exposures []serviceExposure) error {
	identity := s.clusterIdentity(ctx, b, c)
	if err := ctx.Err(); err != nil {
		return err
	}
	if identity == "" {
		return nil
	}
	serviceKeys := make(map[namespacedName]string, len(services))
	serviceObjects := make(map[namespacedName]corev1.Service, len(services))
	for _, svc := range services {
		key := resourceKey(identity, svc.Namespace, "service", svc.Name)
		attrs := topologyAttrs(c.Name, identity, svc.Namespace, svc.Name, "Service", string(svc.UID))
		attrs["service_type"] = string(svc.Spec.Type)
		b.asset(model.KindCloudResource, key, attrs)
		serviceKeys[namespacedName{svc.Namespace, svc.Name}] = key
		serviceObjects[namespacedName{svc.Namespace, svc.Name}] = svc
	}
	for _, exposed := range exposures {
		if key := serviceKeys[namespacedName{exposed.namespace, exposed.name}]; key != "" {
			b.rel(model.KindService, exposed.key, model.KindCloudResource, key, model.RelTargets)
		}
	}
	linkIngressBackends(b, ingresses, serviceObjects, serviceKeys)
	linkHTTPRouteBackends(b, routes, serviceObjects, serviceKeys)

	var pods []corev1.Pod
	if err := paginate(func(opts metav1.ListOptions) (string, error) {
		page, err := c.Client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return "", err
		}
		pods = append(pods, page.Items...)
		return page.Continue, nil
	}); err != nil {
		b.skip(fmt.Sprintf("cluster %s: topology pods skipped (%v)", c.Name, err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	podKeys := make(map[namespacedUID]string, len(pods))
	unresolvedImages := 0
	for _, pod := range pods {
		if pod.UID == "" {
			b.skip(fmt.Sprintf("cluster %s: Pod %s/%s has no UID", c.Name, pod.Namespace, pod.Name))
			continue
		}
		key := resourceKey(identity, pod.Namespace, "pod", string(pod.UID))
		attrs := topologyAttrs(c.Name, identity, pod.Namespace, pod.Name, "Pod", string(pod.UID))
		attrs["phase"] = string(pod.Status.Phase)
		attrs["containers"] = containerReferences(pod)
		b.asset(model.KindWorkload, key, attrs)
		podKeys[namespacedUID{pod.Namespace, string(pod.UID)}] = key
		for _, owner := range pod.OwnerReferences {
			if owner.Controller == nil || !*owner.Controller || owner.UID == "" || !workloadController(owner.Kind) {
				continue
			}
			ownerKey := resourceKey(identity, pod.Namespace, strings.ToLower(owner.Kind), string(owner.UID))
			ownerAttrs := topologyAttrs(c.Name, identity, pod.Namespace, owner.Name, owner.Kind, string(owner.UID))
			ownerAttrs["discovered_via"] = "owner_reference"
			b.asset(model.KindWorkload, ownerKey, ownerAttrs)
			b.rel(model.KindWorkload, ownerKey, model.KindWorkload, key, model.RelContains)
		}
		unresolvedImages += recordRuntimeImages(b, pod, key)
	}
	if unresolvedImages > 0 {
		// The current source contract has one completeness bit. Unknown
		// runtime manifests therefore conservatively preserve the whole source
		// snapshot's prior registrations, not just its image edges.
		b.skip(fmt.Sprintf("cluster %s: %d runtime image identities unresolved; digest relationships incomplete", c.Name, unresolvedImages))
	}

	var slices []discoveryv1.EndpointSlice
	if err := paginate(func(opts metav1.ListOptions) (string, error) {
		page, err := c.Client.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return "", err
		}
		slices = append(slices, page.Items...)
		return page.Continue, nil
	}); err != nil {
		b.skip(fmt.Sprintf("cluster %s: topology endpointslices skipped (%v)", c.Name, err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	linkServicePods(b, services, serviceKeys, pods, podKeys, slices)
	return nil
}

func (s *Source) clusterIdentity(ctx context.Context, b *builder, c Cluster) string {
	ns, err := c.Client.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err == nil && ns.UID != "" {
		return "uid:" + string(ns.UID)
	}
	if err == nil {
		err = fmt.Errorf("namespace has no UID")
	}
	b.skip(fmt.Sprintf("cluster %s: immutable topology cluster identity unavailable (%v); using configured source/context identity", c.Name, err))
	// A fallback must be explicit and unambiguous within this source. Never
	// merge two clusters just because both use the same context label.
	count := 0
	for _, cluster := range s.clusters {
		if cluster.Name == c.Name {
			count++
		}
	}
	if c.Name == "" || count != 1 {
		b.skip(fmt.Sprintf("cluster %s: topology skipped because fallback cluster identity is ambiguous", c.Name))
		return ""
	}
	return "configured:" + url.PathEscape(s.name) + "/" + url.PathEscape(c.Name)
}

func resourceKey(cluster, namespace, kind, identity string) string {
	return "k8s://cluster/" + url.PathEscape(cluster) + "/" + url.PathEscape(namespace) + "/" + kind + "/" + url.PathEscape(identity)
}

func topologyAttrs(cluster, identity, namespace, name, kind, uid string) map[string]any {
	return objAttrs(cluster, namespace, name, map[string]any{"provider": "kubernetes", "cluster_id": identity, "k8s_kind": kind, "uid": uid})
}

func workloadController(kind string) bool {
	switch kind {
	case "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicationController":
		return true
	}
	return false
}

func containerReferences(pod corev1.Pod) []map[string]any {
	var refs []map[string]any
	add := func(name, image, kind string) {
		item := map[string]any{"name": name, "type": kind}
		// Kubernetes accepts arbitrary image strings before a runtime tries
		// pulling them. Do not retain malformed URLs or credential-like input.
		if len(image) <= 512 {
			if _, err := reference.ParseNormalizedNamed(image); err == nil {
				item["image"] = image
			}
		}
		refs = append(refs, item)
	}
	for _, container := range pod.Spec.Containers {
		add(container.Name, container.Image, "container")
	}
	for _, container := range pod.Spec.InitContainers {
		add(container.Name, container.Image, "init")
	}
	for _, container := range pod.Spec.EphemeralContainers {
		add(container.Name, container.Image, "ephemeral")
	}
	return refs
}

func recordRuntimeImages(b *builder, pod corev1.Pod, podKey string) int {
	statuses := append([]corev1.ContainerStatus(nil), pod.Status.ContainerStatuses...)
	statuses = append(statuses, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)
	reported := make(map[string]bool, len(statuses))
	unknown := 0
	for _, status := range statuses {
		reported[status.Name] = true
		// Bare runtime sha256 IDs can be config digests. Only a named,
		// repository-qualified runtime ImageID establishes pullable identity.
		digest, valid := model.ContainerImageKey(status.ImageID)
		if !strings.Contains(status.ImageID, "@") || !valid {
			if status.ImageID != "" || pod.Status.Phase == corev1.PodRunning {
				unknown++
			}
			continue
		}
		b.asset(model.KindContainerImage, digest, map[string]any{"digest": digest})
		b.rel(model.KindWorkload, podKey, model.KindContainerImage, digest, model.RelRuns)
	}
	if pod.Status.Phase == corev1.PodRunning {
		missing := func(name string) {
			if !reported[name] {
				unknown++
			}
		}
		for _, container := range pod.Spec.Containers {
			missing(container.Name)
		}
		for _, container := range pod.Spec.InitContainers {
			missing(container.Name)
		}
		for _, container := range pod.Spec.EphemeralContainers {
			missing(container.Name)
		}
	}
	return unknown
}

func linkServicePods(b *builder, services []corev1.Service, serviceKeys map[namespacedName]string, pods []corev1.Pod, podKeys map[namespacedUID]string, slices []discoveryv1.EndpointSlice) {
	podsByNamespace := map[string][]corev1.Pod{}
	for _, pod := range pods {
		podsByNamespace[pod.Namespace] = append(podsByNamespace[pod.Namespace], pod)
	}
	byService := map[namespacedName][]discoveryv1.EndpointSlice{}
	for _, slice := range slices {
		if name := slice.Labels[discoveryv1.LabelServiceName]; name != "" {
			ref := namespacedName{slice.Namespace, name}
			byService[ref] = append(byService[ref], slice)
		}
	}
	for _, svc := range services {
		ref := namespacedName{svc.Namespace, svc.Name}
		serviceKey := serviceKeys[ref]
		if serviceKey == "" {
			continue
		}
		if endpoints := byService[ref]; len(endpoints) > 0 {
			for _, slice := range endpoints {
				for _, endpoint := range slice.Endpoints {
					target := endpoint.TargetRef
					if target == nil || target.Kind != "Pod" || target.UID == "" || (target.APIVersion != "" && target.APIVersion != "v1") || (target.Namespace != "" && target.Namespace != svc.Namespace) {
						continue
					}
					if key := podKeys[namespacedUID{svc.Namespace, string(target.UID)}]; key != "" {
						b.rel(model.KindCloudResource, serviceKey, model.KindWorkload, key, model.RelTargets)
					}
				}
			}
			continue
		}
		// An empty selector is not "all Pods". Service selectors are confined
		// to the Service namespace and only describe a relationship, not ownership.
		if len(svc.Spec.Selector) == 0 || svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		selector := labels.SelectorFromSet(svc.Spec.Selector)
		for _, pod := range podsByNamespace[svc.Namespace] {
			if selector.Matches(labels.Set(pod.Labels)) {
				if key := podKeys[namespacedUID{pod.Namespace, string(pod.UID)}]; key != "" {
					b.rel(model.KindCloudResource, serviceKey, model.KindWorkload, key, model.RelTargets)
				}
			}
		}
	}
}

func linkIngressBackends(b *builder, ingresses []networkingv1.Ingress, services map[namespacedName]corev1.Service, keys map[namespacedName]string) {
	for _, ingress := range ingresses {
		for _, rule := range ingress.Spec.Rules {
			host := normalizeHost(rule.Host)
			if host == "" || rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				if backend := path.Backend.Service; backend != nil {
					linkIngressService(b, host, ingress.Namespace, backend, services, keys)
				}
			}
		}
		if backend := ingress.Spec.DefaultBackend; backend != nil && backend.Service != nil {
			for _, rule := range ingress.Spec.Rules {
				linkIngressService(b, normalizeHost(rule.Host), ingress.Namespace, backend.Service, services, keys)
			}
			for _, tls := range ingress.Spec.TLS {
				for _, host := range tls.Hosts {
					linkIngressService(b, normalizeHost(host), ingress.Namespace, backend.Service, services, keys)
				}
			}
		}
	}
}

func linkIngressService(b *builder, host, namespace string, backend *networkingv1.IngressServiceBackend, services map[namespacedName]corev1.Service, keys map[namespacedName]string) {
	if host == "" {
		return
	}
	ref := namespacedName{namespace, backend.Name}
	svc, ok := services[ref]
	if !ok {
		return
	}
	for _, port := range svc.Spec.Ports {
		if (backend.Port.Name != "" && backend.Port.Name == port.Name) || (backend.Port.Number > 0 && backend.Port.Number == port.Port) {
			b.rel(model.KindHostname, host, model.KindCloudResource, keys[ref], model.RelTargets)
			return
		}
	}
}

func linkHTTPRouteBackends(b *builder, routes []unstructured.Unstructured, services map[namespacedName]corev1.Service, keys map[namespacedName]string) {
	for _, route := range routes {
		hosts, _, _ := unstructured.NestedStringSlice(route.Object, "spec", "hostnames")
		rules, _, err := unstructured.NestedSlice(route.Object, "spec", "rules")
		if err != nil {
			b.skip(fmt.Sprintf("HTTPRoute %s/%s: malformed backend rules", route.GetNamespace(), route.GetName()))
			continue
		}
		for _, value := range rules {
			rule, ok := value.(map[string]any)
			if !ok {
				continue
			}
			refs, _, err := unstructured.NestedSlice(rule, "backendRefs")
			if err != nil {
				b.skip(fmt.Sprintf("HTTPRoute %s/%s: malformed backend references", route.GetNamespace(), route.GetName()))
				continue
			}
			for _, value := range refs {
				ref, ok := value.(map[string]any)
				if !ok {
					continue
				}
				backend, namespace, err := httpServiceBackend(ref)
				if err != nil {
					b.skip(fmt.Sprintf("HTTPRoute %s/%s: malformed Service backend (%v)", route.GetNamespace(), route.GetName(), err))
					continue
				}
				if backend == nil {
					continue
				}
				if namespace != "" && namespace != route.GetNamespace() {
					b.skip(fmt.Sprintf("HTTPRoute %s/%s: cross-namespace backend %s requires ReferenceGrant verification; skipped", route.GetNamespace(), route.GetName(), namespace))
					continue
				}
				for _, host := range hosts {
					linkIngressService(b, normalizeHost(host), route.GetNamespace(), backend, services, keys)
				}
			}
		}
	}
}

func httpServiceBackend(ref map[string]any) (*networkingv1.IngressServiceBackend, string, error) {
	values := make(map[string]string, 4)
	for _, field := range []string{"kind", "group", "namespace", "name"} {
		value, _, err := unstructured.NestedString(ref, field)
		if err != nil {
			return nil, "", fmt.Errorf("invalid %s", field)
		}
		values[field] = value
	}
	if values["group"] != "" || (values["kind"] != "" && values["kind"] != "Service") {
		return nil, "", nil
	}
	if weight, found, err := unstructured.NestedInt64(ref, "weight"); err != nil || weight < 0 {
		return nil, "", fmt.Errorf("invalid weight")
	} else if found && weight == 0 {
		return nil, "", nil
	}
	port, found, err := unstructured.NestedInt64(ref, "port")
	if err != nil || !found || port <= 0 || port > 65535 || values["name"] == "" {
		return nil, "", fmt.Errorf("missing or invalid name/port")
	}
	backend := &networkingv1.IngressServiceBackend{Name: values["name"], Port: networkingv1.ServiceBackendPort{Number: int32(port)}}
	return backend, values["namespace"], nil
}
