package assessmentjob

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var ErrRefused = errors.New("assessment job refused")
var digestImage = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:\-]*@sha256:[a-f0-9]{64}$`)
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type PlanInput struct {
	ID                                    string
	Tool                                  Tool
	Targets                               []Target
	ProxyToken, UploadToken, RuntimeToken string
	CAPEM                                 []byte
	RuntimeIP                             netip.Addr
}

// Plan is private control-plane material. It contains scoped credentials and
// must never be returned through the public API or operational logs.
type Plan struct {
	ServiceAccount *corev1.ServiceAccount
	Baseline       *networkingv1.NetworkPolicy
	Policies       []*networkingv1.NetworkPolicy
	Secret         *corev1.Secret
	ConfigMap      *corev1.ConfigMap
	Job            *batchv1.Job
	RuntimePod     *corev1.Pod
}

func normalizeSettings(settings Settings) (Settings, error) {
	if settings.BrokerPort == 0 {
		settings.BrokerPort = 9092
	}
	if settings.MaxSessions == 0 {
		settings.MaxSessions = 16
	}
	if settings.MaxRunning == 0 {
		settings.MaxRunning = 2
	}
	if settings.SessionDuration == 0 {
		settings.SessionDuration = 15 * time.Minute
	}
	if settings.Limits.MaxRequests == 0 {
		settings.Limits.MaxRequests = 500
	}
	if settings.Limits.MaxRequestBytes == 0 {
		settings.Limits.MaxRequestBytes = 8 << 20
	}
	if settings.Limits.MaxResponseBytes == 0 {
		settings.Limits.MaxResponseBytes = 32 << 20
	}
	settings.Limits.Timeout = settings.SessionDuration
	if !settings.NetworkPolicyEnforced || !dnsLabel.MatchString(settings.Namespace) || len(settings.Namespace) > 63 || settings.Namespace == "default" || strings.HasPrefix(settings.Namespace, "kube-") ||
		!settings.BrokerIP.IsValid() || !settings.BrokerIP.IsGlobalUnicast() || settings.BrokerIP.IsLoopback() || settings.BrokerIP.IsLinkLocalUnicast() || settings.BrokerIP.Zone() != "" || settings.BrokerPort < 1 || settings.BrokerPort > 65535 ||
		settings.MaxSessions < 1 || settings.MaxSessions > 16 || settings.MaxRunning < 1 || settings.MaxRunning > 2 || settings.MaxRunning > settings.MaxSessions ||
		settings.SessionDuration < time.Second || settings.SessionDuration > 15*time.Minute || !digestImage.MatchString(settings.UploaderImage) ||
		settings.Limits.MaxRequests < 1 || settings.Limits.MaxRequests > 10000 || settings.Limits.MaxRequestBytes < 1 || settings.Limits.MaxRequestBytes > 64<<20 || settings.Limits.MaxResponseBytes < 1 || settings.Limits.MaxResponseBytes > 64<<20 {
		return Settings{}, fmt.Errorf("%w: invalid containment settings", ErrRefused)
	}
	return settings, nil
}

// BuildPlan renders only bounded, tokenless, non-root resources. Its Targets
// must already be verified against current inventory and scope by Manager.
// Creating these objects does not prove the CNI enforces their policies.
func BuildPlan(ctx context.Context, settings Settings, input PlanInput) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	settings, err := normalizeSettings(settings)
	if err != nil {
		return nil, err
	}
	if len(input.ID) > 36 || !dnsLabel.MatchString(input.ID) || len(input.Targets) == 0 || len(input.Targets) > 16 ||
		len(input.ProxyToken) < 32 || len(input.UploadToken) < 32 || len(input.RuntimeToken) < 32 || input.ProxyToken == input.UploadToken || input.RuntimeToken == input.ProxyToken || input.RuntimeToken == input.UploadToken ||
		!digestImage.MatchString(settings.Images[input.Tool]) {
		return nil, fmt.Errorf("%w: invalid session plan", ErrRefused)
	}
	if input.Tool != ToolZAP && input.Tool != ToolZGrab2 && input.Tool != ToolStrix {
		return nil, fmt.Errorf("%w: unsupported tool", ErrRefused)
	}
	name := "deckard-assessment-" + input.ID
	meta := func(suffix, component string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name + suffix, Namespace: settings.Namespace, Labels: labels(input.ID, component)}
	}
	falseValue, trueValue := false, true
	uid := int64(65532)
	plan := &Plan{
		ServiceAccount: &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: ServiceAccountName, Namespace: settings.Namespace, Labels: map[string]string{ManagedLabel: ManagedValue}}, AutomountServiceAccountToken: &falseValue},
		Baseline:       &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: DefaultDenyPolicyName, Namespace: settings.Namespace, Labels: map[string]string{ManagedLabel: ManagedValue}}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}}},
		Secret:         &corev1.Secret{ObjectMeta: meta("-tokens", "credentials"), Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"proxy-token": []byte(input.ProxyToken), "upload-token": []byte(input.UploadToken), "runtime-token": []byte(input.RuntimeToken)}},
		ConfigMap:      &corev1.ConfigMap{ObjectMeta: meta("-request", "request"), Data: map[string]string{"proxy-ca.pem": string(input.CAPEM)}},
	}
	execution := ExecutionRequest{SchemaVersion: 1, SessionID: input.ID, Tool: input.Tool, MaxTurns: 30, TimeoutSeconds: int64(settings.SessionDuration / time.Second), MaxRequests: settings.Limits.MaxRequests, MaxOutputBytes: 32 << 20}
	for _, target := range input.Targets {
		if target.AssetID <= 0 || target.Port == 0 || len(target.Addresses) == 0 || len(target.Addresses) > 16 {
			return nil, fmt.Errorf("%w: invalid fixed target", ErrRefused)
		}
		parsed, err := url.Parse(target.Origin)
		if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
			return nil, fmt.Errorf("%w: invalid target origin", ErrRefused)
		}
		port := parsed.Port()
		if port == "" {
			if parsed.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		actualPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil || actualPort != uint64(target.Port) {
			return nil, fmt.Errorf("%w: target origin port mismatch", ErrRefused)
		}
		for _, address := range target.Addresses {
			if !address.IsValid() || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.Zone() != "" || address.Unmap() == settings.BrokerIP.Unmap() {
				return nil, fmt.Errorf("%w: invalid target address", ErrRefused)
			}
		}
		execution.Targets = append(execution.Targets, target.Origin)
	}
	if input.Tool == ToolZGrab2 {
		execution.FixedTargets = input.Targets
	}
	if input.Tool == ToolStrix {
		execution.MaxOutputBytes = 4 << 20
	}
	encoded, err := json.Marshal(execution)
	if err != nil {
		return nil, fmt.Errorf("encode assessment request: %w", err)
	}
	plan.ConfigMap.Data["assessment.json"] = string(encoded)
	volumes := []corev1.Volume{
		{Name: "request", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: plan.ConfigMap.Name}}}},
		{Name: "report", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: quantity("64Mi")}}},
		{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: quantity("256Mi")}}},
		{Name: "uploader-tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: quantity("32Mi")}}},
	}
	for _, key := range []string{"proxy-token", "upload-token", "runtime-token"} {
		mode := int32(0440)
		volumes = append(volumes, corev1.Volume{Name: key, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: plan.Secret.Name, Items: []corev1.KeyToPath{{Key: key, Path: key, Mode: &mode}}}}})
	}
	security := func() *corev1.SecurityContext {
		return &corev1.SecurityContext{RunAsUser: &uid, RunAsGroup: &uid, RunAsNonRoot: &trueValue, AllowPrivilegeEscalation: &falseValue, ReadOnlyRootFilesystem: &trueValue, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}
	}
	baseContainer := func(component, image string) corev1.Container {
		tmpVolume := "tmp"
		uploader := component == "uploader"
		if uploader {
			// ZAP writes its proxy and optional target authentication into private
			// work files. Never expose that directory to the report identity.
			tmpVolume = "uploader-tmp"
		}
		return corev1.Container{Name: component, Image: image, ImagePullPolicy: corev1.PullIfNotPresent, SecurityContext: security(), Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("256Mi")}, Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("2Gi")}}, VolumeMounts: []corev1.VolumeMount{{Name: "request", MountPath: "/request", ReadOnly: true}, {Name: "report", MountPath: "/report", ReadOnly: uploader}, {Name: tmpVolume, MountPath: "/tmp"}}, Env: []corev1.EnvVar{{Name: "HOME", Value: "/tmp/home"}, {Name: "TMPDIR", Value: "/tmp"}, {Name: "AWS_EC2_METADATA_DISABLED", Value: "true"}}}
	}
	brokerURL := "http://" + net.JoinHostPort(settings.BrokerIP.String(), strconv.Itoa(int(settings.BrokerPort)))
	scanner := baseContainer("scanner", settings.Images[input.Tool])
	scanner.Command = []string{"/usr/local/bin/deckard"}
	scanner.Args = []string{"assessment", "execute", "--tool", string(input.Tool), "--request", "/request/assessment.json", "--report", "/report/report.json", "--done", "/report/done"}
	if input.Tool == ToolZAP {
		scanner.VolumeMounts = append(scanner.VolumeMounts, corev1.VolumeMount{Name: "proxy-token", MountPath: "/secrets/proxy", ReadOnly: true})
		scanner.Env = append(scanner.Env, corev1.EnvVar{Name: "DECKARD_PROXY_URL", Value: brokerURL}, corev1.EnvVar{Name: "DECKARD_PROXY_TOKEN_FILE", Value: "/secrets/proxy/proxy-token"}, corev1.EnvVar{Name: "DECKARD_PROXY_CA_FILE", Value: "/request/proxy-ca.pem"})
		if settings.ZAPAuthSecretName != "" {
			if !dnsLabel.MatchString(settings.ZAPAuthSecretName) || len(settings.ZAPAuthSecretName) > 63 {
				return nil, fmt.Errorf("%w: invalid ZAP auth secret reference", ErrRefused)
			}
			mode := int32(0440)
			volumes = append(volumes, corev1.Volume{Name: "zap-auth", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: settings.ZAPAuthSecretName, Items: []corev1.KeyToPath{{Key: "auth.json", Path: "auth.json", Mode: &mode}}}}})
			scanner.VolumeMounts = append(scanner.VolumeMounts, corev1.VolumeMount{Name: "zap-auth", MountPath: "/secrets/zap-auth", ReadOnly: true})
			scanner.Env = append(scanner.Env, corev1.EnvVar{Name: "DECKARD_ZAP_AUTH_FILE", Value: "/secrets/zap-auth/auth.json"})
		}
	}
	uploader := baseContainer("uploader", settings.UploaderImage)
	uploader.Command = []string{"/usr/local/bin/deckard"}
	uploader.Args = []string{"assessment", "upload", "--report", "/report/report.json", "--done", "/report/done", "--url", brokerURL + "/v1/report", "--token-file", "/secrets/upload/upload-token", "--session", input.ID, "--tool", string(input.Tool)}
	uploader.VolumeMounts = append(uploader.VolumeMounts, corev1.VolumeMount{Name: "upload-token", MountPath: "/secrets/upload", ReadOnly: true})
	deadline := int64(settings.SessionDuration / time.Second)
	zero, ttl := int32(0), int32(300)
	pod := corev1.PodSpec{ServiceAccountName: ServiceAccountName, AutomountServiceAccountToken: &falseValue, RestartPolicy: corev1.RestartPolicyNever, SecurityContext: &corev1.PodSecurityContext{RunAsUser: &uid, RunAsGroup: &uid, RunAsNonRoot: &trueValue, FSGroup: &uid, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}, Containers: []corev1.Container{scanner, uploader}, Volumes: volumes, DNSPolicy: corev1.DNSNone, DNSConfig: &corev1.PodDNSConfig{Nameservers: []string{"127.0.0.1"}}, EnableServiceLinks: &falseValue}
	plan.Job = &batchv1.Job{ObjectMeta: meta("", "runner"), Spec: batchv1.JobSpec{BackoffLimit: &zero, ActiveDeadlineSeconds: &deadline, TTLSecondsAfterFinished: &ttl, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels(input.ID, "runner")}, Spec: pod}}}
	egress := []networkingv1.NetworkPolicyEgressRule{ipRule(settings.BrokerIP, settings.BrokerPort)}
	if input.Tool == ToolZGrab2 {
		for _, target := range input.Targets {
			for _, address := range target.Addresses {
				egress = append(egress, ipRule(address, int32(target.Port)))
			}
		}
	}
	plan.Policies = []*networkingv1.NetworkPolicy{{ObjectMeta: meta("-egress", "policy"), Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: labels(input.ID, "runner")}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}, Egress: egress}}}
	if input.Tool == ToolStrix {
		if err := addStrixPlan(plan, settings, input, baseContainer); err != nil {
			return nil, err
		}
	}
	return plan, nil
}

func labels(id, component string) map[string]string {
	return map[string]string{ManagedLabel: ManagedValue, ComponentLabel: component, SessionLabel: id}
}
func quantity(value string) *resource.Quantity { q := resource.MustParse(value); return &q }
func ipRule(address netip.Addr, port int32) networkingv1.NetworkPolicyEgressRule {
	protocol := corev1.ProtocolTCP
	number := intstr.FromInt32(port)
	return networkingv1.NetworkPolicyEgressRule{To: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen()).String()}}}, Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &number}}}
}

func addStrixPlan(plan *Plan, settings Settings, input PlanInput, container func(string, string) corev1.Container) error {
	endpoint, err := url.Parse(settings.ModelGatewayURL)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Hostname() != settings.ModelGatewayIP.String() || settings.Model == "" || !digestImage.MatchString(settings.StrixRuntimeImage) || !safeModelGateway(settings.ModelGatewayIP) || settings.ModelGatewayPort < 1 || settings.ModelGatewayPort > 65535 {
		return fmt.Errorf("%w: Strix requires an approved model gateway and runtime image", ErrRefused)
	}
	port := endpoint.Port()
	if port == "" {
		if endpoint.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if port != strconv.Itoa(int(settings.ModelGatewayPort)) {
		return fmt.Errorf("%w: model gateway port mismatch", ErrRefused)
	}
	runtime := container("runtime", settings.StrixRuntimeImage)
	runtime.Command = []string{"python", "/opt/deckard/strix_adapter.py", "serve-runtime", "--listen", "0.0.0.0:9093"}
	runtime.Ports = []corev1.ContainerPort{{Name: "runtime-rpc", ContainerPort: 9093, Protocol: corev1.ProtocolTCP}}
	runtime.ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(9093)}}, PeriodSeconds: 2, TimeoutSeconds: 1, FailureThreshold: 15}
	runtime.VolumeMounts = append(runtime.VolumeMounts, corev1.VolumeMount{Name: "proxy-token", MountPath: "/secrets/proxy", ReadOnly: true}, corev1.VolumeMount{Name: "runtime-token", MountPath: "/secrets/runtime", ReadOnly: true})
	runtime.Env = append(runtime.Env, corev1.EnvVar{Name: "DECKARD_ASSESSMENT_ID", Value: input.ID}, corev1.EnvVar{Name: "DECKARD_RUNTIME_TOKEN_FILE", Value: "/secrets/runtime/runtime-token"}, corev1.EnvVar{Name: "DECKARD_PROXY_TOKEN_FILE", Value: "/secrets/proxy/proxy-token"}, corev1.EnvVar{Name: "DECKARD_PROXY_CA_FILE", Value: "/request/proxy-ca.pem"}, corev1.EnvVar{Name: "DECKARD_PROXY_URL", Value: "http://" + net.JoinHostPort(settings.BrokerIP.String(), strconv.Itoa(int(settings.BrokerPort)))})
	pod := plan.Job.Spec.Template.Spec.DeepCopy()
	pod.Containers = []corev1.Container{runtime}
	pod.ActiveDeadlineSeconds = plan.Job.Spec.ActiveDeadlineSeconds
	plan.RuntimePod = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: plan.Job.Name + "-runtime", Namespace: settings.Namespace, Labels: labels(input.ID, "runtime")}, Spec: *pod}
	scanner := &plan.Job.Spec.Template.Spec.Containers[0]
	scanner.VolumeMounts = append(scanner.VolumeMounts, corev1.VolumeMount{Name: "runtime-token", MountPath: "/secrets/runtime", ReadOnly: true})
	scanner.Env = append(scanner.Env, corev1.EnvVar{Name: "DECKARD_RUNTIME_TOKEN_FILE", Value: "/secrets/runtime/runtime-token"}, corev1.EnvVar{Name: "STRIX_LLM", Value: settings.Model}, corev1.EnvVar{Name: "LLM_API_BASE", Value: settings.ModelGatewayURL})
	if settings.ModelSecretName != "" {
		if !dnsLabel.MatchString(settings.ModelSecretName) || settings.ModelSecretKey == "" {
			return fmt.Errorf("%w: invalid model secret reference", ErrRefused)
		}
		scanner.Env = append(scanner.Env, corev1.EnvVar{Name: "LLM_API_KEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: settings.ModelSecretName}, Key: settings.ModelSecretKey}}})
	}
	if input.RuntimeIP.IsValid() {
		scanner.Env = append(scanner.Env, corev1.EnvVar{Name: "DECKARD_RUNTIME_URL", Value: "http://" + net.JoinHostPort(input.RuntimeIP.String(), "9093")})
	}
	protocol := corev1.ProtocolTCP
	rpc := intstr.FromInt32(9093)
	peer := networkingv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{MatchLabels: labels(input.ID, "runtime")}}
	// Containers share this Pod's network grants: uploader can also reach the
	// runtime/model gateway. Only uploader receives the report credential;
	// scanner receives no upload credential or assessment proxy grant.
	plan.Policies[0].Spec.Egress = append(plan.Policies[0].Spec.Egress, networkingv1.NetworkPolicyEgressRule{To: []networkingv1.NetworkPolicyPeer{peer}, Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &rpc}}}, ipRule(settings.ModelGatewayIP, settings.ModelGatewayPort))
	plan.Policies = append(plan.Policies, &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: plan.Job.Name + "-runtime", Namespace: settings.Namespace, Labels: labels(input.ID, "policy")}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: labels(input.ID, "runtime")}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}, Egress: []networkingv1.NetworkPolicyEgressRule{ipRule(settings.BrokerIP, settings.BrokerPort)}, Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: labels(input.ID, "runner")}}}, Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &rpc}}}}}})
	return nil
}

// A model endpoint is an explicit operator grant, but never a cloud metadata,
// reserved or IPv6 translation endpoint. Keep these exclusions aligned with
// scope's never-owned address classes; private LAN/cluster gateways stay valid.
func safeModelGateway(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, raw := range []string{"0.0.0.0/8", "100.100.100.200/32", "240.0.0.0/4", "fd00:ec2::/64", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "::/96", "::ffff:0:0:0/96"} {
		if netip.MustParsePrefix(raw).Contains(address) {
			return false
		}
	}
	return true
}
