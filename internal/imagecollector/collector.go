// Package imagecollector scans immutable images reported by live Kubernetes
// containers. A failed, ambiguous or changing snapshot never certifies absence.
package imagecollector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/trivy"
	"github.com/chainseer-xyz/deckard/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	MaxPods      = 10000
	MaxNodes     = 1000
	MaxImages    = 64
	MaxDuration  = 45 * time.Minute
	ScanDuration = 2 * time.Minute
)

// Inventory deliberately excludes mutating clients and unrelated API groups.
type Inventory interface {
	Pods(string) typedcore.PodInterface
	Nodes() typedcore.NodeInterface
}

type Target struct{ Reference, Digest, Platform string }
type Scanner interface {
	Scan(context.Context, Target) ([]byte, error)
}
type Options struct {
	Namespaces      []string
	AllNamespaces   bool
	ClusterScope    string
	RegistryAuthDir string
	WithScanner     Scanner
}

func ValidateOptions(o Options) error {
	if !regexp.MustCompile(`^k8s:uid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}:runtime-images$`).MatchString(o.ClusterScope) {
		return fmt.Errorf("--cluster-scope must be k8s:uid:<immutable cluster UUID>:runtime-images")
	}
	if (len(o.Namespaces) == 0) == !o.AllNamespaces {
		return fmt.Errorf("choose explicit --namespaces or --all-namespaces, never both")
	}
	if len(o.Namespaces) > 128 {
		return fmt.Errorf("at most 128 explicit namespaces are supported")
	}
	for _, ns := range o.Namespaces {
		if len(validation.IsDNS1123Label(ns)) > 0 {
			return fmt.Errorf("invalid namespace")
		}
	}
	return nil
}

// Collect returns one locally validated envelope, or nil on any uncertainty.
// It never truncates, guesses a mutable tag, posts a partial subset or inherits
// cloud credentials. Callers must keep the scanner and uploader separate.
func Collect(ctx context.Context, client Inventory, options Options) (*ingest.Request, error) {
	if err := ValidateOptions(options); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("kubernetes inventory is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	observed := time.Now().UTC()
	before, targets, err := snapshot(ctx, client, options)
	if err != nil {
		return nil, err
	}
	scanner := options.WithScanner
	if scanner == nil {
		command, err := NewCommandScanner(options.RegistryAuthDir)
		if err != nil {
			return nil, err
		}
		defer command.Close()
		scanner = command
	}
	// Namespace selection can change while the credential scope stays constant.
	// Only an explicit cluster-wide inventory can certify absence in that scope.
	req := &ingest.Request{Tool: trivy.Tool, Scope: options.ClusterScope, Complete: options.AllNamespaces, ObservedAt: &observed, Findings: []ingest.Finding{}}
	artifacts := map[string]ingest.Artifact{}
	findings := map[string]ingest.Finding{}
	relations := map[string]model.RelationInput{}
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		scanCtx, stop := context.WithTimeout(ctx, ScanDuration)
		raw, scanErr := scanner.Scan(scanCtx, target)
		stop()
		if scanErr != nil {
			return nil, fmt.Errorf("immutable image scan failed")
		}
		if len(raw) > trivy.MaxInputBytes {
			return nil, fmt.Errorf("native image report exceeds limit")
		}
		report, err := trivy.ParseReport(raw, ingest.ParseOptions{Scope: options.ClusterScope})
		if err != nil {
			return nil, fmt.Errorf("invalid native image report: %w", err)
		}
		var identity struct {
			Metadata struct{ RepoDigests []string }
		}
		if err := json.Unmarshal(raw, &identity); err != nil {
			return nil, fmt.Errorf("invalid native image identity")
		}
		for _, ref := range identity.Metadata.RepoDigests {
			key, ok := model.ContainerImageKey(ref)
			if !ok || !strings.Contains(ref, "@") || key != target.Digest {
				return nil, fmt.Errorf("native report manifest does not match requested runtime manifest")
			}
		}
		for _, artifact := range report.Artifacts {
			key := string(artifact.Kind) + "\x00" + artifact.Key
			if previous, ok := artifacts[key]; ok && artifact.Kind == model.KindContainerImage {
				artifact.Attrs = mergeImageAttrs(previous.Attrs, artifact.Attrs)
			}
			artifacts[key] = artifact
		}
		for _, finding := range report.Findings {
			previous, ok := findings[finding.Key]
			if !ok || finding.Severity.Rank() > previous.Severity.Rank() || finding.Severity == previous.Severity && jsonLess(finding, previous) {
				findings[finding.Key] = finding
			}
		}
		for _, relation := range report.Relations {
			encoded, _ := json.Marshal(relation)
			relations[string(encoded)] = relation
		}
		if len(artifacts) > ingest.MaxArtifacts || len(findings) > ingest.MaxFindings || len(relations) > ingest.MaxArtifactRelations {
			return nil, fmt.Errorf("aggregate image graph exceeds ingest cardinality limit")
		}
	}
	after, _, err := snapshot(ctx, client, options)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(before, after) {
		return nil, fmt.Errorf("runtime image inventory changed during collection")
	}
	for _, key := range sortedKeys(artifacts) {
		req.Artifacts = append(req.Artifacts, artifacts[key])
	}
	for _, key := range sortedKeys(findings) {
		req.Findings = append(req.Findings, findings[key])
	}
	for _, key := range sortedKeys(relations) {
		req.Relations = append(req.Relations, relations[key])
	}
	if _, err := Encode(req); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return req, nil
}

func sortedKeys[V any](items map[string]V) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func jsonLess(a, b ingest.Finding) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Compare(left, right) < 0
}
func mergeImageAttrs(a, b map[string]any) map[string]any {
	repos := map[string]bool{}
	for _, attrs := range []map[string]any{a, b} {
		if values, ok := attrs["repositories"].([]string); ok {
			for _, value := range values {
				repos[value] = true
			}
		}
	}
	b["repositories"] = sortedKeys(repos)
	return b
}

// Encode applies the server's validation and size bounds before publication.
func Encode(req *ingest.Request) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("missing image request")
	}
	if problems := ingest.Validate(req, ingest.Options{Now: time.Now()}); len(problems) > 0 {
		return nil, fmt.Errorf("invalid image request: %s", ingest.Summary(problems))
	}
	encoded, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode image request: %w", err)
	}
	if len(encoded) > ingest.MaxBodyBytes {
		return nil, fmt.Errorf("aggregate image report exceeds 10 MiB")
	}
	return encoded, nil
}

func snapshot(ctx context.Context, client Inventory, o Options) ([]string, []Target, error) {
	nodes := map[string]corev1.NodeSystemInfo{}
	nodeCount, nodePages := 0, 0
	continuation := ""
	seen := map[string]bool{}
	for {
		nodePages++
		if nodePages > MaxNodes+1 {
			return nil, nil, fmt.Errorf("runtime node pagination exceeds request bound")
		}
		page, err := client.Nodes().List(ctx, metav1.ListOptions{Limit: 500, Continue: continuation})
		if err != nil {
			return nil, nil, fmt.Errorf("list runtime nodes failed")
		}
		nodeCount += len(page.Items)
		if nodeCount > MaxNodes {
			return nil, nil, fmt.Errorf("runtime node inventory exceeds 1000 nodes")
		}
		for _, n := range page.Items {
			nodes[n.Name] = n.Status.NodeInfo
		}
		if page.Continue == "" {
			break
		}
		if seen[page.Continue] {
			return nil, nil, fmt.Errorf("runtime node pagination stalled")
		}
		seen[page.Continue] = true
		continuation = page.Continue
	}
	namespaces := slices.Clone(o.Namespaces)
	sort.Strings(namespaces)
	namespaces = slices.Compact(namespaces)
	if o.AllNamespaces {
		namespaces = []string{""}
	}
	fingerprint := []string{}
	targets := map[string]Target{}
	podCount := 0
	for _, ns := range namespaces {
		podPages := 0
		continuation = ""
		seen = map[string]bool{}
		for {
			podPages++
			if podPages > MaxPods+1 {
				return nil, nil, fmt.Errorf("runtime pod pagination exceeds request bound")
			}
			page, err := client.Pods(ns).List(ctx, metav1.ListOptions{Limit: 500, Continue: continuation})
			if err != nil {
				return nil, nil, fmt.Errorf("list runtime pods failed")
			}
			podCount += len(page.Items)
			if podCount > MaxPods {
				return nil, nil, fmt.Errorf("runtime pod inventory exceeds 10000 pods")
			}
			for _, p := range page.Items {
				if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
					continue
				}
				if p.UID == "" || p.Name == "" || p.Namespace == "" || len(p.Spec.Containers) == 0 {
					return nil, nil, fmt.Errorf("live pod metadata is incomplete")
				}
				info, ok := nodes[p.Spec.NodeName]
				if !ok || info.OperatingSystem != "linux" || !slices.Contains([]string{"amd64", "arm64"}, info.Architecture) {
					return nil, nil, fmt.Errorf("live pod has unknown or unsupported node platform")
				}
				groups := []struct {
					kind     string
					names    []string
					images   map[string]string
					statuses []corev1.ContainerStatus
				}{
					{kind: "container", statuses: p.Status.ContainerStatuses, images: map[string]string{}},
					{kind: "init", statuses: p.Status.InitContainerStatuses, images: map[string]string{}},
					{kind: "ephemeral", statuses: p.Status.EphemeralContainerStatuses, images: map[string]string{}},
				}
				for _, c := range p.Spec.Containers {
					groups[0].names = append(groups[0].names, c.Name)
					groups[0].images[c.Name] = c.Image
				}
				for _, c := range p.Spec.InitContainers {
					groups[1].names = append(groups[1].names, c.Name)
					groups[1].images[c.Name] = c.Image
				}
				for _, c := range p.Spec.EphemeralContainers {
					groups[2].names = append(groups[2].names, c.Name)
					groups[2].images[c.Name] = c.Image
				}
				for _, group := range groups {
					statuses := map[string]corev1.ContainerStatus{}
					for _, status := range group.statuses {
						statuses[status.Name] = status
					}
					if len(statuses) != len(group.statuses) || len(statuses) != len(group.names) {
						return nil, nil, fmt.Errorf("live container status inventory is incomplete or ambiguous")
					}
					for _, name := range group.names {
						status, ok := statuses[name]
						if !ok {
							return nil, nil, fmt.Errorf("live container has no runtime image identity")
						}
						if status.ImageID == "" && status.State.Waiting != nil && status.State.Waiting.Reason == "PodInitializing" && status.State.Running == nil && status.State.Terminated == nil {
							// An init-container collector necessarily sees its uploader
							// waiting. It is not a runtime image yet. Never scan its tag
							// or certify it; require the precise pending state/spec to
							// stay unchanged across both inventories instead.
							fingerprint = append(fingerprint, strings.Join([]string{"not-started", p.Namespace, p.Name, string(p.UID), p.Spec.NodeName, group.kind, name, group.images[name], "PodInitializing", "linux/" + info.Architecture}, "\x00"))
							continue
						}
						ref := strings.TrimPrefix(status.ImageID, "docker-pullable://")
						key, ok := model.ContainerImageKey(ref)
						if !ok || !strings.Contains(ref, "@") || strings.Contains(ref, "://") {
							return nil, nil, fmt.Errorf("live container image is not a repository-qualified immutable manifest")
						}
						target := Target{Reference: ref, Digest: key, Platform: "linux/" + info.Architecture}
						targetKey := key + "\x00" + target.Platform
						if previous, exists := targets[targetKey]; !exists || ref < previous.Reference {
							targets[targetKey] = target
						}
						fingerprint = append(fingerprint, strings.Join([]string{p.Namespace, p.Name, string(p.UID), p.Spec.NodeName, group.kind, name, ref, target.Platform}, "\x00"))
						if len(targets) > MaxImages {
							return nil, nil, fmt.Errorf("runtime inventory exceeds 64 immutable images/platforms")
						}
					}
				}
			}
			if page.Continue == "" {
				break
			}
			if seen[page.Continue] {
				return nil, nil, fmt.Errorf("runtime pod pagination stalled")
			}
			seen[page.Continue] = true
			continuation = page.Continue
		}
	}
	sort.Strings(fingerprint)
	ordered := make([]Target, 0, len(targets))
	for _, key := range sortedKeys(targets) {
		ordered = append(ordered, targets[key])
	}
	return fingerprint, ordered, nil
}
