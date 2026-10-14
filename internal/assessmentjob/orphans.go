package assessmentjob

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// cleanupOrphans is a bounded pre-start sweep, not an autonomous scheduler.
// Kubernetes garbage collection owns resources attached to a live Job. This
// sweep covers the small crash window before a Job owner could be attached.
func (m *Manager) cleanupOrphans(ctx context.Context) error {
	jobs, err := m.kube.BatchV1().Jobs(m.settings.Namespace).List(ctx, metav1.ListOptions{LabelSelector: ManagedLabel + "=" + ManagedValue, Limit: 1000})
	if err != nil || jobs.Continue != "" {
		return fmt.Errorf("%w: cannot bound orphan job lookup", ErrRefused)
	}
	live := make(map[string]string, len(jobs.Items))
	for _, job := range jobs.Items {
		live[job.Name] = string(job.UID)
	}
	m.mu.RLock()
	current := make(map[string]bool, len(m.sessions))
	for id := range m.sessions {
		current[id] = true
	}
	m.mu.RUnlock()
	cutoff := time.Now().Add(-15 * time.Minute)
	orphan := func(meta metav1.ObjectMeta, kind string) bool {
		id := meta.Labels[SessionLabel]
		if meta.Labels[ManagedLabel] != ManagedValue || current[id] || meta.CreationTimestamp.IsZero() || !meta.CreationTimestamp.Time.Before(cutoff) {
			return false
		}
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id {
			return false
		}
		base := "deckard-assessment-" + id
		suffix := ""
		switch kind {
		case "secrets":
			suffix = "-tokens"
		case "configmaps":
			suffix = "-request"
		case "pods":
			suffix = "-runtime"
		case "networkpolicies":
			if strings.HasSuffix(meta.Name, "-runtime") {
				suffix = "-runtime"
			} else {
				suffix = "-egress"
			}
		}
		if meta.Name != base+suffix {
			return false
		}
		if _, exists := live[base]; exists {
			return false
		}
		for _, owner := range meta.OwnerReferences {
			if owner.Kind != "Job" || owner.APIVersion != "batch/v1" || owner.Name != base {
				return false
			}
			if uid, exists := live[owner.Name]; exists && uid == string(owner.UID) {
				return false
			}
		}
		return true
	}
	options := metav1.ListOptions{LabelSelector: ManagedLabel + "=" + ManagedValue, Limit: 1000}
	secrets, err := m.kube.CoreV1().Secrets(m.settings.Namespace).List(ctx, options)
	if err != nil || secrets.Continue != "" {
		return fmt.Errorf("%w: cannot bound orphan credential lookup", ErrRefused)
	}
	for _, secret := range secrets.Items {
		if orphan(secret.ObjectMeta, "secrets") {
			if err := m.kube.CoreV1().Secrets(m.settings.Namespace).Delete(ctx, secret.Name, orphanDeleteOptions(secret.ObjectMeta)); err != nil {
				return fmt.Errorf("%w: orphan cleanup failed", ErrRefused)
			}
		}
	}
	configs, err := m.kube.CoreV1().ConfigMaps(m.settings.Namespace).List(ctx, options)
	if err != nil || configs.Continue != "" {
		return fmt.Errorf("%w: cannot bound orphan request lookup", ErrRefused)
	}
	for _, config := range configs.Items {
		if orphan(config.ObjectMeta, "configmaps") {
			if err := m.kube.CoreV1().ConfigMaps(m.settings.Namespace).Delete(ctx, config.Name, orphanDeleteOptions(config.ObjectMeta)); err != nil {
				return fmt.Errorf("%w: orphan cleanup failed", ErrRefused)
			}
		}
	}
	pods, err := m.kube.CoreV1().Pods(m.settings.Namespace).List(ctx, options)
	if err != nil || pods.Continue != "" {
		return fmt.Errorf("%w: cannot bound orphan runtime lookup", ErrRefused)
	}
	for _, pod := range pods.Items {
		if orphan(pod.ObjectMeta, "pods") {
			if err := m.kube.CoreV1().Pods(m.settings.Namespace).Delete(ctx, pod.Name, orphanDeleteOptions(pod.ObjectMeta)); err != nil {
				return fmt.Errorf("%w: orphan cleanup failed", ErrRefused)
			}
		}
	}
	policies, err := m.kube.NetworkingV1().NetworkPolicies(m.settings.Namespace).List(ctx, options)
	if err != nil || policies.Continue != "" {
		return fmt.Errorf("%w: cannot bound orphan policy lookup", ErrRefused)
	}
	for _, policy := range policies.Items {
		if orphan(policy.ObjectMeta, "networkpolicies") {
			if err := m.kube.NetworkingV1().NetworkPolicies(m.settings.Namespace).Delete(ctx, policy.Name, orphanDeleteOptions(policy.ObjectMeta)); err != nil {
				return fmt.Errorf("%w: orphan cleanup failed", ErrRefused)
			}
		}
	}
	return nil
}

func orphanDeleteOptions(meta metav1.ObjectMeta) metav1.DeleteOptions {
	options := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{}}
	if meta.UID != "" {
		uid := meta.UID
		options.Preconditions.UID = &uid
	}
	if meta.ResourceVersion != "" {
		version := meta.ResourceVersion
		options.Preconditions.ResourceVersion = &version
	}
	return options
}
