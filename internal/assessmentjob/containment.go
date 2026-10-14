package assessmentjob

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (m *Manager) install(ctx context.Context, state *sessionState, plan *Plan) error {
	if err := lockLifecycle(ctx, state); err != nil {
		return err
	}
	defer unlockLifecycle(state)
	if err := m.verifyNamespace(ctx); err != nil {
		return err
	}
	sa, err := m.kube.CoreV1().ServiceAccounts(m.settings.Namespace).Get(ctx, ServiceAccountName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		sa, err = m.kube.CoreV1().ServiceAccounts(m.settings.Namespace).Create(ctx, plan.ServiceAccount, metav1.CreateOptions{})
	}
	if err != nil || sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
		return fmt.Errorf("%w: dedicated service account is not tokenless", ErrRefused)
	}
	for name := range sa.Annotations {
		if strings.Contains(name, "eks.amazonaws.com") || strings.Contains(name, "iam.gke.io") || strings.Contains(name, "azure.workload.identity") {
			return fmt.Errorf("%w: runner service account has cloud identity", ErrRefused)
		}
	}
	baseline, err := m.kube.NetworkingV1().NetworkPolicies(m.settings.Namespace).Get(ctx, DefaultDenyPolicyName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		baseline, err = m.kube.NetworkingV1().NetworkPolicies(m.settings.Namespace).Create(ctx, plan.Baseline, metav1.CreateOptions{})
	}
	if err != nil || !reflect.DeepEqual(baseline.Spec, plan.Baseline.Spec) {
		return fmt.Errorf("%w: default deny policy unavailable or changed", ErrRefused)
	}
	policies, err := m.kube.NetworkingV1().NetworkPolicies(m.settings.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("%w: cannot verify namespace egress", ErrRefused)
	}
	for _, policy := range policies.Items {
		if policy.Name == DefaultDenyPolicyName {
			continue
		}
		selector := policy.Spec.PodSelector
		if policy.Labels[ManagedLabel] != ManagedValue || selector.MatchLabels[SessionLabel] == "" || len(selector.MatchExpressions) != 0 || selector.MatchLabels[SessionLabel] == state.session.ID {
			return fmt.Errorf("%w: namespace contains unexpected additive network policy", ErrRefused)
		}
	}
	for _, policy := range plan.Policies {
		created, err := m.kube.NetworkingV1().NetworkPolicies(m.settings.Namespace).Create(ctx, policy, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("%w: session network policy creation failed", ErrRefused)
		}
		state.resources = append(state.resources, resourceRef{"networkpolicies", created.Name, created.UID})
	}
	secret, err := m.kube.CoreV1().Secrets(m.settings.Namespace).Create(ctx, plan.Secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("%w: scoped credentials creation failed", ErrRefused)
	}
	state.resources = append(state.resources, resourceRef{"secrets", secret.Name, secret.UID})
	configMap, err := m.kube.CoreV1().ConfigMaps(m.settings.Namespace).Create(ctx, plan.ConfigMap, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("%w: request creation failed", ErrRefused)
	}
	state.resources = append(state.resources, resourceRef{"configmaps", configMap.Name, configMap.UID})
	if plan.RuntimePod != nil {
		pod, err := m.kube.CoreV1().Pods(m.settings.Namespace).Create(ctx, plan.RuntimePod, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("%w: runtime pod creation failed", ErrRefused)
		}
		state.runtimeUID = string(pod.UID)
		state.resources = append(state.resources, resourceRef{"pods", pod.Name, pod.UID})
		return nil
	}
	job, err := m.kube.BatchV1().Jobs(m.settings.Namespace).Create(ctx, plan.Job, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("%w: assessment job creation failed", ErrRefused)
	}
	state.jobUID = string(job.UID)
	state.resources = append(state.resources, resourceRef{"jobs", job.Name, job.UID})
	return m.attachOwners(ctx, state)
}

func (m *Manager) verifyNamespace(ctx context.Context) error {
	namespace, err := m.kube.CoreV1().Namespaces().Get(ctx, m.settings.Namespace, metav1.GetOptions{})
	if err != nil || namespace.Labels["deckard.io/assessment-isolated"] != "true" {
		return fmt.Errorf("%w: namespace is not explicitly assessment-isolated", ErrRefused)
	}
	return nil
}

func (m *Manager) attachOwners(ctx context.Context, state *sessionState) error {
	controller := true
	owner := metav1.OwnerReference{APIVersion: "batch/v1", Kind: "Job", Name: state.session.JobName, UID: types.UID(state.jobUID), Controller: &controller}
	for _, resource := range state.resources {
		// UID is immutable: a same-name replacement cannot inherit this
		// session's owner reference between creation and attachment.
		patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"uid": resource.uid, "ownerReferences": []metav1.OwnerReference{owner}}})
		if err != nil {
			return fmt.Errorf("encode assessment resource ownership: %w", err)
		}
		switch resource.kind {
		case "pods":
			_, err = m.kube.CoreV1().Pods(m.settings.Namespace).Patch(ctx, resource.name, types.MergePatchType, patch, metav1.PatchOptions{})
		case "secrets":
			_, err = m.kube.CoreV1().Secrets(m.settings.Namespace).Patch(ctx, resource.name, types.MergePatchType, patch, metav1.PatchOptions{})
		case "configmaps":
			_, err = m.kube.CoreV1().ConfigMaps(m.settings.Namespace).Patch(ctx, resource.name, types.MergePatchType, patch, metav1.PatchOptions{})
		case "networkpolicies":
			_, err = m.kube.NetworkingV1().NetworkPolicies(m.settings.Namespace).Patch(ctx, resource.name, types.MergePatchType, patch, metav1.PatchOptions{})
		}
		if err != nil {
			return fmt.Errorf("%w: resource ownership attachment failed", ErrRefused)
		}
	}
	return nil
}

func terminalJob(job *batchv1.Job) bool {
	for _, condition := range job.Status.Conditions {
		if condition.Status == corev1.ConditionTrue && (condition.Type == batchv1.JobComplete || condition.Type == batchv1.JobFailed) {
			return true
		}
	}
	return false
}

// lockLifecycle serializes creation/owner attachment against cleanup without
// requiring shutdown to wait beyond its shared deadline.
func lockLifecycle(ctx context.Context, state *sessionState) error {
	select {
	case state.lifecycle <- struct{}{}:
		if err := ctx.Err(); err != nil {
			unlockLifecycle(state)
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func unlockLifecycle(state *sessionState) { <-state.lifecycle }

func (m *Manager) markCleanupPending(state *sessionState) {
	m.mu.Lock()
	state.session.CleanupPending = true
	state.session.Status = "failed"
	state.session.Reason = "cleanup_pending"
	state.doneOnce.Do(func() { close(state.done) })
	m.mu.Unlock()
	slog.Warn("assessment resource cleanup incomplete", "session_id", state.session.ID)
}

func (m *Manager) cleanup(ctx context.Context, state *sessionState) error {
	if err := lockLifecycle(ctx, state); err != nil {
		m.markCleanupPending(state)
		return err
	}
	defer unlockLifecycle(state)
	failed := false
	remaining := make([]resourceRef, 0, len(state.resources))
	for index := len(state.resources) - 1; index >= 0; index-- {
		resource := state.resources[index]
		options := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &resource.uid}}
		var err error
		switch resource.kind {
		case "jobs":
			policy := metav1.DeletePropagationBackground
			options.PropagationPolicy = &policy
			err = m.kube.BatchV1().Jobs(m.settings.Namespace).Delete(ctx, resource.name, options)
		case "pods":
			err = m.kube.CoreV1().Pods(m.settings.Namespace).Delete(ctx, resource.name, options)
		case "secrets":
			err = m.kube.CoreV1().Secrets(m.settings.Namespace).Delete(ctx, resource.name, options)
		case "configmaps":
			err = m.kube.CoreV1().ConfigMaps(m.settings.Namespace).Delete(ctx, resource.name, options)
		case "networkpolicies":
			err = m.kube.NetworkingV1().NetworkPolicies(m.settings.Namespace).Delete(ctx, resource.name, options)
		}
		if err != nil && !apierrors.IsNotFound(err) {
			failed = true
			remaining = append(remaining, resource)
		}
	}
	// Preserve original creation order for a later cleanup retry.
	for left, right := 0, len(remaining)-1; left < right; left, right = left+1, right-1 {
		remaining[left], remaining[right] = remaining[right], remaining[left]
	}
	state.resources = remaining
	if failed {
		m.markCleanupPending(state)
		return fmt.Errorf("assessment cleanup pending")
	}
	m.mu.Lock()
	state.session.CleanupPending = false
	m.mu.Unlock()
	return nil
}
