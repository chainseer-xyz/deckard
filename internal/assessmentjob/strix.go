package assessmentjob

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
)

func (m *Manager) startStrix(state *sessionState, plan *Plan) {
	ctx, cancel := context.WithTimeout(state.ctx, time.Minute)
	defer cancel()
	selector := "metadata.name=" + plan.RuntimePod.Name
	lw := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = selector
			return m.kube.CoreV1().Pods(m.settings.Namespace).List(ctx, options)
		},
		WatchFuncWithContext: func(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = selector
			return m.kube.CoreV1().Pods(m.settings.Namespace).Watch(ctx, options)
		},
	}
	event, err := watchtools.UntilWithSync(ctx, cache.ToListWatcherWithWatchListSemantics(lw, m.kube), &corev1.Pod{}, nil, func(event watch.Event) (bool, error) {
		pod, ok := event.Object.(*corev1.Pod)
		if !ok || pod.Name != plan.RuntimePod.Name {
			return false, nil
		}
		if string(pod.UID) != state.runtimeUID || event.Type == watch.Deleted || pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
			return false, fmt.Errorf("runtime unavailable")
		}
		address, err := netip.ParseAddr(pod.Status.PodIP)
		if err != nil || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return false, nil
		}
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil || event == nil {
		m.finalize(state, false, "runtime_start_failed")
		return
	}
	pod, ok := event.Object.(*corev1.Pod)
	if !ok {
		m.finalize(state, false, "runtime_start_failed")
		return
	}
	if _, err := m.targets(state.ctx, state.session.AssetIDs); err != nil {
		m.finalize(state, false, "target_ownership_changed")
		return
	}
	if err := lockLifecycle(state.ctx, state); err != nil {
		m.finalize(state, false, "runtime_start_expired")
		return
	}
	remaining := int64(time.Until(state.session.ExpiresAt) / time.Second)
	if remaining < 1 {
		unlockLifecycle(state)
		m.finalize(state, false, "runtime_start_expired")
		return
	}
	job := plan.Job.DeepCopy()
	job.Spec.ActiveDeadlineSeconds = &remaining
	job.Spec.Template.Spec.Containers[0].Env = append(job.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{Name: "DECKARD_RUNTIME_URL", Value: "http://" + net.JoinHostPort(pod.Status.PodIP, "9093")})
	created, err := m.kube.BatchV1().Jobs(m.settings.Namespace).Create(state.ctx, job, metav1.CreateOptions{})
	if err == nil {
		state.jobUID = string(created.UID)
		state.resources = append(state.resources, resourceRef{"jobs", created.Name, created.UID})
		err = m.attachOwners(state.ctx, state)
		if err == nil {
			m.mu.Lock()
			state.session.Status = "running"
			m.mu.Unlock()
		}
	}
	unlockLifecycle(state)
	if err != nil {
		m.finalize(state, false, "controller_job_start_failed")
		return
	}
	m.watchJob(state)
}
