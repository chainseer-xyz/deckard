package assessmentjob

import (
	"context"
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
)

func (m *Manager) watchJob(state *sessionState) {
	selector := "metadata.name=" + state.session.JobName
	lw := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = selector
			return m.kube.BatchV1().Jobs(m.settings.Namespace).List(ctx, options)
		},
		WatchFuncWithContext: func(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = selector
			return m.kube.BatchV1().Jobs(m.settings.Namespace).Watch(ctx, options)
		},
	}
	// Propagate the client's watch-list capability. Fake clients explicitly
	// lack initial-event/bookmark semantics; production clients retain them.
	watcher := cache.ToListWatcherWithWatchListSemantics(lw, m.kube)
	event, err := watchtools.UntilWithSync(state.ctx, watcher, &batchv1.Job{}, nil, func(event watch.Event) (bool, error) {
		job, ok := event.Object.(*batchv1.Job)
		if !ok || job.Name != state.session.JobName {
			return false, nil
		}
		if string(job.UID) != state.jobUID || event.Type == watch.Deleted {
			return false, fmt.Errorf("assessment Job identity lost")
		}
		return terminalJob(job), nil
	})
	success := false
	reason := "job_failed_or_expired"
	if err == nil && event != nil {
		if job, ok := event.Object.(*batchv1.Job); ok {
			for _, condition := range job.Status.Conditions {
				if condition.Type == batchv1.JobComplete && condition.Status == corev1.ConditionTrue {
					success = true
					reason = ""
				}
			}
		}
	}
	m.finalize(state, success, reason)
}

func (m *Manager) finalize(state *sessionState, jobSuccess bool, reason string) {
	m.mu.Lock()
	if state.finalizing || state.finished {
		m.mu.Unlock()
		return
	}
	state.finalizing = true
	delete(m.proxyTokens, state.input.ProxyToken)
	delete(m.uploadTokens, state.input.UploadToken)
	data := state.report
	state.report = nil
	session := cloneSession(state.session)
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()
	if err := state.proxy.Finish(ctx); err != nil {
		jobSuccess = false
		reason = "network_policy_refused_or_incomplete"
	}
	if len(data) == 0 {
		jobSuccess = false
		reason = "report_missing"
	}
	complete := jobSuccess
	if _, err := m.targets(ctx, state.session.AssetIDs); err != nil {
		complete = false
		reason = "target_ownership_changed"
	}
	coverageUnproven := false
	switch state.session.Tool {
	case ToolZAP, ToolZGrab2, ToolStrix:
		coverageUnproven = true
		if reason == "" {
			switch state.session.Tool {
			case ToolZAP:
				reason = "scanner_coverage_unproven"
			case ToolZGrab2:
				reason = "http_observations_only"
			case ToolStrix:
				reason = "agent_report_is_additive"
			}
		}
	}
	if len(data) > 0 && ctx.Err() == nil {
		if err := m.complete(ctx, Completion{Session: session, Targets: cloneTargets(state.input.Targets), Format: string(state.session.Tool), Data: data, Complete: complete, Reason: reason}); err != nil {
			complete = false
			reason = "report_ingest_failed"
		}
	}
	if m.ctx.Err() != nil {
		complete = false
		reason = "manager_stopped"
	}
	state.cancel()
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	cleanupErr := m.cleanup(cleanupCtx, state)
	cleanupCancel()
	m.mu.Lock()
	state.session.Status = "complete"
	if !complete || coverageUnproven {
		state.session.Status = "partial"
	}
	if len(data) == 0 || reason == "report_ingest_failed" || reason == "manager_stopped" {
		state.session.Status = "failed"
	}
	state.session.Reason = reason
	if cleanupErr != nil || state.session.CleanupPending {
		state.session.Status = "failed"
		state.session.Reason = "cleanup_pending"
	}
	state.finalizing = false
	state.finished = true
	state.doneOnce.Do(func() { close(state.done) })
	m.mu.Unlock()
}
