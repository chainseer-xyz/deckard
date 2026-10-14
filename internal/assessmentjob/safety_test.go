package assessmentjob_test

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	k8stesting "k8s.io/client-go/testing"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestManagerRecoversClosedJobWatchByRelisting(t *testing.T) {
	kube := fakeKube()
	var closed atomic.Bool
	var relisted atomic.Int32
	kube.PrependReactor("list", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
		if closed.Load() {
			relisted.Add(1)
		}
		return false, nil, nil
	})
	kube.PrependWatchReactor("jobs", func(action k8stesting.Action) (bool, watch.Interface, error) {
		if !closed.CompareAndSwap(false, true) {
			return false, nil, nil
		}
		resource := schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}
		object, err := kube.Tracker().List(resource, schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "Job"}, action.GetNamespace())
		if err != nil {
			return true, nil, err
		}
		job := object.(*batchv1.JobList).Items[0].DeepCopy()
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		if err := kube.Tracker().Update(resource, job, action.GetNamespace()); err != nil {
			return true, nil, err
		}
		stream := watch.NewRaceFreeFake()
		stream.Stop()
		return true, stream, nil
	})
	m, err := assessmentjob.NewManager(settings(), assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, managerGuard(t), kube, func(context.Context, assessmentjob.Completion) error {
		t.Error("missing report must not reconcile")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	session, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := m.Wait(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != "report_missing" || relisted.Load() == 0 {
		t.Fatalf("closed stream did not recover terminalJob: status=%#v relists=%d", result, relisted.Load())
	}
}

func TestManagerRefusesAdditiveNamespacePolicy(t *testing.T) {
	kube := fakeKube()
	_, err := kube.NetworkingV1().NetworkPolicies("deckard-assessment").Create(context.Background(), &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-all", Namespace: "deckard-assessment"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, Egress: []networkingv1.NetworkPolicyEgressRule{{}}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := assessmentjob.NewManager(settings(), assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, managerGuard(t), kube, func(context.Context, assessmentjob.Completion) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}}); err == nil {
		t.Fatal("additive allow-all policy bypassed containment gate")
	}
	jobs, err := kube.BatchV1().Jobs("deckard-assessment").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(jobs.Items) != 0 {
		t.Fatal("Job started despite unexpected additive policy")
	}
}

func TestPreStartCleansOnlyOldVerifiedOrphanResources(t *testing.T) {
	kube := fakeKube()
	old := metav1.NewTime(time.Now().Add(-time.Hour))
	fresh := metav1.NewTime(time.Now())
	ids := []string{"4d0d5071-7819-4e66-916d-bbd614c3a3f0", "4d0d5072-7819-4e66-916d-bbd614c3a3f0", "4d0d5073-7819-4e66-916d-bbd614c3a3f0", "4d0d5074-7819-4e66-916d-bbd614c3a3f0"}
	for index, id := range ids {
		created := old
		if index == 1 {
			created = fresh
		}
		name := "deckard-assessment-" + id + "-tokens"
		if index == 2 {
			name = "foreign-name"
		}
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "deckard-assessment", CreationTimestamp: created, Labels: map[string]string{assessmentjob.ManagedLabel: assessmentjob.ManagedValue, assessmentjob.SessionLabel: id}}}
		if _, err := kube.CoreV1().Secrets("deckard-assessment").Create(context.Background(), secret, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := kube.BatchV1().Jobs("deckard-assessment").Create(context.Background(), &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "deckard-assessment-" + ids[3], Namespace: "deckard-assessment", Labels: map[string]string{assessmentjob.ManagedLabel: assessmentjob.ManagedValue}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := assessmentjob.NewManager(settings(), assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, managerGuard(t), kube, func(context.Context, assessmentjob.Completion) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.CoreV1().Secrets("deckard-assessment").Get(context.Background(), "deckard-assessment-"+ids[0]+"-tokens", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("old verified orphan was not removed")
	}
	for index, name := range []string{"deckard-assessment-" + ids[1] + "-tokens", "foreign-name", "deckard-assessment-" + ids[3] + "-tokens"} {
		if _, err := kube.CoreV1().Secrets("deckard-assessment").Get(context.Background(), name, metav1.GetOptions{}); err != nil {
			t.Fatalf("protected fixture%d was removed: %v", index, err)
		}
	}
}

func TestStrixPlanKeepsModelCredentialOutOfRuntime(t *testing.T) {
	bound := settings()
	bound.ModelGatewayIP = netip.MustParseAddr("10.20.30.60")
	bound.ModelGatewayURL = "http://10.20.30.60:8000/v1"
	bound.ModelGatewayPort = 8000
	bound.Model = "openai/local-model"
	bound.ModelSecretName = "assessment-model"
	bound.ModelSecretKey = "api-key"
	plan, err := assessmentjob.BuildPlan(context.Background(), bound, assessmentjob.PlanInput{ID: "4d0d5075-7819-4e66-916d-bbd614c3a3f0", Tool: assessmentjob.ToolStrix, Targets: []assessmentjob.Target{{AssetID: 1, Origin: "https://app.example.com:443", Port: 443, Addresses: []netip.Addr{netip.MustParseAddr("10.20.30.40")}}}, ProxyToken: "proxy-token-at-least32bytes-long-value", UploadToken: "upload-token-at-least32bytes-long-value", RuntimeToken: "runtime-token-at-least32bytes-long-value"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, env := range plan.Job.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "LLM_API_KEY" {
			found = env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil && env.ValueFrom.SecretKeyRef.Name == "assessment-model"
		}
	}
	if !found {
		t.Fatal("controller modelsecret reference missing")
	}
	for _, container := range plan.RuntimePod.Spec.Containers {
		for _, env := range container.Env {
			if env.Name == "LLM_API_KEY" || env.Name == "LLM_API_BASE" || env.Name == "STRIX_LLM" || env.ValueFrom != nil {
				t.Fatal("runtime inherited model or Kubernetes credential")
			}
		}
		for _, mount := range container.VolumeMounts {
			if mount.Name == "upload-token" {
				t.Fatal("runtime can fabricate uploaded result authority")
			}
		}
	}
	if len(plan.Policies[1].Spec.Egress) != 1 || plan.Policies[1].Spec.Egress[0].To[0].IPBlock.CIDR != "10.20.30.50/32" {
		t.Fatal("runtime may reach something besides enforcing broker")
	}
}

func TestStrixControllerWaitsForSeparateReadyRuntime(t *testing.T) {
	bound := settings()
	bound.ModelGatewayIP = netip.MustParseAddr("10.20.30.60")
	bound.ModelGatewayURL = "http://10.20.30.60:8000/v1"
	bound.ModelGatewayPort = 8000
	bound.Model = "openai/local-model"
	kube := fakeKube()
	created := make(chan struct{}, 1)
	watchStarted := make(chan struct{}, 1)
	completion := make(chan assessmentjob.Completion, 1)
	kube.PrependReactor("create", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) { created <- struct{}{}; return false, nil, nil })
	kube.PrependWatchReactor("jobs", func(k8stesting.Action) (bool, watch.Interface, error) {
		select {
		case watchStarted <- struct{}{}:
		default:
		}
		return false, nil, nil
	})
	m, err := assessmentjob.NewManager(bound, assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, managerGuard(t), kube, func(_ context.Context, c assessmentjob.Completion) error { completion <- c; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	session, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolStrix, AssetIDs: []int64{1}})
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != "starting" {
		t.Fatalf("controller started before runtime: %#v", session)
	}
	select {
	case <-created:
		t.Fatal("controller Job created before runtime readiness")
	default:
	}
	pod, err := kube.CoreV1().Pods(bound.Namespace).Get(context.Background(), session.JobName+"-runtime", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.Status.PodIP = "10.20.30.70"
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if _, err := kube.CoreV1().Pods(bound.Namespace).UpdateStatus(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-created:
	case <-time.After(2 * time.Second):
		t.Fatal("ready runtime did not start controller Job")
	}
	select {
	case <-watchStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("controller Job was not fully initialized for observation")
	}
	secret, err := kube.CoreV1().Secrets(bound.Namespace).Get(context.Background(), session.JobName+"-tokens", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(secret.OwnerReferences) != 1 || secret.OwnerReferences[0].Name != session.JobName {
		t.Fatal("runtime companions lack native Job garbage collection owner")
	}
	if code := submit(t, m, session, string(secret.Data["upload-token"])); code != 202 {
		t.Fatalf("report submission %d", code)
	}
	endJob(t, kube, session, true)
	if result := wait(t, m, session.ID); result.Status != "partial" || result.Reason != "agent_report_is_additive" {
		t.Fatalf("agent assessments must remain additive: %#v", result)
	}
	if c := <-completion; !c.Complete || c.Reason != "agent_report_is_additive" {
		t.Fatal("Strix transport result lost its explicit additive-coverage distinction")
	}
}

func TestCurrentOwnershipRevocationPreventsCompleteReconciliation(t *testing.T) {
	kube := fakeKube()
	inventory := assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}
	completed := make(chan assessmentjob.Completion, 1)
	m, err := assessmentjob.NewManager(settings(), inventory, managerGuard(t), kube, func(_ context.Context, c assessmentjob.Completion) error { completed <- c; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	session, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := kube.CoreV1().Secrets("deckard-assessment").Get(context.Background(), session.JobName+"-tokens", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if code := submit(t, m, session, string(secret.Data["upload-token"])); code != 202 {
		t.Fatal(code)
	}
	asset := inventory[1]
	asset.Scope = model.ScopeExternal
	inventory[1] = asset
	endJob(t, kube, session, true)
	if result := wait(t, m, session.ID); result.Status != "partial" || result.Reason != "target_ownership_changed" {
		t.Fatalf("lost ownership produced clean result: %#v", result)
	}
	if c := <-completed; c.Complete {
		t.Fatal("ownership revocation permitted complete reconciliation")
	}
}
