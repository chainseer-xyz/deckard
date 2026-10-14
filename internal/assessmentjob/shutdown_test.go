package assessmentjob_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestCloseCancelsReportCallbackRatherThanWaitingThirtySeconds(t *testing.T) {
	kube := fakeKube()
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	m, err := assessmentjob.NewManager(settings(), assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, managerGuard(t), kube, func(ctx context.Context, _ assessmentjob.Completion) error {
		close(entered)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := kube.CoreV1().Secrets(settings().Namespace).Get(context.Background(), session.JobName+"-tokens", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if submit(t, m, session, string(secret.Data["upload-token"])) != 202 {
		t.Fatal("report refused")
	}
	endJob(t, kube, session, true)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("callback did not start")
	}
	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Error("Close did not cancel the active callback")
	}
}

func TestCleanupFailureCannotBeReportedAsCleaned(t *testing.T) {
	m, session, kube, secret, _ := running(t, settings())
	kube.PrependReactor("delete", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("private Kubernetes credential details")
	})
	if submit(t, m, session, string(secret.Data["upload-token"])) != 202 {
		t.Fatal("report refused")
	}
	endJob(t, kube, session, true)
	result := wait(t, m, session.ID)
	if result.Status != "failed" || result.Reason != "cleanup_pending" {
		t.Fatalf("failed cleanup looked successful: %#v", result)
	}
}

func TestCleanupUsesUIDOfCreatedObjects(t *testing.T) {
	kube := fakeKube()
	kube.PrependReactor("create", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		object := action.(k8stesting.CreateAction).GetObject()
		if metadata, ok := object.(metav1.Object); ok {
			metadata.SetUID(types.UID("fixture-" + metadata.GetName()))
		}
		return false, nil, nil
	})
	deletes := 0
	kube.PrependReactor("delete", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deletes++
		deleted := action.(k8stesting.DeleteAction)
		preconditions := deleted.GetDeleteOptions().Preconditions
		if preconditions == nil || preconditions.UID == nil || string(*preconditions.UID) != "fixture-"+deleted.GetName() {
			t.Errorf("cleanup could delete a foreign name replacement: %s", deleted.GetResource().Resource)
		}
		return false, nil, nil
	})
	m, err := assessmentjob.NewManager(settings(), assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, managerGuard(t), kube, func(context.Context, assessmentjob.Completion) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if deletes < 4 {
		t.Fatalf("cleanup fixture did not cover all created objects: %d", deletes)
	}
}

func TestCloseDuringStrixControllerCreationSerializesCleanup(t *testing.T) {
	bound := settings()
	bound.ModelGatewayIP = netip.MustParseAddr("10.20.30.60")
	bound.ModelGatewayURL = "http://10.20.30.60:8000/v1"
	bound.ModelGatewayPort = 8000
	bound.Model = "openai/local-model"
	var calls atomic.Int32
	runtimeContext := make(chan context.Context, 1)
	bound.RefreshOwnership = func(ctx context.Context) error {
		if calls.Add(1) == 3 { // Start selection, policy construction, runtime ready.
			runtimeContext <- ctx
		}
		return ctx.Err()
	}
	kube := fakeKube()
	creating := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	kube.PrependReactor("create", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
		close(creating)
		<-release
		return false, nil, nil
	})
	m, err := assessmentjob.NewManager(bound, assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, managerGuard(t), kube, func(context.Context, assessmentjob.Completion) error {
		t.Error("shutdown must not ingest an unobserved report")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	session, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolStrix, AssetIDs: []int64{1}})
	if err != nil {
		t.Fatal(err)
	}
	pod, err := kube.CoreV1().Pods(bound.Namespace).Get(context.Background(), session.JobName+"-runtime", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.Status.PodIP = "10.20.30.70"
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if _, err := kube.CoreV1().Pods(bound.Namespace).UpdateStatus(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-creating:
	case <-time.After(2 * time.Second):
		t.Fatal("ready runtime did not enter controller creation")
	}
	ctx := <-runtimeContext
	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Close waited for controller creation before canceling its context")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after the canceled create returned")
	}
	jobs, err := kube.BatchV1().Jobs(bound.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil || len(jobs.Items) != 0 {
		t.Fatalf("late successful creation escaped serialized cleanup: jobs=%d err=%v", len(jobs.Items), err)
	}
}
