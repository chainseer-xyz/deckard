package assessmentjob_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func running(t *testing.T, bound assessmentjob.Settings) (*assessmentjob.Manager, assessmentjob.Session, *k8sfake.Clientset, *corev1.Secret, <-chan assessmentjob.Completion) {
	t.Helper()
	return runningWithKube(t, bound, fakeKube())
}

// Configure fake reactors before starting the manager's concurrent watchers.
func runningWithKube(t *testing.T, bound assessmentjob.Settings, kube *k8sfake.Clientset) (*assessmentjob.Manager, assessmentjob.Session, *k8sfake.Clientset, *corev1.Secret, <-chan assessmentjob.Completion) {
	t.Helper()
	completed := make(chan assessmentjob.Completion, 4)
	m, err := assessmentjob.NewManager(bound, assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, managerGuard(t), kube, func(_ context.Context, c assessmentjob.Completion) error { completed <- c; return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	session, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := kube.CoreV1().Secrets(bound.Namespace).Get(context.Background(), session.JobName+"-tokens", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return m, session, kube, secret, completed
}

func submit(t *testing.T, m *assessmentjob.Manager, session assessmentjob.Session, token string) int {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/report", strings.NewReader(`{"site":[]}`))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Deckard-Session", session.ID)
	r.Header.Set("X-Deckard-Tool", string(session.Tool))
	w := httptest.NewRecorder()
	m.ServeBroker(w, r)
	return w.Code
}
func endJob(t *testing.T, kube *k8sfake.Clientset, session assessmentjob.Session, success bool) {
	t.Helper()
	job, err := kube.BatchV1().Jobs("deckard-assessment").Get(context.Background(), session.JobName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	kind := batchv1.JobFailed
	if success {
		kind = batchv1.JobComplete
	}
	job.Status.Conditions = []batchv1.JobCondition{{Type: kind, Status: corev1.ConditionTrue}}
	if _, err := kube.BatchV1().Jobs("deckard-assessment").UpdateStatus(context.Background(), job, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}
func wait(t *testing.T, m *assessmentjob.Manager, id string) assessmentjob.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	session, err := m.Wait(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestUnknownAndCrossPurposeTokensCannotCancelValidSession(t *testing.T) {
	m, session, kube, secret, completed := running(t, settings())
	unauthenticated := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://app.example.com:443", nil)
	challenge := httptest.NewRecorder()
	m.ServeBroker(challenge, unauthenticated)
	if challenge.Code != http.StatusProxyAuthRequired || challenge.Header().Get("Proxy-Authenticate") != `Basic realm="Deckard assessment"` {
		t.Fatalf("native clients cannot negotiate proxy auth: status=%d challenge=%q", challenge.Code, challenge.Header().Get("Proxy-Authenticate"))
	}
	for _, token := range []string{"unknown-token", string(secret.Data["proxy-token"])} {
		if status := submit(t, m, session, token); status != http.StatusUnauthorized {
			t.Fatalf("wrong-purpose upload token status %d", status)
		}
	}
	for _, token := range []string{"unknown-token", string(secret.Data["upload-token"])} {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://app.example.com/", nil)
		r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("deckard:"+token)))
		w := httptest.NewRecorder()
		m.ServeBroker(w, r)
		if w.Code != http.StatusProxyAuthRequired {
			t.Fatalf("wrong-purpose proxy token status %d", w.Code)
		}
		if w.Header().Get("Proxy-Authenticate") != `Basic realm="Deckard assessment"` {
			t.Fatal("unknown token response omitted the non-session proxy challenge")
		}
	}
	if status := submit(t, m, session, string(secret.Data["upload-token"])); status != http.StatusAccepted {
		t.Fatalf("valid report status %d", status)
	}
	endJob(t, kube, session, true)
	if result := wait(t, m, session.ID); result.Status != "partial" || result.Reason != "scanner_coverage_unproven" {
		t.Fatalf("unknown tokens poisoned valid assessment: %#v", result)
	}
	if completion := <-completed; !completion.Complete {
		t.Fatal("valid session became incomplete")
	}
}

func TestSuccessfulTransportDoesNotClaimAssessmentCoverage(t *testing.T) {
	for _, test := range []struct {
		tool   assessmentjob.Tool
		reason string
	}{{assessmentjob.ToolZAP, "scanner_coverage_unproven"}, {assessmentjob.ToolZGrab2, "http_observations_only"}} {
		t.Run(string(test.tool), func(t *testing.T) {
			kube := fakeKube()
			completed := make(chan assessmentjob.Completion, 1)
			m, err := assessmentjob.NewManager(settings(), assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, managerGuard(t), kube, func(_ context.Context, c assessmentjob.Completion) error { completed <- c; return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			session, err := m.Start(context.Background(), assessmentjob.Request{Tool: test.tool, AssetIDs: []int64{1}})
			if err != nil {
				t.Fatal(err)
			}
			secret, err := kube.CoreV1().Secrets(settings().Namespace).Get(context.Background(), session.JobName+"-tokens", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if code := submit(t, m, session, string(secret.Data["upload-token"])); code != 202 {
				t.Fatal(code)
			}
			endJob(t, kube, session, true)
			if result := wait(t, m, session.ID); result.Status != "partial" || result.Reason != test.reason {
				t.Fatalf("successful process certified unproven coverage: %#v", result)
			}
			if candidate := <-completed; !candidate.Complete || candidate.Reason != test.reason {
				t.Fatalf("native parser lost the successful transport candidate: %#v", candidate)
			}
		})
	}
}

func TestFailedJobSalvagesReportOnlyAsPartial(t *testing.T) {
	m, session, kube, secret, completed := running(t, settings())
	if status := submit(t, m, session, string(secret.Data["upload-token"])); status != http.StatusAccepted {
		t.Fatal(status)
	}
	endJob(t, kube, session, false)
	if result := wait(t, m, session.ID); result.Status != "partial" {
		t.Fatalf("failed Job must remain partial: %#v", result)
	}
	if completion := <-completed; completion.Complete || len(completion.Data) == 0 {
		t.Fatal("failed Job report was lost or marked complete")
	}
}

func TestSuccessfulJobWithoutReportCannotResolveFindings(t *testing.T) {
	m, session, kube, _, completed := running(t, settings())
	endJob(t, kube, session, true)
	if result := wait(t, m, session.ID); result.Status != "failed" || result.Reason != "report_missing" {
		t.Fatalf("missing report looked clean: %#v", result)
	}
	select {
	case <-completed:
		t.Fatal("missing report triggered reconciliation")
	default:
	}
}

func TestManagerCapacityAndCleanupUseNativeJobs(t *testing.T) {
	bound := settings()
	bound.MaxRunning = 1
	m, session, kube, _, _ := running(t, bound)
	if _, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}}); err == nil {
		t.Fatal("running capacity limit bypassed")
	}
	endJob(t, kube, session, true)
	wait(t, m, session.ID)
	if _, err := kube.CoreV1().Secrets(bound.Namespace).Get(context.Background(), session.JobName+"-tokens", metav1.GetOptions{}); err == nil {
		t.Fatal("completed session credential was not deleted")
	}
	if _, err := kube.NetworkingV1().NetworkPolicies(bound.Namespace).Get(context.Background(), assessmentjob.DefaultDenyPolicyName, metav1.GetOptions{}); err != nil {
		t.Fatal("cleanup removed protective baseline")
	}
}
