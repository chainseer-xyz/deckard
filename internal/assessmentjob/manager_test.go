package assessmentjob_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

type assets map[int64]model.Asset

func (a assets) GetAsset(_ context.Context, id int64) (*model.Asset, error) {
	asset, ok := a[id]
	if !ok {
		return nil, fmt.Errorf("missing fixture asset")
	}
	return &asset, nil
}

type jobResolver struct{}

func (jobResolver) LookupHost(context.Context, string) ([]string, error) {
	return []string{"10.20.30.40"}, nil
}
func (jobResolver) LookupCNAME(context.Context, string) (string, error) { return "", nil }
func (jobResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (jobResolver) LookupNS(context.Context, string) ([]string, error)  { return nil, nil }
func managerGuard(t *testing.T) *scope.Guard {
	t.Helper()
	g, err := scope.NewGuard(config.ScopeConfig{Include: []string{"app.example.com", "10.20.30.40/32"}}, scope.WithResolver(jobResolver{}))
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func fakeKube() *k8sfake.Clientset {
	return k8sfake.NewClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "deckard-assessment", Labels: map[string]string{"deckard.io/assessment-isolated": "true"}}})
}

func TestManagerRefreshesOwnershipBeforeTargetSelectionAndBrokerAuthorization(t *testing.T) {
	bound := settings()
	g, err := scope.NewGuard(config.ScopeConfig{}, scope.WithResolver(jobResolver{}))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var unavailable atomic.Bool
	bound.RefreshOwnership = func(context.Context) error {
		calls.Add(1)
		if unavailable.Load() {
			return errors.New("private ledger failure")
		}
		g.SetZones([]string{"example.com"})
		g.SetOwnedPrefixes([]netip.Prefix{netip.MustParsePrefix("10.20.30.40/32")})
		return nil
	}
	kube := fakeKube()
	m, err := assessmentjob.NewManager(bound, assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, g, kube, func(context.Context, assessmentjob.Completion) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	session, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}})
	if err != nil {
		t.Fatalf("target selection did not load persisted ownership: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("target selection and policy construction must both refresh: calls=%d", calls.Load())
	}
	secret, err := kube.CoreV1().Secrets(bound.Namespace).Get(context.Background(), session.JobName+"-tokens", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	unavailable.Store(true)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://app.example.com:443", nil)
	r.Host = "app.example.com:443"
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("deckard:"+string(secret.Data["proxy-token"]))))
	w := httptest.NewRecorder()
	m.ServeBroker(w, r)
	if w.Code != http.StatusForbidden || calls.Load() != 3 || strings.Contains(w.Body.String(), "private") {
		t.Fatalf("broker did not refresh/fail closed: status=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
	}
}

func TestManagerNormalizesIDNAOriginBeforeGrantAndNativeReportBinding(t *testing.T) {
	g, err := scope.NewGuard(config.ScopeConfig{Include: []string{"xn--bcher-kva.example.com", "10.20.30.40/32"}}, scope.WithResolver(jobResolver{}))
	if err != nil {
		t.Fatal(err)
	}
	kube := fakeKube()
	m, err := assessmentjob.NewManager(settings(), assets{1: {ID: 1, Kind: model.KindURL, Key: "https://BÜCHER.example.com/private?ignored=value", Scope: model.ScopeOwned}}, g, kube, func(context.Context, assessmentjob.Completion) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	session, err := m.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}})
	if err != nil {
		t.Fatal(err)
	}
	cm, err := kube.CoreV1().ConfigMaps(settings().Namespace).Get(context.Background(), session.JobName+"-request", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var request assessmentjob.ExecutionRequest
	if err := json.Unmarshal([]byte(cm.Data["assessment.json"]), &request); err != nil {
		t.Fatal(err)
	}
	if len(request.Targets) != 1 || request.Targets[0] != "https://xn--bcher-kva.example.com:443" {
		t.Fatalf("grant/report hostname differs from policy's IDNA origin: %#v", request.Targets)
	}
}

func TestManagerRejectsNonOwnedAssetsBeforeCreatingResources(t *testing.T) {
	kube := fakeKube()
	manager, err := assessmentjob.NewManager(settings(), assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeExternal}}, managerGuard(t), kube, func(context.Context, assessmentjob.Completion) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}}); err == nil {
		t.Fatal("stored external asset was accepted despite owned hostname")
	}
	for _, action := range kube.Actions() {
		if action.GetVerb() == "create" {
			t.Fatal("refused target created Kubernetes resources")
		}
	}
}

func TestManagerCreatesContainmentBeforeJob(t *testing.T) {
	kube := fakeKube()
	manager, err := assessmentjob.NewManager(settings(), assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, managerGuard(t), kube, func(context.Context, assessmentjob.Completion) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	session, err := manager.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}})
	if err != nil {
		t.Fatal(err)
	}
	if session.ID == "" || session.Status != "running" {
		t.Fatalf("unexpected session %#v", session)
	}
	serviceAccount, policies, job := false, 0, false
	for _, action := range kube.Actions() {
		if action.GetVerb() != "create" {
			continue
		}
		switch action.GetResource().Resource {
		case "serviceaccounts":
			serviceAccount = true
		case "networkpolicies":
			policies++
		case "jobs":
			if !serviceAccount || policies < 2 {
				t.Fatal("Job created before dedicated identity/defaultdeny/sessionpolicy")
			}
			job = true
		}
	}
	if !job {
		t.Fatal("assessment job was not created")
	}
}

func TestManagerReportWaitsForJobSuccessAndDrainsProxy(t *testing.T) {
	kube := fakeKube()
	completed := make(chan assessmentjob.Completion, 1)
	manager, err := assessmentjob.NewManager(settings(), assets{1: {ID: 1, Kind: model.KindURL, Key: "https://app.example.com", Scope: model.ScopeOwned}}, managerGuard(t), kube, func(_ context.Context, completion assessmentjob.Completion) error {
		completed <- completion
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	session, err := manager.Start(context.Background(), assessmentjob.Request{Tool: assessmentjob.ToolZAP, AssetIDs: []int64{1}})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := kube.CoreV1().Secrets("deckard-assessment").Get(context.Background(), session.JobName+"-tokens", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	report := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/report", strings.NewReader(`{"site":[]}`))
	report.Header.Set("Authorization", "Bearer "+string(secret.Data["upload-token"]))
	report.Header.Set("X-Deckard-Session", session.ID)
	report.Header.Set("X-Deckard-Tool", "zap")
	receipt := httptest.NewRecorder()
	manager.ServeBroker(receipt, report)
	if receipt.Code != http.StatusAccepted {
		t.Fatalf("report status %d body %s", receipt.Code, receipt.Body.String())
	}
	select {
	case <-completed:
		t.Fatal("report reconciled before Job success")
	default:
	}
	job, err := kube.BatchV1().Jobs("deckard-assessment").Get(context.Background(), session.JobName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
	if _, err := kube.BatchV1().Jobs("deckard-assessment").UpdateStatus(context.Background(), job, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case completion := <-completed:
		if !completion.Complete || string(completion.Data) != `{"site":[]}` || completion.Format != "zap" {
			t.Fatalf("unexpected completion %#v", completion)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Job completion was not observed")
	}
}
