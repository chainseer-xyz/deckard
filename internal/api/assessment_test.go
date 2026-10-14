package api_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
	"github.com/chainseer-xyz/deckard/internal/config"
)

type assessmentRunner struct{ starts int }

func (a *assessmentRunner) Start(_ context.Context, r assessmentjob.Request) (assessmentjob.Session, error) {
	a.starts++
	if len(r.AssetIDs) != 1 || r.AssetIDs[0] != 7 || r.Tool != "zap" {
		return assessmentjob.Session{}, assessmentjob.ErrRefused
	}
	return assessmentjob.Session{ID: "run-1", Tool: r.Tool, Status: "running", AssetIDs: r.AssetIDs}, nil
}
func (a *assessmentRunner) Get(_ context.Context, id string) (assessmentjob.Session, error) {
	if id != "run-1" {
		return assessmentjob.Session{}, assessmentjob.ErrRefused
	}
	return assessmentjob.Session{ID: id, Tool: "zap", Status: "running"}, nil
}

func TestExplicitAssessmentAPIRequiresOperatorIdentity(t *testing.T) {
	runner := &assessmentRunner{}
	e := newEnv(t, func(d *api.Deps) {
		d.Assessments = runner
		d.Ingest = scopedConfig(t)
		d.AuthOptions.Getenv = func(string) string { return collectorToken }
	})
	if r := e.do("POST", "/api/v1/assessments", `{"tool":"zap","asset_ids":[7]}`); r.Code != 202 {
		t.Fatalf("start%d %s", r.Code, r.Body)
	}
	if r := e.get("/api/v1/assessments/run-1"); r.Code != 200 {
		t.Fatalf("get%d %s", r.Code, r.Body)
	}
	if r := e.do("POST", "/api/v1/assessments", `{"tool":"zap","asset_ids":[7]}`, "Authorization", "Bearer "+collectorToken); r.Code != 403 || runner.starts != 1 {
		t.Fatalf("producer escalated: %d starts%d", r.Code, runner.starts)
	}
	if r := newEnv(t).do("POST", "/api/v1/assessments", `{"tool":"zap","asset_ids":[7]}`); r.Code != 501 {
		t.Fatalf("disabled runner%d", r.Code)
	}
}

func TestAssessmentCapabilitiesExposeOnlyConfiguredTools(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) {
		d.Assessments = &assessmentRunner{}
		d.Assessment = config.AssessmentConfig{Enabled: true, Timeout: 5 * time.Minute, Images: map[string]string{"zap": "private-image"}, ModelSecretName: "secret-name"}
	})
	r := e.get("/api/v1/assessments")
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"tools":["zap"]`) || strings.Contains(r.Body.String(), "secret-name") || strings.Contains(r.Body.String(), "private-image") {
		t.Fatalf("capabilities %d %s", r.Code, r.Body)
	}
	r = newEnv(t).get("/api/v1/assessments")
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"enabled":false`) || !strings.Contains(r.Body.String(), `"tools":[]`) {
		t.Fatalf("disabled %d %s", r.Code, r.Body)
	}
}
