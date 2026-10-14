package api_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestRuntimeIncidentRequiresAuditedManualResolution(t *testing.T) {
	e := newIngestEnv(t)
	if r, _ := e.post(body("tetragon", "k8s:uid:cluster", false, t0, bucket("runtime"))); r.Code != 200 {
		t.Fatal(r.Body)
	}
	fs, _, err := e.store.ListFindings(context.Background(), store.FindingFilter{Check: "ext.tetragon"})
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings%+v %v", fs, err)
	}
	path := fmt.Sprintf("/api/v1/findings/%d/resolve", fs[0].ID)
	if r := e.do("POST", path, `{}`); r.Code != 400 {
		t.Fatalf("resolution without reason: %d %s", r.Code, r.Body)
	}
	if r := e.do("POST", path, `{"note":"Container removed; reviewed the detection"}`); r.Code != 200 {
		t.Fatalf("resolution: %d %s", r.Code, r.Body)
	}
	f, err := e.store.GetFinding(context.Background(), fs[0].ID)
	if err != nil || f.Status != model.StatusResolved || f.SuppressionNote == "" || f.ResolvedAt == nil {
		t.Fatalf("audit lost: %+v %v", f, err)
	}
	if r := e.do("POST", fmt.Sprintf("/api/v1/findings/%d/reopen", f.ID), `{}`); r.Code != 200 {
		t.Fatalf("runtime reopen: %d %s", r.Code, r.Body)
	}
}

func TestAssessmentFindingCannotBeManuallyHealed(t *testing.T) {
	e := newIngestEnv(t)
	e.seed()
	if r := e.do("POST", "/api/v1/findings/1/resolve", `{"note":"skip scan"}`); r.Code != 409 {
		t.Fatalf("non-runtime healed: %d %s", r.Code, r.Body)
	}
}
