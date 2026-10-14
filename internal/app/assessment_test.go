package app

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestAssessmentCompletionUsesOwnedRefsAndFailedRunsNeverHeal(t *testing.T) {
	a, ctx := wiringApp(t)
	now := time.Now().UTC().Add(-10 * time.Minute)
	_, err := a.st.UpsertSnapshot(ctx, "lab", []store.AssetUpsert{{AssetInput: model.AssetInput{Kind: model.KindURL, Key: "https://app.example.com", Source: "lab"}, Scope: model.ScopeOwned}}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := a.st.GetAssetByKey(ctx, model.KindURL, "https://app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"site":[{"@name":"https://app.example.com","alerts":[{"pluginid":"10020","alert":"Missing security header","riskcode":"2","instances":[{"uri":"https://app.example.com/private?token=SECRET","method":"GET","evidence":"SECRET"}]}]}]}`
	c := assessmentjob.Completion{Session: assessmentjob.Session{ID: "session", Tool: "zap", AssetIDs: []int64{asset.ID}, CreatedAt: now}, Targets: []assessmentjob.Target{{AssetID: asset.ID, Origin: "https://app.example.com"}}, Data: []byte(raw), Complete: true}
	if err := a.completeAssessment(ctx, c); err != nil {
		t.Fatal(err)
	}
	findings, _, err := a.st.ListFindings(ctx, store.FindingFilter{Check: "ext.zap"})
	if err != nil || len(findings) != 1 || findings[0].AssetID != asset.ID || strings.Contains(findings[0].Description, "SECRET") {
		t.Fatalf("result%+v %v", findings, err)
	}
	c.Data = []byte(`{"site":[{"@name":"https://app.example.com","alerts":[]}]}`)
	c.Complete = false
	c.Session.CreatedAt = now.Add(time.Minute)
	if err := a.completeAssessment(ctx, c); err != nil {
		t.Fatal(err)
	}
	f, err := a.st.GetFinding(ctx, findings[0].ID)
	if err != nil || f.Status != model.StatusOpen || f.MissedRuns != 0 {
		t.Fatalf("failed assessment healed%+v %v", f, err)
	}
	for i := 2; i < 4; i++ {
		c.Complete = true
		c.Session.CreatedAt = now.Add(time.Duration(i) * time.Minute)
		if err := a.completeAssessment(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	f, err = a.st.GetFinding(ctx, findings[0].ID)
	if err != nil || f.Status != model.StatusOpen || f.MissedRuns != 0 {
		t.Fatalf("ZAP exit success certified unproven scan completeness %+v %v", f, err)
	}
}

func TestZGrabObservationCannotHealAnotherProducerScope(t *testing.T) {
	a, ctx := wiringApp(t)
	now := time.Now().UTC().Add(-time.Minute)
	_, err := a.st.UpsertSnapshot(ctx, "lab", []store.AssetUpsert{{AssetInput: model.AssetInput{Kind: model.KindURL, Key: "https://app.example.com", Source: "lab"}, Scope: model.ScopeOwned}}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := a.st.GetAssetByKey(ctx, model.KindURL, "https://app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := a.proc.Ingest(ctx, store.IngestInput{Tool: "zgrab2", Scope: "separate-producer", Check: "ext.zgrab2", Source: "ingest:zgrab2", ObservedAt: now, Items: []store.IngestItem{{Ref: true, AssetKind: asset.Kind, AssetKey: asset.Key, Finding: model.FindingInput{Key: "issue", Title: "Unauthenticated administrative service", Severity: model.SeverityHigh}}}})
	if err != nil || len(opened.Opened) != 1 {
		t.Fatalf("seed%+v %v", opened, err)
	}
	c := assessmentjob.Completion{Session: assessmentjob.Session{ID: "session", Tool: "zgrab2", AssetIDs: []int64{asset.ID}, CreatedAt: now}, Targets: []assessmentjob.Target{{AssetID: asset.ID, Origin: "https://app.example.com", Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.7")}, Port: 443}}, Data: []byte(`{"ip":"203.0.113.7","domain":"app.example.com","port":443,"data":{"http":{"status":"success","result":{"response":{"status_code":200}}}}}`), Complete: true}
	if err := a.completeAssessment(ctx, c); err != nil {
		t.Fatal(err)
	}
	f, err := a.st.GetFinding(ctx, opened.Opened[0].ID)
	if err != nil || f.MissedRuns != 0 || f.Status != model.StatusOpen {
		t.Fatalf("HTTP-only observation healed another assessment%+v %v", f, err)
	}
	if _, err := a.st.GetBaseline(ctx, asset.ID, "ext.zgrab2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("HTTP-only observation seeded a coverage baseline: %v", err)
	}
	observations, err := a.st.LatestObservations(ctx, asset.ID)
	if err != nil || len(observations) != 1 {
		t.Fatalf("observation lost%+v %v", observations, err)
	}
}

func TestAPIOnlyAssessmentsRefreshOwnershipAndReferenceData(t *testing.T) {
	a := &App{cfg: &config.Config{Server: config.ServerConfig{Roles: []string{"api"}}, Assessment: config.AssessmentConfig{Enabled: true}}}
	if !a.scopeRefreshEnabled() {
		t.Fatal("API-only assessment broker has stale ownership and reference data")
	}
	a.cfg.Assessment.Enabled = false
	if a.scopeRefreshEnabled() {
		t.Fatal("disabled API-only app unnecessarily starts scanner refresh loops")
	}
}
