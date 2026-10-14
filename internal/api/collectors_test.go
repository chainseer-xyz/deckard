package api_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type collectorStore struct {
	store.Store
	scopes []store.IngestScope
	err    error
}

func (s collectorStore) ListIngestScopes(context.Context) ([]store.IngestScope, error) {
	return s.scopes, s.err
}

func TestCollectorsDistinguishFreshReportsFromCompleteCoverage(t *testing.T) {
	rows := []store.IngestScope{
		{Tool: "prowler", Scope: "fresh", LastAt: t0.Add(-time.Minute), CompleteAt: t0.Add(-time.Minute), Open: 3},
		{Tool: "prowler", Scope: "stale", LastAt: t0.Add(-3 * time.Minute), CompleteAt: t0.Add(-3 * time.Minute)},
		{Tool: "prowler", Scope: "partial", LastAt: t0.Add(-time.Minute), CompleteAt: t0.Add(-time.Hour)},
		{Tool: "prowler", Scope: "boundary", LastAt: t0.Add(-2 * time.Minute), CompleteAt: t0.Add(-2 * time.Minute)},
		{Tool: "tetragon", Scope: "runtime", LastAt: t0.Add(-time.Minute), CompleteAt: t0.Add(-time.Minute)},
		{Tool: "custom", Scope: "unscheduled", LastAt: t0.Add(-time.Hour)},
	}
	e := newEnv(t, func(d *api.Deps) {
		d.Store = collectorStore{Store: d.Store, scopes: rows}
		d.Ingest.Tools = map[string]config.IngestToolConfig{"prowler": {ExpectedReportInterval: time.Minute}, "tetragon": {ExpectedReportInterval: time.Minute}}
	})
	r := e.get("/api/v1/collectors")
	var out listOut
	r.json(t, &out)
	if r.Code != http.StatusOK || out.Total != 6 {
		t.Fatalf("collector list: %d %s", r.Code, r.Body)
	}
	byScope := map[string]map[string]any{}
	for _, item := range out.Items {
		byScope[item["scope"].(string)] = item
	}
	for scope, want := range map[string][2]string{"fresh": {"healthy", "complete"}, "stale": {"stale", "complete"}, "partial": {"healthy", "incomplete"}, "boundary": {"healthy", "complete"}, "runtime": {"healthy", "event_only"}, "unscheduled": {"reporting", "incomplete"}} {
		if byScope[scope]["health"] != want[0] || byScope[scope]["coverage"] != want[1] {
			t.Fatalf("%s state: %+v", scope, byScope[scope])
		}
	}
	if byScope["fresh"]["open_findings"] != float64(3) || byScope["fresh"]["expected_interval_seconds"] != float64(60) {
		t.Fatalf("missing producer state: %+v", byScope["fresh"])
	}
	if _, ok := byScope["runtime"]["last_complete"]; ok {
		t.Fatal("runtime producer implied complete assessment")
	}
}

func TestCollectorsIncludeConfiguredNeverSeenPairsWithoutCredentials(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) {
		d.Ingest.Tools = map[string]config.IngestToolConfig{"tetragon": {ExpectedReportInterval: 5 * time.Minute}}
		d.Ingest.Credentials = map[string]config.CollectorCredentialConfig{"sensor": {TokenEnv: "PRIVATE_SENSOR_TOKEN", Tools: []string{"tetragon", "prowler"}, Scopes: []string{"scope-b", "scope-a"}}, "duplicate": {TokenEnv: "OTHER_PRIVATE_TOKEN", Tools: []string{"prowler"}, Scopes: []string{"scope-a"}}}
		d.AuthOptions.Getenv = func(name string) string { return name + strings.Repeat("x", 32) }
	})
	r := e.get("/api/v1/collectors?limit=2&offset=1")
	var out listOut
	r.json(t, &out)
	if r.Code != 200 || out.Total != 4 || len(out.Items) != 2 || out.Limit != 2 || out.Offset != 1 {
		t.Fatalf("known producer pagination: %d %s", r.Code, r.Body)
	}
	if out.Items[0]["tool"] != "prowler" || out.Items[0]["scope"] != "scope-b" || out.Items[1]["tool"] != "tetragon" || out.Items[1]["scope"] != "scope-a" {
		t.Fatalf("unstable producer ordering: %+v", out.Items)
	}
	for _, item := range out.Items {
		if item["health"] != "never" {
			t.Fatalf("never-seen producer looks healthy: %+v", item)
		}
		if _, ok := item["last_report"]; ok {
			t.Fatal("invented report time")
		}
	}
	if out.Items[1]["coverage"] != "event_only" {
		t.Fatal("runtime producer can never claim complete coverage")
	}
	if strings.Contains(r.Body.String(), "TOKEN") || strings.Contains(r.Body.String(), "token_env") || strings.Contains(r.Body.String(), strings.Repeat("x", 32)) {
		t.Fatal("collector list disclosed credential configuration")
	}
}

func TestCollectorDatabaseFailureCannotLookLikeEmptySuccess(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.Store = collectorStore{Store: d.Store, err: errors.New("db SECRET")} })
	r := e.get("/api/v1/collectors")
	if r.Code != 500 || strings.Contains(r.Body.String(), "SECRET") {
		t.Fatalf("database failure became healthy/secret-bearing response: %d %s", r.Code, r.Body)
	}
}

func TestCollectorQueryValidation(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/api/v1/collectors?limit=501", "/api/v1/collectors?unknown=x", "/api/v1/collectors?offset=-1"} {
		if r := e.get(path); r.Code != 400 {
			t.Fatalf("query accepted: %s = %d", path, r.Code)
		}
	}
}

func TestCollectorLongReportIntervalDoesNotOverflowStaleness(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) {
		d.Store = collectorStore{Store: d.Store, scopes: []store.IngestScope{{Tool: "prowler", Scope: "long-interval", LastAt: t0.Add(-time.Hour)}}}
		d.Ingest.Tools = map[string]config.IngestToolConfig{"prowler": {ExpectedReportInterval: time.Duration(1<<63 - 1)}}
	})
	r := e.get("/api/v1/collectors")
	var out listOut
	r.json(t, &out)
	if r.Code != 200 || len(out.Items) != 1 || out.Items[0]["health"] != "healthy" {
		t.Fatalf("long report interval overflowed: %d %s", r.Code, r.Body)
	}
}
