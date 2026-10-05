package api_test

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type listOut struct {
	Items  []map[string]any `json:"items"`
	Total  int              `json:"total"`
	Limit  int              `json:"limit"`
	Offset int              `json:"offset"`
}

func ids(l listOut) []int {
	var out []int
	for _, it := range l.Items {
		out = append(out, int(it["id"].(float64)))
	}
	return out
}

func eq(a, b []int) bool { return fmt.Sprint(a) == fmt.Sprint(b) }

func TestProbes(t *testing.T) {
	e := newEnv(t)
	// Probes need no credentials.
	rec := httpGetNoAuth(e, "/healthz")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("healthz = %d %s", rec.Code, rec.Body)
	}
	if rec := httpGetNoAuth(e, "/readyz"); rec.Code != 200 {
		t.Fatalf("readyz = %d", rec.Code)
	}
	e.store.Do(func(s *fakestore.Store) { s.PingErr = errors.New("conn refused: password=hunter2") })
	rec = httpGetNoAuth(e, "/readyz")
	if rec.Code != 503 {
		t.Fatalf("readyz with db down = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Error("readyz leaked store error")
	}
	if rec := httpGetNoAuth(e, "/healthz"); rec.Code != 200 {
		t.Error("healthz must stay 200 while db is down")
	}
}

func TestStats(t *testing.T) {
	e := newEnv(t)
	var st map[string]map[string]int
	r := e.get("/api/v1/stats")
	r.json(t, &st)
	if r.Code != 200 || st["assets_by_kind"] == nil || st["findings_by_check"] == nil {
		t.Fatalf("empty stats must render objects not null: %d %s", r.Code, r.Body)
	}
	e.store.Do(func(s *fakestore.Store) {
		s.StatsVal = store.Stats{AssetsByKind: map[string]int{"hostname": 2}}
	})
	e.get("/api/v1/stats").json(t, &st)
	if st["assets_by_kind"]["hostname"] != 2 {
		t.Errorf("stats = %v", st)
	}
	e.store.Do(func(s *fakestore.Store) { s.StatsErr = errors.New("boom") })
	if r := e.get("/api/v1/stats"); r.Code != 500 || r.errCode(t) != "internal" || strings.Contains(r.Body.String(), "boom") {
		t.Errorf("stats error = %d %s", r.Code, r.Body)
	}
}

func TestListAssets(t *testing.T) {
	e := newEnv(t)
	e.seed()
	tests := []struct {
		name  string
		query string
		want  []int
		total int
	}{
		{"default hides removed", "", []int{1, 2, 3, 4, 5}, 5},
		{"include removed", "?include_removed=true", []int{1, 2, 3, 4, 5, 6}, 6},
		{"kind", "?kind=hostname", []int{1, 4}, 2},
		{"source", "?source=scan", []int{3, 5}, 2},
		{"scope", "?scope=shared", []int{4}, 1},
		{"zone", "?zone=example.com", []int{1, 4}, 2},
		{"q", "?q=203.0.113", []int{2, 3}, 2},
		{"combined", "?kind=hostname&source=aws", []int{4}, 1},
		{"paging", "?limit=2&offset=1", []int{2, 3}, 5},
		{"offset past end", "?offset=100", nil, 5},
		{"no match", "?q=zzz", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := e.get("/api/v1/assets" + tt.query)
			if r.Code != 200 {
				t.Fatalf("status %d %s", r.Code, r.Body)
			}
			var l listOut
			r.json(t, &l)
			if !eq(ids(l), tt.want) || l.Total != tt.total {
				t.Errorf("ids=%v total=%d, want %v/%d", ids(l), l.Total, tt.want, tt.total)
			}
			if l.Items == nil {
				t.Error("items must be [] never null")
			}
		})
	}
	var l listOut
	e.get("/api/v1/assets?limit=2&offset=1").json(t, &l)
	if l.Limit != 2 || l.Offset != 1 {
		t.Errorf("envelope limit/offset = %d/%d", l.Limit, l.Offset)
	}
	e.get("/api/v1/assets").json(t, &l)
	if l.Limit != 50 {
		t.Errorf("default limit = %d", l.Limit)
	}
}

func TestStrictQueryValidation(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("a", 300)
	for _, target := range []string{
		"/api/v1/assets?limit=0", "/api/v1/assets?limit=501", "/api/v1/assets?limit=abc", "/api/v1/assets?limit=-1",
		"/api/v1/assets?limit=1&limit=2", "/api/v1/assets?offset=-1", "/api/v1/assets?offset=x",
		"/api/v1/assets?kind=bogus", "/api/v1/assets?scope=bogus", "/api/v1/assets?include_removed=maybe",
		"/api/v1/assets?nope=1", "/api/v1/assets?q=" + long,
		"/api/v1/findings?status=bogus", "/api/v1/findings?status=open&status=wat", "/api/v1/findings?min_severity=urgent",
		"/api/v1/findings?asset_id=0", "/api/v1/findings?asset_id=x", "/api/v1/findings?unknown=1",
		"/api/v1/assets/1?foo=bar", "/api/v1/assets/abc", "/api/v1/assets/0", "/api/v1/assets/-3", "/api/v1/assets/99999999999999999999",
		"/api/v1/assets/1/graph?depth=0", "/api/v1/assets/1/graph?depth=4", "/api/v1/assets/1/graph?depth=x",
		"/api/v1/findings/abc", "/api/v1/changes?since=yesterday", "/api/v1/changes?limit=0", "/api/v1/changes?x=1",
		"/api/v1/sources?limit=9999", "/api/v1/scans?offset=-5", "/api/v1/events?since=nope", "/api/v1/stats?x=1",
	} {
		r := e.get(target)
		if r.Code != 400 {
			t.Errorf("%s = %d, want 400", target, r.Code)
			continue
		}
		if c := r.errCode(t); c != "invalid_query" && c != "invalid_id" {
			t.Errorf("%s code %q", target, c)
		}
	}
	// Boundaries that must succeed.
	for _, target := range []string{"/api/v1/assets?limit=1", "/api/v1/assets?limit=500", "/api/v1/assets?include_removed=false", "/api/v1/assets/1/graph?depth=3"} {
		e.seed()
		if r := e.get(target); r.Code != 200 {
			t.Errorf("%s = %d %s", target, r.Code, r.Body)
		}
	}
}

func TestGetAsset(t *testing.T) {
	e := newEnv(t)
	e.seed()
	var d struct {
		Asset struct {
			ID  int    `json:"id"`
			Key string `json:"key"`
		} `json:"asset"`
		Edges []struct {
			Direction string `json:"direction"`
			Type      string `json:"type"`
			Asset     struct{ Key string }
		} `json:"edges"`
		Observations []map[string]any `json:"observations"`
		Baselines    []struct {
			Check  string `json:"check"`
			Stable bool   `json:"stable"`
		} `json:"baselines"`
		Findings []map[string]any `json:"findings"`
	}
	r := e.get("/api/v1/assets/1")
	if r.Code != 200 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	r.json(t, &d)
	if d.Asset.ID != 1 || d.Asset.Key != "www.example.com" {
		t.Errorf("asset = %+v", d.Asset)
	}
	if len(d.Edges) != 1 || d.Edges[0].Direction != "out" || d.Edges[0].Type != "resolves_to" || d.Edges[0].Asset.Key != "203.0.113.5" {
		t.Errorf("edges = %+v", d.Edges)
	}
	if len(d.Observations) != 1 || len(d.Baselines) != 1 || d.Baselines[0].Check != "tls.cert" || !d.Baselines[0].Stable {
		t.Errorf("obs/baselines = %v / %+v", d.Observations, d.Baselines)
	}
	if len(d.Findings) != 2 { // open only; suppressed #5 excluded
		t.Errorf("findings = %d, want the 2 open ones", len(d.Findings))
	}
	// asset with inbound edges and nothing else
	var d2 struct {
		Edges    []struct{ Direction string }
		Findings []any
	}
	e.get("/api/v1/assets/2").json(t, &d2)
	dirs := map[string]int{}
	for _, ed := range d2.Edges {
		dirs[ed.Direction]++
	}
	if dirs["in"] != 2 || dirs["out"] != 1 || d2.Findings == nil {
		t.Errorf("asset 2 edges = %v findings=%v", dirs, d2.Findings)
	}
	if r := e.get("/api/v1/assets/999"); r.Code != 404 || r.errCode(t) != "not_found" {
		t.Errorf("missing = %d", r.Code)
	}
}

func TestAssetGraph(t *testing.T) {
	e := newEnv(t)
	e.seed()
	type graph struct {
		Nodes []struct {
			ID    int
			Kind  string
			Key   string
			Scope string
		}
		Edges []struct {
			From, To int
			Type     string
		}
		Truncated bool
	}
	tests := []struct {
		query     string
		nodes     []int
		edges     int
		truncated bool
	}{
		{"", []int{1, 2}, 1, false},
		{"?depth=1", []int{1, 2}, 1, false},
		{"?depth=2", []int{1, 2, 3, 4}, 3, false},
		{"?depth=3", []int{1, 2, 3, 4, 5}, 4, false},
	}
	for _, tt := range tests {
		var g graph
		r := e.get("/api/v1/assets/1/graph" + tt.query)
		if r.Code != 200 {
			t.Fatalf("%s: %d %s", tt.query, r.Code, r.Body)
		}
		r.json(t, &g)
		var got []int
		for _, n := range g.Nodes {
			got = append(got, n.ID)
		}
		if !sameSet(got, tt.nodes) || len(g.Edges) != tt.edges || g.Truncated != tt.truncated {
			t.Errorf("%q: nodes=%v edges=%d trunc=%v want %v/%d", tt.query, got, len(g.Edges), g.Truncated, tt.nodes, tt.edges)
		}
	}
	var g graph
	e.get("/api/v1/assets/3/graph").json(t, &g)
	// edge directions preserved: 2 -> 3 (exposes) and 3 -> 5 (has_cert)
	var found23, found35 bool
	for _, ed := range g.Edges {
		found23 = found23 || (ed.From == 2 && ed.To == 3 && ed.Type == "exposes")
		found35 = found35 || (ed.From == 3 && ed.To == 5 && ed.Type == "has_cert")
	}
	if !found23 || !found35 || g.Nodes[0].Kind == "" || g.Nodes[0].Scope == "" {
		t.Errorf("graph = %+v", g)
	}
	if r := e.get("/api/v1/assets/999/graph"); r.Code != 404 {
		t.Errorf("missing = %d", r.Code)
	}
}

func sameSet(a, b []int) bool {
	m := map[int]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestGraphTruncation(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.MaxGraphNodes = 3 })
	e.seed()
	var g struct {
		Nodes     []any
		Truncated bool
	}
	e.get("/api/v1/assets/2/graph").json(t, &g)
	if len(g.Nodes) != 3 || !g.Truncated {
		t.Errorf("nodes=%d truncated=%v", len(g.Nodes), g.Truncated)
	}
}

func TestListFindings(t *testing.T) {
	e := newEnv(t)
	e.seed()
	tests := []struct {
		name  string
		query string
		want  []int
	}{
		{"all", "", []int{1, 2, 3, 4, 5}},
		{"status single", "?status=open", []int{1, 2}},
		{"status repeatable", "?status=open&status=acknowledged", []int{1, 2, 3}},
		{"min severity", "?min_severity=high", []int{1, 3}},
		{"check", "?check=tls.cert", []int{1, 3}},
		{"zone", "?zone=example.com&status=open", []int{1, 2}},
		{"source", "?source=aws", []int{3}},
		{"asset", "?asset_id=1", []int{1, 2, 5}},
		{"q", "?q=hsts", []int{2}},
		{"paging", "?limit=2&offset=2", []int{3, 4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var l listOut
			r := e.get("/api/v1/findings" + tt.query)
			r.json(t, &l)
			if r.Code != 200 || !eq(ids(l), tt.want) {
				t.Errorf("%d ids=%v want %v", r.Code, ids(l), tt.want)
			}
		})
	}
	var f map[string]any
	r := e.get("/api/v1/findings/3")
	r.json(t, &f)
	if r.Code != 200 || f["title"] != "expired cert" {
		t.Errorf("get finding: %d %v", r.Code, f)
	}
	if r := e.get("/api/v1/findings/77"); r.Code != 404 {
		t.Errorf("missing finding = %d", r.Code)
	}
}

func TestSourcesScansChanges(t *testing.T) {
	e := newEnv(t)
	e.seed()
	var l listOut
	e.get("/api/v1/sources?limit=2&offset=1").json(t, &l)
	if l.Total != 3 || len(l.Items) != 2 || l.Items[0]["source"] != "aws" {
		t.Errorf("sources = %+v", l)
	}
	e.get("/api/v1/sources?offset=50").json(t, &l)
	if l.Items == nil || len(l.Items) != 0 {
		t.Errorf("sources past end = %+v", l)
	}

	e.get("/api/v1/scans?limit=2").json(t, &l)
	if len(l.Items) != 2 || l.Limit != 2 {
		t.Errorf("scans = %+v", l)
	}
	e.get("/api/v1/scans?limit=2&offset=3").json(t, &l)
	if len(l.Items) != 2 || int(l.Items[0]["id"].(float64)) != 4 {
		t.Errorf("scans paged = %+v", l)
	}

	e.store.Do(func(s *fakestore.Store) {
		s.Events = []store.Event{
			{ID: 1, Type: "asset_added", Subject: "a", At: t0.Add(-48 * time.Hour)},
			{ID: 2, Type: "finding_opened", Subject: "b", At: t0.Add(-time.Hour)},
			{ID: 3, Type: "asset_removed", Subject: "c", At: t0.Add(-time.Minute)},
		}
	})
	e.get("/api/v1/changes").json(t, &l) // default window: 24h
	if !eq(ids(l), []int{3, 2}) {
		t.Errorf("default window = %v", ids(l))
	}
	since := t0.Add(-90 * time.Minute).Format(time.RFC3339)
	e.get("/api/v1/changes?since="+since+"&limit=1").json(t, &l)
	if !eq(ids(l), []int{3}) || l.Limit != 1 {
		t.Errorf("since+limit = %v", ids(l))
	}
	e.get("/api/v1/changes?since=2020-01-01T00:00:00Z").json(t, &l)
	if len(l.Items) != 3 {
		t.Errorf("since 2020 = %v", ids(l))
	}
}

func TestActionsOnFindings(t *testing.T) {
	future := t0.Add(24 * time.Hour).Format(time.RFC3339)
	past := t0.Add(-time.Hour).Format(time.RFC3339)
	tests := []struct {
		name       string
		path       string
		body       string
		ctype      string
		status     int
		code       string
		wantStatus model.FindingStatus
		wantNote   string
	}{
		{"ack no body", "/findings/1/acknowledge", "", "", 200, "", model.StatusAcknowledged, ""},
		{"ack with note+until", "/findings/1/acknowledge", `{"note":"looking","until":"` + future + `"}`, "", 200, "", model.StatusAcknowledged, "looking"},
		{"suppress ok", "/findings/1/suppress", `{"note":" accepted risk ","until":"` + future + `"}`, "", 200, "", model.StatusSuppressed, "accepted risk"},
		{"suppress indefinite", "/findings/1/suppress", `{"note":"forever"}`, "", 200, "", model.StatusSuppressed, "forever"},
		{"suppress needs note", "/findings/1/suppress", `{}`, "", 400, "invalid_body", "", ""},
		{"suppress blank note", "/findings/1/suppress", `{"note":"   "}`, "", 400, "invalid_body", "", ""},
		{"suppress no body", "/findings/1/suppress", ``, "", 400, "invalid_body", "", ""},
		{"until in past", "/findings/1/suppress", `{"note":"x","until":"` + past + `"}`, "", 400, "invalid_body", "", ""},
		{"until equal now", "/findings/1/suppress", `{"note":"x","until":"` + t0.Format(time.RFC3339) + `"}`, "", 400, "invalid_body", "", ""},
		{"until bad format", "/findings/1/suppress", `{"note":"x","until":"tomorrow"}`, "", 400, "invalid_body", "", ""},
		{"fp ok", "/findings/2/false-positive", `{"note":"scanner noise"}`, "", 200, "", model.StatusFalsePositive, "scanner noise"},
		{"fp until rejected", "/findings/2/false-positive", `{"until":"` + future + `"}`, "", 400, "invalid_body", "", ""},
		{"reopen ok", "/findings/3/reopen", `{"note":"regressed"}`, "", 200, "", model.StatusOpen, "regressed"},
		{"reopen until rejected", "/findings/3/reopen", `{"until":"` + future + `"}`, "", 400, "invalid_body", "", ""},
		{"resolved conflicts", "/findings/4/acknowledge", ``, "", 409, "conflict", "", ""},
		{"resolved reopen conflicts", "/findings/4/reopen", ``, "", 409, "conflict", "", ""},
		{"missing finding", "/findings/99/acknowledge", ``, "", 404, "not_found", "", ""},
		{"bad id", "/findings/x/acknowledge", ``, "", 400, "invalid_id", "", ""},
		{"unknown field", "/findings/1/acknowledge", `{"note":"x","evil":true}`, "", 400, "invalid_body", "", ""},
		{"malformed json", "/findings/1/acknowledge", `{"note":`, "", 400, "invalid_body", "", ""},
		{"trailing data", "/findings/1/acknowledge", `{"note":"a"}{"note":"b"}`, "", 400, "invalid_body", "", ""},
		{"wrong content type", "/findings/1/acknowledge", `note=x`, "text/plain", 415, "unsupported_media_type", "", ""},
		{"note too long", "/findings/1/acknowledge", `{"note":"` + strings.Repeat("a", 2001) + `"}`, "", 400, "invalid_body", "", ""},
		{"body too large", "/findings/1/acknowledge", `{"note":"` + strings.Repeat("a", 70<<10) + `"}`, "", 413, "too_large", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.seed()
			var hdr []string
			if tt.ctype != "" {
				hdr = []string{"Content-Type", tt.ctype}
			}
			r := e.do("POST", "/api/v1"+tt.path, tt.body, hdr...)
			if r.Code != tt.status {
				t.Fatalf("status %d want %d: %s", r.Code, tt.status, r.Body)
			}
			if tt.status != 200 {
				if r.errCode(t) != tt.code {
					t.Errorf("code %q want %q", r.errCode(t), tt.code)
				}
				if len(e.store.Changes) != 0 {
					t.Error("failed request must not change state")
				}
				return
			}
			var f struct {
				Status          model.FindingStatus `json:"status"`
				SuppressionNote string              `json:"suppression_note"`
			}
			r.json(t, &f)
			if f.Status != tt.wantStatus || f.SuppressionNote != tt.wantNote {
				t.Errorf("response finding = %+v", f)
			}
			if len(e.store.Changes) != 1 {
				t.Fatalf("changes = %d", len(e.store.Changes))
			}
			c := e.store.Changes[0]
			if c.Status != tt.wantStatus || c.Note != tt.wantNote || c.Actor != "token" {
				t.Errorf("recorded change = %+v", c)
			}
			if strings.Contains(tt.body, "until") && tt.wantStatus != model.StatusOpen && c.Until == nil {
				t.Error("until not passed through")
			}
		})
	}
}

func TestRescanAndSync(t *testing.T) {
	e := newEnv(t)
	e.seed()
	if r := e.do("POST", "/api/v1/assets/1/rescan", ""); r.Code != 202 {
		t.Fatalf("rescan = %d %s", r.Code, r.Body)
	}
	if len(e.actions.rescans) != 1 || e.actions.rescans[0] != 1 {
		t.Errorf("rescans = %v", e.actions.rescans)
	}
	if r := e.do("POST", "/api/v1/assets/999/rescan", ""); r.Code != 404 {
		t.Errorf("rescan missing = %d", r.Code)
	}
	if r := e.do("POST", "/api/v1/assets/6/rescan", ""); r.Code != 409 {
		t.Errorf("rescan removed = %d", r.Code)
	}
	if r := e.do("POST", "/api/v1/assets/x/rescan", ""); r.Code != 400 {
		t.Errorf("rescan bad id = %d", r.Code)
	}
	if r := e.do("POST", "/api/v1/sources/cf/sync", ""); r.Code != 202 {
		t.Fatalf("sync = %d", r.Code)
	}
	if len(e.actions.syncs) != 1 || e.actions.syncs[0] != "cf" {
		t.Errorf("syncs = %v", e.actions.syncs)
	}
	if r := e.do("POST", "/api/v1/sources/cf/sync?x=1", ""); r.Code != 400 {
		t.Errorf("sync with query = %d", r.Code)
	}
	if r := e.do("POST", "/api/v1/sources/"+strings.Repeat("a", 300)+"/sync", ""); r.Code != 400 {
		t.Errorf("sync long name = %d", r.Code)
	}

	for _, tt := range []struct {
		err  error
		want int
	}{
		{api.ErrNotSupported, 501}, {api.ErrUnknownSource, 404}, {store.ErrNotFound, 404},
		{api.ErrBusy, 409}, {api.ErrNotScannable, 409}, {errors.New("kaboom"), 500},
	} {
		e.actions.syncErr, e.actions.rescanErr = tt.err, tt.err
		if r := e.do("POST", "/api/v1/sources/x/sync", ""); r.Code != tt.want {
			t.Errorf("sync err %v = %d want %d", tt.err, r.Code, tt.want)
		}
		if r := e.do("POST", "/api/v1/assets/1/rescan", ""); r.Code != tt.want {
			t.Errorf("rescan err %v = %d want %d", tt.err, r.Code, tt.want)
		}
	}
}

func TestDefaultActionsNotImplemented(t *testing.T) {
	e := newEnv(t, func(d *api.Deps) { d.Actions = nil })
	e.seed()
	if r := e.do("POST", "/api/v1/assets/1/rescan", ""); r.Code != 501 || r.errCode(t) != "not_implemented" {
		t.Errorf("rescan = %d %s", r.Code, r.Body)
	}
	if r := e.do("POST", "/api/v1/sources/cf/sync", ""); r.Code != 501 {
		t.Errorf("sync = %d", r.Code)
	}
}

func TestStoreErrorsAreSanitised(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.store.Do(func(s *fakestore.Store) { s.StatsErr = errors.New("pq: password authentication failed") })
	r := e.get("/api/v1/stats")
	if r.Code != 500 || strings.Contains(r.Body.String(), "pq:") {
		t.Errorf("leak: %d %s", r.Code, r.Body)
	}
	if !strings.Contains(e.logs.String(), "password authentication failed") {
		t.Error("store error should be logged server-side")
	}
}

func TestUnknownRoutes(t *testing.T) {
	e := newEnv(t)
	if r := e.get("/api/v1/nope"); r.Code != 404 || r.errCode(t) != "not_found" {
		t.Errorf("unknown api = %d %s", r.Code, r.Body)
	}
	if r := e.do("DELETE", "/api/v1/assets", ""); r.Code != 405 || r.errCode(t) != "method_not_allowed" {
		t.Errorf("wrong method = %d %s", r.Code, r.Body)
	}
	if r := e.get("/api/other"); r.Code != 404 || r.errCode(t) != "not_found" {
		t.Errorf("unknown /api = %d", r.Code)
	}
	// SPA fallback for anything else (placeholder UI embedded in tests).
	r := e.get("/some/spa/route")
	if r.Code != 200 || !strings.HasPrefix(r.Header().Get("Content-Type"), "text/html") {
		t.Errorf("spa fallback = %d %s", r.Code, r.Header().Get("Content-Type"))
	}
	if r := e.do("POST", "/some/spa/route", ""); r.Code != 405 {
		t.Errorf("POST to spa = %d", r.Code)
	}
}

func TestOpenAPIServed(t *testing.T) {
	e := newEnv(t)
	r := e.get("/api/v1/openapi.yaml")
	if r.Code != 200 || !strings.HasPrefix(r.Header().Get("Content-Type"), "application/yaml") || !strings.HasPrefix(r.Body.String(), "openapi: 3") {
		t.Fatalf("openapi = %d %s %.40s", r.Code, r.Header().Get("Content-Type"), r.Body)
	}
}

func httpGetNoAuth(e *env, target string) resp {
	req := newReq("GET", target)
	rec := newRec()
	e.h.ServeHTTP(rec, req)
	return resp{rec}
}

var _ = http.StatusOK
