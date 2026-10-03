//go:build staging

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The e2e self-test producer. Its findings are info severity (below any
// sensible notification floor) and attach to one cloud_resource asset that
// deckard never probes.
const (
	selftestTool  = "e2e-selftest"
	selftestCheck = "ext." + selftestTool
	selftestScope = "e2e:deckard-selftest"
)

// The ingest endpoint is documented, so the auth sweep in
// TestEveryAPIRouteRequiresAuth already posts to it without and with a wrong
// token. This only pins that it is part of that sweep and that the wrong
// method is refused in the documented error shape, neither of which writes.
func TestIngestIsDocumentedAndGuarded(t *testing.T) {
	e := loadEnv(t)
	if e.spec.responseSchema("/api/v1/ingest", "POST", "200") == nil {
		t.Fatal("POST /api/v1/ingest has no documented 200 response")
	}
	code, _, b := e.raw(t, http.MethodGet, "/api/v1/ingest", nil, true)
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/v1/ingest = %d, want 405", code)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("405 body is not JSON: %.120s", b)
	}
	report(t, "GET /api/v1/ingest 405 body", e.spec.validate(e.spec.resolve(obj{"$ref": "#/components/schemas/Error"}), v))
}

// ingestPost posts a self-test run observed at obs, waiting out the rate
// limit if needed, and checks the response against the spec.
func (e env) ingestPost(t *testing.T, obs time.Time, findings []obj) obj {
	t.Helper()
	if findings == nil {
		findings = []obj{}
	}
	body := obj{"tool": selftestTool, "scope": selftestScope, "complete": true,
		"observed_at": obs.UTC().Format(time.RFC3339Nano), "findings": findings}
	for attempt := 0; attempt < 5; attempt++ {
		code, hdr, b := e.raw(t, http.MethodPost, "/api/v1/ingest", body, true)
		if code == http.StatusTooManyRequests {
			wait, _ := strconv.Atoi(hdr.Get("Retry-After"))
			time.Sleep(time.Duration(max(wait, 1)) * time.Second)
			continue
		}
		if code != http.StatusOK {
			t.Fatalf("POST /api/v1/ingest = %d: %.300s", code, b)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("ingest response is not JSON: %.200s", b)
		}
		report(t, "POST /api/v1/ingest 200 body", e.spec.validate(e.spec.responseSchema("/api/v1/ingest", "POST", "200"), v))
		return obj(v.(map[string]any))
	}
	t.Fatal("ingest rate limited five times in a row")
	return nil
}

func (e env) selftestFindings(t *testing.T, status string) []obj {
	t.Helper()
	q := url.Values{"check": {selftestCheck}}
	if status != "" {
		q.Set("status", status)
	}
	return e.listAll(t, "/api/v1/findings", q)
}

// clock hands out strictly increasing observed_at values: a run must be newer
// than every accepted one to resolve anything.
type clock struct{ last time.Time }

func (c *clock) next() time.Time {
	n := time.Now().UTC()
	if !n.After(c.last) {
		n = c.last.Add(time.Millisecond)
	}
	c.last = n
	return n
}

// drain posts empty complete runs until the self-test scope has no open
// finding (bounded): the cleanup for this test and for an aborted earlier run.
func (e env) drain(t *testing.T, c *clock) {
	t.Helper()
	for i := 0; i < 10 && len(e.selftestFindings(t, "open")) > 0; i++ {
		e.ingestPost(t, c.next(), nil)
	}
	if left := e.selftestFindings(t, "open"); len(left) > 0 {
		t.Errorf("%d open %s finding(s) left behind", len(left), selftestCheck)
	}
}

// A tiny self-test run appears as an open ext.e2e-selftest finding, a replay
// changes nothing, and empty complete runs resolve it after the configured
// miss count (findings.resolve_after). Nothing open is left behind.
func TestIngestRoundTrip(t *testing.T) {
	e := loadEnv(t)
	if !e.mutate {
		t.Skip("set DECKARD_E2E_MUTATE=1 to run tests that write findings")
	}
	c := &clock{}
	e.drain(t, c)
	t.Cleanup(func() { e.drain(t, c) })

	item := obj{
		"key":         "selftest",
		"asset":       obj{"kind": "cloud_resource", "key": "e2e-selftest:deckard"},
		"title":       "deckard e2e ingest self-test",
		"description": "Posted by the deckard end-to-end suite; resolved by the same run.",
		"severity":    "info",
		"tags":        []string{selftestTool, "selftest"},
		"evidence":    obj{"suite": "tests/e2e"},
	}
	first := c.next()
	got := e.ingestPost(t, first, []obj{item})
	if num(got, "accepted") != 1 || num(got, "opened")+num(got, "reopened") != 1 || got["complete"] != true {
		t.Fatalf("first run: %v", got)
	}
	open := e.selftestFindings(t, "open")
	if len(open) != 1 {
		t.Fatalf("open %s findings = %d, want 1", selftestCheck, len(open))
	}
	f := open[0]
	if str(f, "check") != selftestCheck || str(f, "source") != "ingest:"+selftestTool || str(f, "ingest_scope") != selftestScope {
		t.Fatalf("finding = %v", f)
	}
	id := num(f, "id")
	report(t, "GET finding", e.spec.validate(e.spec.responseSchema("/api/v1/findings/{id}", "GET", "200"), map[string]any(e.finding(t, id))))

	// The same delivery again is a no-op.
	b, _ := json.Marshal(item)
	var again obj
	_ = json.Unmarshal(b, &again)
	if r := e.ingestPost(t, first, []obj{again}); r["replay"] != true || num(r, "accepted") != 0 {
		t.Fatalf("replay: %v", r)
	}

	// Empty complete runs: the finding accrues one miss per run and resolves
	// exactly at findings.resolve_after.
	for misses := 1; misses <= 10; misses++ {
		r := e.ingestPost(t, c.next(), nil)
		cur := e.finding(t, id)
		if num(cur, "missed_runs") != misses {
			t.Fatalf("after %d empty runs missed_runs = %d", misses, num(cur, "missed_runs"))
		}
		if str(cur, "status") == "resolved" {
			if num(r, "resolved") != 1 {
				t.Errorf("resolving run reported resolved=%d", num(r, "resolved"))
			}
			t.Logf("resolved after %d complete misses", misses)
			return
		}
		if num(r, "resolved_pending") != 1 || str(cur, "status") != "open" {
			t.Fatalf("miss %d: response %v, status %s", misses, r, str(cur, "status"))
		}
	}
	t.Fatalf("finding %d not resolved after 10 complete misses", id)
}

// The ingest safety invariant, observed on the live system: no scan run (not
// even a skipped one) ever names an asset created by the ingest API, because
// the scheduler never selects one. Read-only.
func TestIngestedAssetsAreNeverScanned(t *testing.T) {
	e := loadEnv(t)
	assets := e.listAll(t, "/api/v1/assets", url.Values{"include_removed": {"true"}})
	ingested := map[int]string{}
	for _, a := range assets {
		if strings.HasPrefix(str(a, "source"), "ingest:") {
			ingested[num(a, "id")] = str(a, "key")
		}
	}
	if len(ingested) == 0 {
		t.Skip("no ingested assets")
	}
	var bad []string
	var p listPage
	e.get(t, "/api/v1/scans?limit=500", &p)
	for _, r := range p.Items {
		if key, ok := ingested[num(r, "asset_id")]; ok {
			bad = append(bad, fmt.Sprintf("scan run #%d (%s) on ingested asset %s: %s", num(r, "id"), str(r, "check"), key, str(r, "error")))
		}
	}
	report(t, "scan runs on ingested assets", bad)
}
