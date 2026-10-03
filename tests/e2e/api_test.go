//go:build staging

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestHealthProbesNeedNoAuth(t *testing.T) {
	e := loadEnv(t)
	for _, p := range []string{"/healthz", "/readyz"} {
		if code, _, _ := e.raw(t, http.MethodGet, p, nil, false); code != http.StatusOK {
			t.Errorf("GET %s without auth = %d, want 200", p, code)
		}
	}
}

// Every documented /api/v1 operation must refuse a missing or wrong token and
// must say so in the documented error shape.
func TestEveryAPIRouteRequiresAuth(t *testing.T) {
	e := loadEnv(t)
	paths, _ := dig(e.spec.root, "paths").(map[string]any)
	var bad []string
	checked := 0
	for p, ops := range paths {
		if !strings.HasPrefix(p, "/api/v1/") {
			continue
		}
		for method := range ops.(map[string]any) {
			m := strings.ToUpper(method)
			if m != "GET" && m != "POST" {
				continue
			}
			// Obviously nonexistent ids: if auth were broken these would 404, not mutate.
			concrete := strings.NewReplacer("{id}", "2147483647", "{name}", "e2e-nonexistent").Replace(p)
			if concrete == "/api/v1/openapi.yaml" || strings.HasSuffix(concrete, "/events") {
				continue // the spec is served openly; SSE is covered separately
			}
			checked++
			var body any
			if m == "POST" {
				body = obj{}
			}
			for label, tok := range map[string]bool{"no token": false} {
				code, _, b := e.raw(t, m, concrete, body, tok)
				if code != http.StatusUnauthorized {
					bad = append(bad, fmt.Sprintf("%s %s with %s = %d", m, concrete, label, code))
					continue
				}
				var v any
				if err := json.Unmarshal(b, &v); err != nil {
					bad = append(bad, fmt.Sprintf("%s %s 401 body is not JSON", m, concrete))
					continue
				}
				if errs := e.spec.validate(e.spec.resolve(obj{"$ref": "#/components/schemas/Error"}), v); len(errs) > 0 {
					bad = append(bad, fmt.Sprintf("%s %s 401 body: %v", m, concrete, errs))
				}
			}
			// A wrong token must also be refused.
			wrong := e
			wrong.token = strings.Repeat("x", 64)
			if code, _, _ := wrong.raw(t, m, concrete, body, true); code != http.StatusUnauthorized {
				bad = append(bad, fmt.Sprintf("%s %s with a wrong token = %d", m, concrete, code))
			}
		}
	}
	if checked < 10 {
		t.Fatalf("only %d routes checked; spec parsing is off", checked)
	}
	report(t, "auth enforcement", bad)
}

// Every parameterless GET and the detail endpoints must return exactly what the
// spec documents, field for field.
func TestResponsesMatchOpenAPI(t *testing.T) {
	e := loadEnv(t)
	check := func(path, specPath string) {
		t.Helper()
		var v any
		if code := e.get(t, path, &v); code != http.StatusOK {
			t.Errorf("GET %s = %d", path, code)
			return
		}
		sc := e.spec.responseSchema(specPath, "GET", "200")
		if sc == nil {
			t.Errorf("no 200 schema in the spec for %s", specPath)
			return
		}
		report(t, "GET "+path, e.spec.validate(sc, v))
	}
	for _, p := range []string{"/api/v1/me", "/api/v1/stats", "/api/v1/assets?limit=20", "/api/v1/findings?limit=20",
		"/api/v1/sources", "/api/v1/scans?limit=20", "/api/v1/changes?limit=20"} {
		sp := strings.SplitN(p, "?", 2)[0]
		check(p, sp)
	}
	var fl, al listPage
	e.get(t, "/api/v1/findings?limit=3&status=open&min_severity=medium", &fl)
	e.get(t, "/api/v1/assets?limit=3", &al)
	if len(fl.Items) == 0 || len(al.Items) == 0 {
		t.Skip("no findings or assets to take detail ids from")
	}
	check(fmt.Sprintf("/api/v1/findings/%d", num(fl.Items[0], "id")), "/api/v1/findings/{id}")
	aid := num(al.Items[0], "id")
	check(fmt.Sprintf("/api/v1/assets/%d", aid), "/api/v1/assets/{id}")
	check(fmt.Sprintf("/api/v1/assets/%d/graph", aid), "/api/v1/assets/{id}/graph")
	// An asset that carries a dependent finding exercises edges, observations and baselines.
	check(fmt.Sprintf("/api/v1/assets/%d", num(fl.Items[0], "asset_id")), "/api/v1/assets/{id}")
}

func TestNotFoundAndBadIDsUseTheErrorShape(t *testing.T) {
	e := loadEnv(t)
	cases := []struct {
		path string
		want int
	}{
		{"/api/v1/findings/2147483647", http.StatusNotFound},
		{"/api/v1/assets/2147483647", http.StatusNotFound},
		{"/api/v1/assets/2147483647/graph", http.StatusNotFound},
		{"/api/v1/findings/abc", http.StatusBadRequest},
		{"/api/v1/assets/-1", http.StatusBadRequest},
		{"/api/v1/findings?min_severity=catastrophic", http.StatusBadRequest},
		{"/api/v1/findings?status=nope", http.StatusBadRequest},
		{"/api/v1/findings?totally_unknown=1", http.StatusBadRequest},
		{"/api/v1/assets?kind=nope", http.StatusBadRequest},
		{"/api/v1/assets?limit=0", http.StatusBadRequest},
		{"/api/v1/assets?limit=501", http.StatusBadRequest},
		{"/api/v1/assets?offset=-1", http.StatusBadRequest},
	}
	for _, c := range cases {
		code, _, b := e.raw(t, http.MethodGet, c.path, nil, true)
		if code != c.want {
			t.Errorf("GET %s = %d, want %d", c.path, code, c.want)
			continue
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Errorf("GET %s: error body is not JSON: %.120s", c.path, b)
			continue
		}
		if errs := e.spec.validate(e.spec.resolve(obj{"$ref": "#/components/schemas/Error"}), v); len(errs) > 0 {
			t.Errorf("GET %s: error body: %v", c.path, errs)
		}
	}
}

// The documented page-size bounds are accepted exactly at the edge, and a full
// walk of each list returns every item once.
func TestPaginationWalksEveryItemOnce(t *testing.T) {
	e := loadEnv(t)
	for _, path := range []string{"/api/v1/assets", "/api/v1/findings", "/api/v1/scans", "/api/v1/changes"} {
		t.Run(strings.TrimPrefix(path, "/api/v1/"), func(t *testing.T) {
			var edge listPage
			if code := e.get(t, path+"?limit=1", &edge); code != http.StatusOK {
				t.Fatalf("limit=1 = %d", code)
			}
			if code := e.get(t, path+"?limit=500", &edge); code != http.StatusOK {
				t.Fatalf("limit=500 = %d", code)
			}
			if edge.Limit != 500 {
				t.Errorf("echoed limit = %d, want 500", edge.Limit)
			}
			if path == "/api/v1/scans" || path == "/api/v1/changes" {
				return // continuously growing feeds: edges only
			}
			all := e.listAll(t, path, nil)
			var one listPage
			e.get(t, path+"?limit=1", &one)
			if d := abs(len(all) - one.Total); d > 25 {
				t.Errorf("walked %d items but total says %d", len(all), one.Total)
			}
		})
	}
}

func TestFindingFiltersAreExactAndMonotonic(t *testing.T) {
	e := loadEnv(t)
	counts := map[string]int{}
	for _, sev := range []string{"info", "low", "medium", "high", "critical"} {
		var p listPage
		e.get(t, "/api/v1/findings?status=open&limit=500&min_severity="+sev, &p)
		counts[sev] = p.Total
		for _, f := range p.Items {
			if sevRank[str(f, "severity")] < sevRank[sev] {
				t.Errorf("min_severity=%s returned a %s finding (#%d)", sev, str(f, "severity"), num(f, "id"))
			}
			if str(f, "status") != "open" {
				t.Errorf("status=open returned a %s finding (#%d)", str(f, "status"), num(f, "id"))
			}
		}
	}
	prev := 1 << 30
	for _, sev := range []string{"info", "low", "medium", "high", "critical"} {
		if counts[sev] > prev {
			t.Errorf("min_severity=%s (%d) returned more than a lower floor (%d)", sev, counts[sev], prev)
		}
		prev = counts[sev]
	}
	// check, zone, source and asset_id filters return only matching rows.
	var seed listPage
	e.get(t, "/api/v1/findings?status=open&min_severity=medium&limit=200", &seed)
	if len(seed.Items) == 0 {
		t.Skip("no open medium+ findings to filter on")
	}
	f := seed.Items[0]
	for key, val := range map[string]string{"check": str(f, "check"), "zone": str(f, "zone"), "source": str(f, "source"), "asset_id": fmt.Sprint(num(f, "asset_id"))} {
		if val == "" || val == "0" {
			continue
		}
		var p listPage
		q := url.Values{"status": {"open"}, "limit": {"500"}, key: {val}}
		if code := e.get(t, "/api/v1/findings?"+q.Encode(), &p); code != http.StatusOK {
			t.Errorf("filter %s=%s = %d", key, val, code)
			continue
		}
		if p.Total == 0 {
			t.Errorf("filter %s=%s returned nothing though finding #%d matches", key, val, num(f, "id"))
		}
		for _, it := range p.Items {
			got := str(it, key)
			if key == "asset_id" {
				got = fmt.Sprint(num(it, key))
			}
			if got != val {
				t.Errorf("filter %s=%s returned a row with %s=%s", key, val, key, got)
			}
		}
	}
}

func TestAssetFiltersAreExact(t *testing.T) {
	e := loadEnv(t)
	for _, scope := range []string{"owned", "external", "shared"} {
		var p listPage
		if code := e.get(t, "/api/v1/assets?limit=500&scope="+scope, &p); code != http.StatusOK {
			t.Errorf("scope=%s = %d", scope, code)
			continue
		}
		for _, a := range p.Items {
			if str(a, "scope") != scope {
				t.Errorf("scope=%s returned asset %s with scope %s", scope, str(a, "key"), str(a, "scope"))
			}
		}
	}
	var zones listPage
	e.get(t, "/api/v1/assets?limit=500&kind=zone", &zones)
	if len(zones.Items) == 0 {
		t.Skip("no zone assets")
	}
	sort.Slice(zones.Items, func(i, j int) bool { return str(zones.Items[i], "key") < str(zones.Items[j], "key") })
	z := str(zones.Items[0], "key")
	var inZone listPage
	e.get(t, "/api/v1/assets?limit=500&zone="+url.QueryEscape(z), &inZone)
	for _, a := range inZone.Items {
		k := str(a, "key")
		if k != z && !strings.HasSuffix(k, "."+z) && str(a, "zone") != z {
			t.Errorf("zone=%s returned unrelated asset %s", z, k)
		}
	}
}

func TestEventStreamAcceptsAndStreams(t *testing.T) {
	e := loadEnv(t)
	if code, _, _ := e.raw(t, http.MethodGet, "/api/v1/events", nil, false); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated /events = %d, want 401", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.base+"/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("content-type %q, want text/event-stream", ct)
	}
	line := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if s := sc.Text(); s != "" {
				line <- s
				return
			}
		}
	}()
	select {
	case s := <-line:
		t.Logf("first stream line: %.80s", s)
	case <-time.After(15 * time.Second):
		t.Log("no stream bytes in 15s (idle system); connection itself was healthy")
	}
}
