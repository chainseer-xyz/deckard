//go:build staging

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// env is the target deployment, read from the environment.
//
//	DECKARD_URL             base URL of the API (e.g. http://127.0.0.1:18080)      required
//	DECKARD_TOKEN           admin bearer token                                     required
//	DECKARD_METRICS_URL     base URL of the metrics port                           optional
//	ALERTMANAGER_URLS       comma-separated base URLs of EVERY Alertmanager replica optional
//	DECKARD_NOTIFY_MIN_SEVERITY  configured notification floor (default info)      optional
//	DECKARD_E2E_MUTATE=1    also run the tests that change finding state           optional
//	DECKARD_OPENAPI         path to openapi.yaml (default ../../docs/openapi.yaml) optional
type env struct {
	base, token, metrics string
	alertmanagers        []string
	minSeverity          string
	mutate               bool
	spec                 *spec
}

var httpc = &http.Client{Timeout: 45 * time.Second}

func loadEnv(t *testing.T) env {
	t.Helper()
	e := env{
		base:        strings.TrimRight(os.Getenv("DECKARD_URL"), "/"),
		token:       os.Getenv("DECKARD_TOKEN"),
		metrics:     strings.TrimRight(os.Getenv("DECKARD_METRICS_URL"), "/"),
		minSeverity: os.Getenv("DECKARD_NOTIFY_MIN_SEVERITY"),
		mutate:      os.Getenv("DECKARD_E2E_MUTATE") == "1",
	}
	if e.base == "" || e.token == "" {
		t.Skip("set DECKARD_URL and DECKARD_TOKEN (see tests/e2e/README.md)")
	}
	if e.minSeverity == "" {
		e.minSeverity = "info"
	}
	for _, u := range strings.Split(os.Getenv("ALERTMANAGER_URLS"), ",") {
		if u = strings.TrimRight(strings.TrimSpace(u), "/"); u != "" {
			e.alertmanagers = append(e.alertmanagers, u)
		}
	}
	path := os.Getenv("DECKARD_OPENAPI")
	if path == "" {
		path = "../../docs/openapi.yaml"
	}
	sp, err := loadSpec(path)
	if err != nil {
		t.Fatalf("load openapi: %v", err)
	}
	e.spec = sp
	return e
}

// raw performs one request. A nil body sends none; withToken controls auth.
func (e env) raw(t *testing.T, method, path string, body any, withToken bool) (int, http.Header, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, e.base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withToken {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, resp.Header, b
}

// get fetches path with the token and decodes JSON into out (may be nil).
func (e env) get(t *testing.T, path string, out any) int {
	t.Helper()
	code, _, b := e.raw(t, http.MethodGet, path, nil, true)
	if out != nil && code == http.StatusOK {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("GET %s: bad JSON: %v\n%.300s", path, err, b)
		}
	}
	return code
}

type obj = map[string]any

type listPage struct {
	Items  []obj `json:"items"`
	Total  int   `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

// listAll pages through a list endpoint at the maximum page size and returns
// every item. It fails if the total moves while paging by more than a little
// (scans are continuous), and always if pages overlap.
func (e env) listAll(t *testing.T, path string, q url.Values) []obj {
	t.Helper()
	if q == nil {
		q = url.Values{}
	}
	q.Set("limit", "500")
	var all []obj
	seen := map[string]bool{}
	for off, total := 0, -1; ; {
		q.Set("offset", strconv.Itoa(off))
		var p listPage
		if code := e.get(t, path+"?"+q.Encode(), &p); code != http.StatusOK {
			t.Fatalf("GET %s?%s = %d", path, q.Encode(), code)
		}
		if total >= 0 && abs(p.Total-total) > 25 {
			t.Fatalf("%s: total moved from %d to %d while paging", path, total, p.Total)
		}
		total = p.Total
		for _, it := range p.Items {
			id := fmt.Sprint(it["id"])
			if it["id"] != nil && seen[id] {
				t.Fatalf("%s: item %s returned on two pages", path, id)
			}
			seen[id] = true
		}
		all = append(all, p.Items...)
		off += len(p.Items)
		if len(p.Items) == 0 || off >= p.Total {
			return all
		}
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

var sevRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func str(o obj, k string) string { s, _ := o[k].(string); return s }

func num(o obj, k string) int { f, _ := o[k].(float64); return int(f) }

func parseTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("bad time %q: %v", s, err)
	}
	return ts
}

// eventually retries fn until it returns no error or the budget is spent.
func eventually(t *testing.T, tries int, wait time.Duration, fn func() error) {
	t.Helper()
	var err error
	for i := 0; i < tries; i++ {
		if err = fn(); err == nil {
			return
		}
		time.Sleep(wait)
	}
	t.Fatal(err)
}

// report fails the test with at most max sample violations.
func report(t *testing.T, what string, bad []string) {
	t.Helper()
	if len(bad) == 0 {
		return
	}
	n := len(bad)
	if n > 8 {
		bad = append(bad[:8], fmt.Sprintf("... and %d more", n-8))
	}
	t.Errorf("%s: %d violation(s):\n  %s", what, n, strings.Join(bad, "\n  "))
}
