//go:build staging

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func url2(k, v string) url.Values { return url.Values{k: {v}} }

func (e env) post(t *testing.T, path string, body any) (int, obj) {
	t.Helper()
	code, _, b := e.raw(t, http.MethodPost, path, body, true)
	var o obj
	_ = json.Unmarshal(b, &o)
	return code, o
}

func (e env) finding(t *testing.T, id int) obj {
	t.Helper()
	var f obj
	if code := e.get(t, fmt.Sprintf("/api/v1/findings/%d", id), &f); code != http.StatusOK {
		t.Fatalf("GET finding %d = %d", id, code)
	}
	return f
}

// pickDisposable returns a low-impact open finding (info or low, so it is below any
// sensible notification floor) to exercise state transitions on, and restores it.
func pickDisposable(t *testing.T, e env) obj {
	t.Helper()
	var p listPage
	e.get(t, "/api/v1/findings?status=open&limit=500", &p)
	for _, f := range p.Items {
		if sevRank[str(f, "severity")] <= sevRank["low"] && str(f, "check") == "http.headers" {
			return f
		}
	}
	for _, f := range p.Items {
		if sevRank[str(f, "severity")] <= sevRank["low"] {
			return f
		}
	}
	t.Skip("no open info/low finding to use")
	return nil
}

// State transitions are reversible and validated: every action is refused for bad
// input, accepted for good, reflected immediately, and undone by reopen.
func TestFindingStateTransitionsRoundTrip(t *testing.T) {
	e := loadEnv(t)
	if !e.mutate {
		t.Skip("set DECKARD_E2E_MUTATE=1 to run tests that change finding state")
	}
	f := pickDisposable(t, e)
	id := num(f, "id")
	path := func(a string) string { return fmt.Sprintf("/api/v1/findings/%d/%s", id, a) }
	t.Cleanup(func() { e.post(t, path("reopen"), obj{"note": "e2e cleanup"}) })

	// Validation first: nothing may change on a refused request.
	if code, _ := e.post(t, path("suppress"), obj{}); code != http.StatusBadRequest {
		t.Errorf("suppress without a note = %d, want 400", code)
	}
	if code, _ := e.post(t, path("acknowledge"), obj{"until": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}); code != http.StatusBadRequest {
		t.Errorf("acknowledge until a past time = %d, want 400", code)
	}
	if code, _ := e.post(t, path("acknowledge"), obj{"bogus": true}); code != http.StatusBadRequest {
		t.Errorf("unknown body field = %d, want 400", code)
	}
	if got := str(e.finding(t, id), "status"); got != "open" {
		t.Fatalf("refused requests changed the status to %s", got)
	}

	until := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	steps := []struct {
		action, want string
		body         obj
	}{
		{"acknowledge", "acknowledged", obj{"note": "e2e", "until": until}},
		{"reopen", "open", obj{"note": "e2e"}},
		{"suppress", "suppressed", obj{"note": "e2e suppress", "until": until}},
		{"reopen", "open", obj{"note": "e2e"}},
		{"false-positive", "false_positive", obj{"note": "e2e fp"}},
		{"reopen", "open", obj{"note": "e2e"}},
	}
	for _, s := range steps {
		code, got := e.post(t, path(s.action), s.body)
		if code != http.StatusOK {
			t.Fatalf("%s = %d (%v)", s.action, code, got)
		}
		if st := str(got, "status"); st != s.want {
			t.Errorf("%s returned status %q, want %q", s.action, st, s.want)
		}
		if st := str(e.finding(t, id), "status"); st != s.want {
			t.Errorf("after %s the finding reads %q, want %q", s.action, st, s.want)
		}
		if errs := e.spec.validate(e.spec.responseSchema("/api/v1/findings/{id}/"+s.action, "POST", "200"), anyOf(got)); len(errs) > 0 {
			t.Errorf("%s response violates the spec: %v", s.action, errs)
		}
	}
	if code, _ := e.post(t, "/api/v1/findings/2147483647/acknowledge", obj{}); code != http.StatusNotFound {
		t.Errorf("acknowledge on a missing finding = %d, want 404", code)
	}
}

func anyOf(o obj) any { return map[string]any(o) }

// A rescan request must be accepted and actually produce scan runs for the asset.
func TestRescanQueuesRealWork(t *testing.T) {
	e := loadEnv(t)
	if !e.mutate {
		t.Skip("set DECKARD_E2E_MUTATE=1")
	}
	f := pickDisposable(t, e)
	asset := num(f, "asset_id")
	before := time.Now().Add(-5 * time.Second)
	code, _ := e.post(t, fmt.Sprintf("/api/v1/assets/%d/rescan", asset), obj{})
	if code != http.StatusAccepted {
		t.Fatalf("rescan = %d, want 202", code)
	}
	eventually(t, 18, 10*time.Second, func() error {
		var p listPage
		e.get(t, "/api/v1/scans?limit=500", &p)
		for _, r := range p.Items {
			if num(r, "asset_id") == asset && parseTime(t, str(r, "started_at")).After(before) {
				return nil
			}
		}
		return fmt.Errorf("no scan run for asset %d started after the rescan request within 3 minutes", asset)
	})
	if code, _ := e.post(t, "/api/v1/assets/2147483647/rescan", obj{}); code != http.StatusNotFound {
		t.Errorf("rescan of a missing asset = %d, want 404", code)
	}
}

// Triggering a sync must queue one and the source's last_run must advance.
func TestSourceSyncTrigger(t *testing.T) {
	e := loadEnv(t)
	if !e.mutate {
		t.Skip("set DECKARD_E2E_MUTATE=1")
	}
	var p listPage
	e.get(t, "/api/v1/sources", &p)
	var name string
	var lastRun time.Time
	for _, s := range p.Items {
		if str(s, "type") == "kubernetes" { // cheap and safe to re-sync
			name, lastRun = str(s, "source"), parseTime(t, str(s, "last_run"))
		}
	}
	if name == "" {
		t.Skip("no kubernetes source to sync")
	}
	if code, _ := e.post(t, "/api/v1/sources/"+name+"/sync", obj{}); code != http.StatusAccepted {
		t.Fatalf("sync trigger = %d, want 202", code)
	}
	eventually(t, 15, 8*time.Second, func() error {
		var q listPage
		e.get(t, "/api/v1/sources", &q)
		for _, s := range q.Items {
			if str(s, "source") == name && parseTime(t, str(s, "last_run")).After(lastRun) {
				return nil
			}
		}
		return fmt.Errorf("source %s last_run did not advance past %s", name, lastRun.Format(time.RFC3339))
	})
	if code, _ := e.post(t, "/api/v1/sources/e2e-nonexistent/sync", obj{}); code != http.StatusNotFound {
		t.Errorf("sync of an unknown source = %d, want 404", code)
	}
}
