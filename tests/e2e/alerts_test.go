//go:build staging

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

type amAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	EndsAt      time.Time         `json:"endsAt"`
	Fingerprint string            `json:"fingerprint"`
	Status      struct {
		State string `json:"state"`
	} `json:"status"`
}

var findingURL = regexp.MustCompile(`/findings/(\d+)$`)

// deckardAlerts returns the finding alerts one Alertmanager replica holds, keyed by
// finding id (parsed from the alert's url annotation). Rule alerts raised by
// Prometheus (label service=deckard) are not findings and are skipped.
func deckardAlerts(t *testing.T, base string) map[int]amAlert {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v2/alerts?silenced=true&inhibited=true&active=true", nil)
	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatalf("alertmanager %s: %v", base, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var all []amAlert
	if err := json.NewDecoder(resp.Body).Decode(&all); err != nil {
		t.Fatalf("alertmanager %s: %v", base, err)
	}
	out := map[int]amAlert{}
	for _, a := range all {
		if a.Labels["deckard_check"] == "" {
			continue
		}
		m := findingURL.FindStringSubmatch(a.Annotations["url"])
		if m == nil {
			t.Errorf("alert %s has no finding url annotation: %q", a.Labels["alertname"], a.Annotations["url"])
			continue
		}
		id, _ := strconv.Atoi(m[1])
		out[id] = a
	}
	return out
}

// Every open finding at or above the configured floor must be pushed to EVERY
// Alertmanager replica (peers do not replicate alerts), carry the context a
// responder needs, and nothing stale or below the floor may linger.
func TestAlertmanagerHoldsEveryNotifiableFindingOnEveryReplica(t *testing.T) {
	e := loadEnv(t)
	if len(e.alertmanagers) == 0 {
		t.Skip("set ALERTMANAGER_URLS to the base URL of every replica")
	}
	floor, ok := sevRank[e.minSeverity]
	if !ok {
		t.Fatalf("DECKARD_NOTIFY_MIN_SEVERITY=%q is not a severity", e.minSeverity)
	}
	eventually(t, 4, 20*time.Second, func() error {
		open := map[int]obj{}
		for _, f := range e.listAll(t, "/api/v1/findings", url2("status", "open")) {
			open[num(f, "id")] = f
		}
		var bad []string
		for i, base := range e.alertmanagers {
			held := deckardAlerts(t, base)
			for id, f := range open {
				if sevRank[str(f, "severity")] < floor {
					if _, present := held[id]; present {
						bad = append(bad, fmt.Sprintf("replica %d holds an alert for finding #%d (%s) below the floor %s", i, id, str(f, "severity"), e.minSeverity))
					}
					continue
				}
				a, present := held[id]
				if !present {
					bad = append(bad, fmt.Sprintf("replica %d is missing the alert for finding #%d %s on %s (%s)", i, id, str(f, "check"), str(f, "asset_key"), str(f, "severity")))
					continue
				}
				if a.Labels["severity"] != str(f, "severity") || a.Labels["asset"] != str(f, "asset_key") || a.Labels["deckard_check"] != str(f, "check") {
					bad = append(bad, fmt.Sprintf("replica %d: alert for #%d has labels %v, finding says %s/%s/%s", i, id, a.Labels, str(f, "severity"), str(f, "asset_key"), str(f, "check")))
				}
				if !a.EndsAt.After(time.Now()) {
					bad = append(bad, fmt.Sprintf("replica %d: alert for #%d has already expired (endsAt %s)", i, id, a.EndsAt.Format(time.RFC3339)))
				}
			}
			for id := range held {
				if _, still := open[id]; !still {
					bad = append(bad, fmt.Sprintf("replica %d holds an alert for finding #%d that is no longer open", i, id))
				}
			}
		}
		if len(bad) > 0 {
			n := len(bad)
			if n > 6 {
				bad = append(bad[:6], fmt.Sprintf("... and %d more", n-6))
			}
			return fmt.Errorf("%d alert discrepancies:\n  %s", n, strings.Join(bad, "\n  "))
		}
		return nil
	})
}

// A responder reads the alert, not the UI: it must say what, where, why and what to do.
func TestAlertsCarryResponderContext(t *testing.T) {
	e := loadEnv(t)
	if len(e.alertmanagers) == 0 {
		t.Skip("set ALERTMANAGER_URLS")
	}
	held := deckardAlerts(t, e.alertmanagers[0])
	if len(held) == 0 {
		t.Skip("no deckard alerts at the current floor")
	}
	var bad []string
	for id, a := range held {
		tag := fmt.Sprintf("#%d %s", id, a.Labels["alertname"])
		for _, k := range []string{"summary", "description", "url", "owner", "lineage", "first_seen"} {
			if strings.TrimSpace(a.Annotations[k]) == "" {
				bad = append(bad, tag+": empty annotation "+k)
			}
		}
		if sevRank[a.Labels["severity"]] >= sevRank["medium"] && strings.TrimSpace(a.Annotations["remediation"]) == "" {
			bad = append(bad, tag+": no remediation")
		}
		if !strings.HasPrefix(a.Annotations["url"], "http") {
			bad = append(bad, tag+": url is not absolute: "+a.Annotations["url"])
		}
		var ev any
		if err := json.Unmarshal([]byte(a.Annotations["evidence"]), &ev); err != nil {
			bad = append(bad, tag+": evidence annotation is not JSON")
		}
		for _, k := range []string{"deckard_check", "asset", "severity", "source"} {
			if a.Labels[k] == "" {
				bad = append(bad, tag+": missing label "+k)
			}
		}
	}
	report(t, "alert context", bad)
}
