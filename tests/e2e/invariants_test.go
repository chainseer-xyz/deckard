//go:build staging

package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// The safety invariant, observed on the live system: a finding exists only on
// an asset deckard may probe, i.e. an owned one.
func TestFindingsExistOnlyOnOwnedAssets(t *testing.T) {
	e := loadEnv(t)
	findings := e.listAll(t, "/api/v1/findings", nil)
	if len(findings) == 0 {
		t.Skip("no findings")
	}
	ids := map[int][]string{}
	for _, f := range findings {
		ids[num(f, "asset_id")] = append(ids[num(f, "asset_id")], str(f, "check"))
	}
	type res struct {
		id    int
		scope string
		key   string
		code  int
	}
	out := make(chan res, len(ids))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(id int) {
			defer wg.Done()
			defer func() { <-sem }()
			var a obj
			code := e.get(t, fmt.Sprintf("/api/v1/assets/%d", id), &a)
			asset, _ := a["asset"].(obj)
			if asset == nil {
				asset = a
			}
			out <- res{id, str(asset, "scope"), str(asset, "key"), code}
		}(id)
	}
	wg.Wait()
	close(out)
	var bad []string
	for r := range out {
		switch {
		case r.code != http.StatusOK:
			bad = append(bad, fmt.Sprintf("asset %d (checks %v): GET = %d", r.id, ids[r.id], r.code))
		case r.scope != "owned":
			bad = append(bad, fmt.Sprintf("asset %d %s has scope %q but carries findings from %v", r.id, r.key, r.scope, ids[r.id]))
		}
	}
	report(t, "findings on non-owned assets", bad)
}

func TestFindingFieldInvariants(t *testing.T) {
	e := loadEnv(t)
	findings := e.listAll(t, "/api/v1/findings", nil)
	ids := map[int]bool{}
	fps := map[string]int{}
	var bad []string
	for _, f := range findings {
		id := num(f, "id")
		tag := fmt.Sprintf("#%d %s", id, str(f, "check"))
		if ids[id] {
			bad = append(bad, tag+": duplicate id")
		}
		ids[id] = true
		if _, ok := sevRank[str(f, "severity")]; !ok {
			bad = append(bad, tag+": bad severity "+str(f, "severity"))
		}
		for _, k := range []string{"title", "description", "check", "asset_key", "fingerprint"} {
			if strings.TrimSpace(str(f, k)) == "" {
				bad = append(bad, tag+": empty "+k)
			}
		}
		if sevRank[str(f, "severity")] >= sevRank["medium"] && strings.TrimSpace(str(f, "remediation")) == "" {
			bad = append(bad, tag+": medium+ finding without remediation")
		}
		if _, ok := f["evidence"].(obj); !ok {
			bad = append(bad, tag+": evidence is not an object")
		}
		first, last := parseTime(t, str(f, "first_seen")), parseTime(t, str(f, "last_seen"))
		if last.Before(first) {
			bad = append(bad, tag+": last_seen before first_seen")
		}
		if first.After(time.Now().Add(5 * time.Minute)) {
			bad = append(bad, tag+": first_seen in the future")
		}
		status := str(f, "status")
		if (status == "resolved") != (f["resolved_at"] != nil) {
			bad = append(bad, fmt.Sprintf("%s: status %s but resolved_at=%v", tag, status, f["resolved_at"]))
		}
		if f["suppressed_until"] != nil && status != "suppressed" && status != "acknowledged" {
			bad = append(bad, fmt.Sprintf("%s: suppressed_until set while %s", tag, status))
		}
		if num(f, "reopened_count") < 0 || num(f, "missed_runs") < 0 {
			bad = append(bad, tag+": negative counter")
		}
		if status == "open" {
			fps[fmt.Sprintf("%d/%s", num(f, "asset_id"), str(f, "fingerprint"))]++
		}
	}
	for k, n := range fps {
		if n > 1 {
			bad = append(bad, fmt.Sprintf("fingerprint %s open %d times on one asset", k, n))
		}
	}
	report(t, "finding invariants", bad)
}

func TestAssetFieldInvariants(t *testing.T) {
	e := loadEnv(t)
	assets := e.listAll(t, "/api/v1/assets", nil)
	if len(assets) == 0 {
		t.Fatal("inventory is empty")
	}
	seen := map[string]bool{}
	var bad []string
	for _, a := range assets {
		key := str(a, "key")
		tag := fmt.Sprintf("asset %d %q", num(a, "id"), key)
		if key == "" {
			bad = append(bad, tag+": empty key")
		}
		if str(a, "kind") == "hostname" || str(a, "kind") == "zone" {
			if key != strings.ToLower(key) || strings.HasSuffix(key, ".") || strings.ContainsAny(key, " /") {
				bad = append(bad, tag+": hostname not normalised")
			}
		}
		id := str(a, "kind") + "|" + key
		if seen[id] {
			bad = append(bad, tag+": duplicate (kind,key)")
		}
		seen[id] = true
		if _, ok := map[string]bool{"owned": true, "external": true, "shared": true}[str(a, "scope")]; !ok {
			bad = append(bad, tag+": bad scope "+str(a, "scope"))
		}
		if parseTime(t, str(a, "last_seen")).Before(parseTime(t, str(a, "first_seen"))) {
			bad = append(bad, tag+": last_seen before first_seen")
		}
	}
	report(t, "asset invariants", bad)
}

// /stats must agree with what the list endpoints say, within live churn.
func TestStatsAgreeWithLists(t *testing.T) {
	e := loadEnv(t)
	eventually(t, 4, 6*time.Second, func() error {
		var st struct {
			AssetsByScope      map[string]int `json:"assets_by_scope"`
			FindingsBySeverity map[string]int `json:"findings_by_severity"`
		}
		e.get(t, "/api/v1/stats", &st)
		for scope, n := range st.AssetsByScope {
			var p listPage
			e.get(t, "/api/v1/assets?limit=1&scope="+scope, &p)
			if abs(p.Total-n) > 5 {
				return fmt.Errorf("stats says %d %s assets, list says %d", n, scope, p.Total)
			}
		}
		for sev, n := range st.FindingsBySeverity {
			var p listPage
			e.get(t, "/api/v1/findings?limit=1&status=open&min_severity="+sev, &p)
			var above int
			for s, r := range sevRank {
				if r > sevRank[sev] {
					var q listPage
					e.get(t, "/api/v1/findings?limit=1&status=open&min_severity="+s, &q)
					above = max(above, q.Total)
				}
			}
			exact := p.Total - above
			if abs(exact-n) > 5 {
				return fmt.Errorf("stats says %d open %s findings, list says about %d", n, sev, exact)
			}
		}
		return nil
	})
}

// A source that has not synced recently means the inventory is going stale and
// removals are blocked; both must be visible rather than silent.
func TestSourcesAreFreshAndHonest(t *testing.T) {
	e := loadEnv(t)
	var p listPage
	e.get(t, "/api/v1/sources", &p)
	if len(p.Items) == 0 {
		t.Fatal("no sources configured")
	}
	var bad []string
	for _, s := range p.Items {
		name := str(s, "source")
		if str(s, "last_ok") == "" {
			bad = append(bad, name+": has never completed a sync")
			continue
		}
		if age := time.Since(parseTime(t, str(s, "last_ok"))); age > 30*time.Minute {
			bad = append(bad, fmt.Sprintf("%s: last good sync %s ago", name, age.Round(time.Minute)))
		}
		if str(s, "error") != "" {
			bad = append(bad, name+": error: "+str(s, "error"))
		}
		if w := str(s, "warning"); w != "" {
			t.Logf("source %s reports a partial sync: %s", name, w)
		}
		if num(s, "asset_count") == 0 {
			bad = append(bad, name+": zero assets")
		}
	}
	report(t, "source health", bad)
}

func TestChangeFeedIsOrderedAndUnique(t *testing.T) {
	e := loadEnv(t)
	var p listPage
	e.get(t, "/api/v1/changes?limit=100", &p)
	if len(p.Items) < 2 {
		t.Skip("change feed too short")
	}
	seen := map[int]bool{}
	var prev time.Time
	var bad []string
	for i, ev := range p.Items {
		id := num(ev, "id")
		if seen[id] {
			bad = append(bad, fmt.Sprintf("duplicate event id %d", id))
		}
		seen[id] = true
		at := parseTime(t, str(ev, "at"))
		if i > 0 && at.After(prev) {
			bad = append(bad, fmt.Sprintf("event %d is newer than the one before it (feed must be newest first)", id))
		}
		prev = at
		if str(ev, "type") == "" || str(ev, "subject") == "" {
			bad = append(bad, fmt.Sprintf("event %d has an empty type or subject", id))
		}
	}
	report(t, "change feed", bad)
	// `since` must return only newer events.
	cut := str(p.Items[len(p.Items)/2], "at")
	var after listPage
	e.get(t, "/api/v1/changes?limit=500&since="+cut, &after)
	for _, ev := range after.Items {
		if parseTime(t, str(ev, "at")).Before(parseTime(t, cut)) {
			t.Errorf("since=%s returned older event %d at %s", cut, num(ev, "id"), str(ev, "at"))
		}
	}
}
