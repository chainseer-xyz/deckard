package api_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func TestCompletePagedFindingQueries(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.store.Do(func(s *fakestore.Store) {
		s.Findings = map[int64]model.Finding{}
		for i := int64(1); i <= 6005; i++ {
			s.Findings[i] = model.Finding{ID: i, AssetID: 1, AssetKey: "host.example", Zone: "example", Check: "mass", Status: model.StatusOpen, Severity: model.SeverityHigh, FirstSeen: time.Unix(i, 0), LastSeen: time.Unix(i, 0), Title: fmt.Sprintf("finding-%d", i)}
		}
		tail := s.Findings[6005]
		tail.Severity, tail.Zone = model.SeverityCritical, ""
		s.Findings[6005] = tail
	})
	var page listOut
	e.get("/api/v1/findings?severity=high&sort=first_seen&direction=asc&limit=50&offset=5000").json(t, &page)
	if page.Total != 6004 || len(page.Items) != 50 || !eq(ids(page), integerRange(5001, 5051)) {
		t.Fatalf("bounded complete page: total=%d ids=%v", page.Total, ids(page))
	}
	e.get("/api/v1/findings?group_by=zone&sort=count&limit=1").json(t, &page)
	if page.Total != 2 || len(page.Items) != 1 || page.Items[0]["total"] != float64(6004) {
		t.Fatalf("complete groups: %+v", page)
	}
	e.get("/api/v1/findings?group_by=zone&group_key=&limit=50").json(t, &page)
	if page.Total != 1 || !eq(ids(page), []int{6005}) {
		t.Fatalf("empty-zone members: %+v", page)
	}
	for _, query := range []string{"sort=title", "direction=sideways", "group_by=severity", "group_key=x", "severity=urgent", "first_seen_after=no", "attention=maybe", "sort=count", "group_by=zone&group_key=x&sort=count"} {
		if r := e.get("/api/v1/findings?" + query); r.Code != 400 {
			t.Errorf("invalid query %q returned %d", query, r.Code)
		}
	}
}

func integerRange(start, end int) []int {
	var out []int
	for i := start; i < end; i++ {
		out = append(out, i)
	}
	return out
}

func TestAssetPageSummaries(t *testing.T) {
	e := newEnv(t)
	e.seed()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	e.store.Do(func(s *fakestore.Store) {
		s.Scans = []store.ScanRun{{AssetID: 1, Check: "tls.cert", StartedAt: now}}
	})
	var page listOut
	e.get("/api/v1/assets?include_summary=true&open_min_severity=high").json(t, &page)
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0]["open_findings"] != float64(2) || page.Items[0]["top_severity"] != "high" || page.Items[0]["last_scan"] != now.Format(time.RFC3339) {
		t.Fatalf("asset summary/filter: %+v", page)
	}
	for _, query := range []string{"include_summary=wat", "open_min_severity=urgent"} {
		if r := e.get("/api/v1/assets?" + query); r.Code != 400 {
			t.Errorf("invalid query %q returned %d", query, r.Code)
		}
	}
}
