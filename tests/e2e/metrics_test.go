//go:build staging

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"testing"
	"time"
)

var metricLine = regexp.MustCompile(`^(deckard_[a-z_]+)\{([^}]*)\}\s+([0-9.e+-]+)$`)

// scrape returns metric name -> label string -> value.
func scrape(t *testing.T, base string) map[string]map[string]float64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/metrics", nil)
	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	out := map[string]map[string]float64{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if m := metricLine.FindStringSubmatch(sc.Text()); m != nil {
			v, _ := strconv.ParseFloat(m[3], 64)
			if out[m[1]] == nil {
				out[m[1]] = map[string]float64{}
			}
			out[m[1]][m[2]] = v
		}
	}
	return out
}

// What Prometheus sees must be what the API says, or dashboards and alerts lie.
func TestMetricsAgreeWithAPI(t *testing.T) {
	e := loadEnv(t)
	if e.metrics == "" {
		t.Skip("set DECKARD_METRICS_URL")
	}
	eventually(t, 4, 20*time.Second, func() error {
		m := scrape(t, e.metrics)
		for _, scope := range []string{"owned", "external", "shared"} {
			var p listPage
			e.get(t, "/api/v1/assets?limit=1&scope="+scope, &p)
			got := m["deckard_assets"][fmt.Sprintf(`kind="all",scope=%q,source="all"`, scope)]
			if abs(int(got)-p.Total) > 5 {
				return fmt.Errorf("deckard_assets{scope=%s} = %v, API total = %d", scope, got, p.Total)
			}
		}
		for sev := range sevRank {
			var gte, gt listPage
			e.get(t, "/api/v1/findings?limit=1&status=open&min_severity="+sev, &gte)
			next := map[string]string{"info": "low", "low": "medium", "medium": "high", "high": "critical"}[sev]
			if next != "" {
				e.get(t, "/api/v1/findings?limit=1&status=open&min_severity="+next, &gt)
			}
			want := gte.Total - gt.Total
			got := m["deckard_findings_open"][fmt.Sprintf(`check="all",severity=%q`, sev)]
			if abs(int(got)-want) > 5 {
				return fmt.Errorf("deckard_findings_open{severity=%s} = %v, API says %d", sev, got, want)
			}
		}
		return nil
	})
}
