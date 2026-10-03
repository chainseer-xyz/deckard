package metrics_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/intel"
	"github.com/chainseer-xyz/deckard/internal/metrics"
)

var _ intel.Recorder = (*metrics.Metrics)(nil)

func TestIntelMetrics(t *testing.T) {
	m := metrics.New("v", "c")
	m.IntelRequest("rdap", "ok")
	m.IntelRequest("rdap", "ok")
	m.IntelRequest("rdap", "blocked")
	m.IntelDuration("rdap", 300*time.Millisecond)

	out := scrape(t, m)
	for _, want := range []string{
		`deckard_intel_requests_total{result="ok",service="rdap"} 2`,
		`deckard_intel_requests_total{result="blocked",service="rdap"} 1`,
		`deckard_intel_request_duration_seconds_count{service="rdap"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}
