package metrics_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/metrics"
)

func TestSourceCadenceIncludesNeverSeenAndOmitsDisabled(t *testing.T) {
	m := metrics.New("v", "c")
	m.RegisterSourceCadence(map[string]time.Duration{"recon": 6 * time.Hour, "native": 10 * time.Minute, "disabled": 0})
	out := scrape(t, m)
	for _, want := range []string{`deckard_source_expected_interval_seconds{source="recon"} 21600`, `deckard_source_expected_interval_seconds{source="native"} 600`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing configured source: %s", out)
		}
	}
	if strings.Contains(out, `source="disabled"`) {
		t.Fatal("zero interval registered")
	}
}
