package metrics_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/metrics"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

type fakeVISource struct{ st vulnintel.Status }

func (f fakeVISource) Status() vulnintel.Status { return f.st }

func TestVulnintelMetrics(t *testing.T) {
	m := metrics.New("v", "c")
	m.ObserveVulnintelRefresh("kev", "ok")
	m.ObserveVulnintelRefresh("kev", "ok")
	m.ObserveVulnintelRefresh("epss", "error")
	m.SetKEVOpen(3)

	out := scrape(t, m)
	for _, want := range []string{
		`deckard_vulnintel_refresh_total{feed="kev",result="ok"} 2`,
		`deckard_vulnintel_refresh_total{feed="epss",result="error"} 1`,
		`deckard_findings_kev_open 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "deckard_vulnintel_age_seconds") || strings.Contains(out, "deckard_vulnintel_kev_entries") {
		t.Error("age/entries emitted without a registered source")
	}

	m.RegisterVulnintel(fakeVISource{vulnintel.Status{KEVEntries: 1200, KEVFetchedAt: time.Now().Add(-time.Hour)}})
	out = scrape(t, m)
	if !strings.Contains(out, "deckard_vulnintel_kev_entries 1200") {
		t.Errorf("entries missing:\n%s", out)
	}
	if !strings.Contains(out, `deckard_vulnintel_age_seconds{feed="kev"} 3`) {
		t.Errorf("kev age missing")
	}
	if strings.Contains(out, `feed="epss"} `) && strings.Contains(out, `deckard_vulnintel_age_seconds{feed="epss"}`) {
		t.Error("epss age emitted although never fetched")
	}
}
