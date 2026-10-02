package metrics_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/metrics"
)

func TestNucleiTemplateMetrics(t *testing.T) {
	m := metrics.New("v1", "abc")

	// Before any update: counters exist at zero (so rate() and increase()
	// alerts work from the first scrape); the gauges are absent, so an
	// operator who mounts their own templates sees no bogus age.
	out := scrape(t, m)
	for _, want := range []string{
		`deckard_nuclei_template_updates_total{result="ok"} 0`,
		`deckard_nuclei_template_updates_total{result="error"} 0`,
		`deckard_nuclei_template_updates_total{result="unchanged"} 0`,
		`deckard_nuclei_new_templates_total 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	for _, absent := range []string{"deckard_nuclei_templates_age_seconds", "deckard_nuclei_template_count"} {
		if strings.Contains(out, absent+" ") {
			t.Errorf("%s must be absent before the first status", absent)
		}
	}

	m.ObserveTemplateUpdate("ok")
	m.ObserveTemplateUpdate("ok")
	m.ObserveTemplateUpdate("error")
	m.ObserveTemplateUpdate("unchanged")
	m.ObserveTemplateUpdate("bogus") // unknown results are not allowed to mint label values
	m.AddNewTemplates(12)
	m.AddNewTemplates(0)
	m.AddNewTemplates(-3)

	base := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	now := base.Add(90 * time.Minute)
	m.SetClock(func() time.Time { return now })
	m.SetTemplateStatus(13542, base)
	m.SetTemplateMaxAgeWarn(72 * time.Hour)

	out = scrape(t, m)
	for _, want := range []string{
		`deckard_nuclei_template_updates_total{result="ok"} 2`,
		`deckard_nuclei_template_updates_total{result="error"} 1`,
		`deckard_nuclei_template_updates_total{result="unchanged"} 1`,
		`deckard_nuclei_new_templates_total 12`,
		`deckard_nuclei_template_count 13542`,
		`deckard_nuclei_templates_age_seconds 5400`,
		`deckard_nuclei_templates_max_age_warn_seconds 259200`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in scrape", want)
		}
	}
	if strings.Contains(out, `result="bogus"`) {
		t.Error("unknown result created a series")
	}

	// The age keeps growing between updates, computed at scrape time.
	now = base.Add(5 * time.Hour)
	if out = scrape(t, m); !strings.Contains(out, `deckard_nuclei_templates_age_seconds 18000`) {
		t.Errorf("age did not advance:\n%s", out)
	}
	// A zero checked-at (nothing installed) clears the gauges.
	m.SetTemplateStatus(0, time.Time{})
	if out = scrape(t, m); strings.Contains(out, "deckard_nuclei_templates_age_seconds ") {
		t.Error("gauge must disappear for a zero checked-at")
	}
}
