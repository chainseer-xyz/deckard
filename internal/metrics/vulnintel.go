package metrics

import (
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

// VulnintelSource is the slice of *vulnintel.Service the scrape-time
// collector reads.
type VulnintelSource interface {
	Status() vulnintel.Status
}

var (
	descVIAge     = prometheus.NewDesc("deckard_vulnintel_age_seconds", "Seconds since the last successful fetch of an exploit-intelligence feed (absent until the first success).", []string{"feed"}, nil)
	descVIEntries = prometheus.NewDesc("deckard_vulnintel_kev_entries", "Entries in the loaded CISA KEV catalog.", nil, nil)
)

// vulnintelMetrics holds the exploit-intelligence series. The counter and the
// kev_open gauge are fed by the engine's refresh job; age and entries are
// computed at scrape time from the registered source.
type vulnintelMetrics struct {
	refresh *prometheus.CounterVec
	kevOpen prometheus.Gauge
	src     atomic.Pointer[VulnintelSource]
	now     func() time.Time
}

func newVulnintelMetrics() *vulnintelMetrics {
	return &vulnintelMetrics{
		refresh: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "deckard_vulnintel_refresh_total", Help: "Exploit-intelligence feed refresh attempts by feed (kev, epss) and result (ok, not_modified, error).",
		}, []string{"feed", "result"}),
		kevOpen: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "deckard_findings_kev_open", Help: "Open findings tagged kev (CVE listed in CISA KEV), as of the last refresh job.",
		}),
		now: time.Now,
	}
}

// Describe implements prometheus.Collector (scrape-time series only).
func (v *vulnintelMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- descVIAge
	ch <- descVIEntries
}

// Collect implements prometheus.Collector.
func (v *vulnintelMetrics) Collect(ch chan<- prometheus.Metric) {
	p := v.src.Load()
	if p == nil {
		return
	}
	st := (*p).Status()
	ch <- prometheus.MustNewConstMetric(descVIEntries, prometheus.GaugeValue, float64(st.KEVEntries))
	for feed, at := range map[string]time.Time{"kev": st.KEVFetchedAt, "epss": st.EPSSFetchedAt} {
		if at.IsZero() {
			continue
		}
		age := v.now().Sub(at).Seconds()
		if age < 0 {
			age = 0
		}
		ch <- prometheus.MustNewConstMetric(descVIAge, prometheus.GaugeValue, age, feed)
	}
}

// RegisterVulnintel makes the age and entries gauges read src at scrape time.
func (m *Metrics) RegisterVulnintel(src VulnintelSource) {
	m.vi.src.Store(&src)
}

// ObserveVulnintelRefresh counts one feed refresh attempt.
func (m *Metrics) ObserveVulnintelRefresh(feed, result string) {
	m.vi.refresh.WithLabelValues(feed, result).Inc()
}

// SetKEVOpen sets the open-findings-tagged-kev gauge.
func (m *Metrics) SetKEVOpen(n int) { m.vi.kevOpen.Set(float64(n)) }
