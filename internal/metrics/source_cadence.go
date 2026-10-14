package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// RegisterSourceCadence exposes configured sources, including never-seen remote
// producers. Source success timestamps alone cannot distinguish their cadence.
func (m *Metrics) RegisterSourceCadence(expected map[string]time.Duration) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "deckard_source_expected_interval_seconds", Help: "Configured native sync or remote discovery report interval per source."}, []string{"source"})
	for source, interval := range expected {
		if interval > 0 {
			gauge.WithLabelValues(source).Set(interval.Seconds())
		}
	}
	m.reg.MustRegister(gauge)
}
