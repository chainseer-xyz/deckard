package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// intelMetrics tracks the restricted third-party metadata client
// (internal/intel). *Metrics satisfies intel.Recorder.
type intelMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

func newIntelMetrics() *intelMetrics {
	return &intelMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "deckard_intel_requests_total",
			Help: "Metadata-service requests (RDAP, InternetDB, Wayback) by result: ok, cached, not_found, rate_limited, error, blocked. blocked indicates a bug or a misbehaving upstream redirect.",
		}, []string{"service", "result"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "deckard_intel_request_duration_seconds",
			Help:    "Duration of individual upstream metadata-service attempts (cache hits are not observed).",
			Buckets: []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 20},
		}, []string{"service"}),
	}
}

// IntelRequest counts one metadata-service request.
func (m *Metrics) IntelRequest(service, result string) {
	m.intel.requests.WithLabelValues(service, result).Inc()
}

// IntelDuration observes one upstream metadata-service attempt.
func (m *Metrics) IntelDuration(service string, d time.Duration) {
	m.intel.duration.WithLabelValues(service).Observe(d.Seconds())
}
