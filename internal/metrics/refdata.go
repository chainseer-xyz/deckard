package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// refdataMetrics tracks the live refresh of the embedded reference datasets.
// *Metrics exposes it through ObserveRefdata / SetRefdataState, which satisfy
// refdata.Recorder.
type refdataMetrics struct {
	entries *prometheus.GaugeVec
	total   *prometheus.CounterVec
	now     func() time.Time

	mu      sync.Mutex
	updated map[string]time.Time
}

var descRefdataAge = prometheus.NewDesc("deckard_refdata_age_seconds",
	"Seconds since the dataset was last verified fresh (refreshed or confirmed unchanged); for embedded data, since process start.",
	[]string{"dataset"}, nil)

func newRefdataMetrics() *refdataMetrics {
	return &refdataMetrics{
		entries: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "deckard_refdata_entries", Help: "Entries in the live reference dataset.",
		}, []string{"dataset"}),
		total: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "deckard_refdata_refresh_total", Help: "Reference dataset refresh attempts by result (ok, unchanged, rejected, error).",
		}, []string{"dataset", "result"}),
		now:     time.Now,
		updated: map[string]time.Time{},
	}
}

// Describe implements prometheus.Collector (age only; the vecs register
// themselves).
func (r *refdataMetrics) Describe(ch chan<- *prometheus.Desc) { ch <- descRefdataAge }

// Collect implements prometheus.Collector.
func (r *refdataMetrics) Collect(ch chan<- prometheus.Metric) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for ds, t := range r.updated {
		age := now.Sub(t).Seconds()
		if age < 0 {
			age = 0
		}
		ch <- prometheus.MustNewConstMetric(descRefdataAge, prometheus.GaugeValue, age, ds)
	}
}

// ObserveRefdata counts one refresh attempt.
func (m *Metrics) ObserveRefdata(dataset, result string) {
	m.ref.total.WithLabelValues(dataset, result).Inc()
}

// SetRefdataState records the live size and the time the data was last
// verified fresh.
func (m *Metrics) SetRefdataState(dataset string, entries int, updated time.Time) {
	m.ref.entries.WithLabelValues(dataset).Set(float64(entries))
	m.ref.mu.Lock()
	m.ref.updated[dataset] = updated
	m.ref.mu.Unlock()
}
