// Package metrics exposes deckard's Prometheus metrics (spec section 10).
//
// Gauge families that mirror database state (assets, open findings, source
// freshness) are emitted as const metrics at scrape time from a short-lived
// cache, so label sets that disappear from the store disappear from /metrics.
// Counters and histograms fed by the engine live in the registry directly.
package metrics

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/chainseer-xyz/deckard/internal/store"
)

// Recorder is what the engine calls to report activity.
type Recorder interface {
	ObserveScan(check, tier string, d time.Duration, err error)
	ObserveSync(source string, d time.Duration, ok bool)
	InventoryChange(kind string, n int)
	SetQueueDepth(queue string, n int)
}

// Nop is a Recorder that discards everything.
type Nop struct{}

func (Nop) ObserveScan(string, string, time.Duration, error) {}
func (Nop) ObserveSync(string, time.Duration, bool)          {}
func (Nop) InventoryChange(string, int)                      {}
func (Nop) SetQueueDepth(string, int)                        {}

// StateSource is the slice of store.Store the scrape-time collector needs.
type StateSource interface {
	Stats(ctx context.Context) (store.Stats, error)
	ListSyncs(ctx context.Context) ([]store.SyncStatus, error)
}

// Metrics owns the registry and implements Recorder.
type Metrics struct {
	reg *prometheus.Registry

	scanDuration  *prometheus.HistogramVec
	scanErrors    *prometheus.CounterVec
	checksRun     *prometheus.CounterVec
	syncDuration  *prometheus.HistogramVec
	queueDepth    *prometheus.GaugeVec
	invChanges    *prometheus.CounterVec
	collectErrors prometheus.Counter
	ref           *refdataMetrics

	templateUpdates *prometheus.CounterVec
	newTemplates    prometheus.Counter
	templates       *templateState
	vi              *vulnintelMetrics
}

var _ Recorder = (*Metrics)(nil)

// New builds a registry with Go/process collectors, build info and the
// engine-fed metrics. Call RegisterState to add the store-backed gauges.
func New(version, commit string) *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry(), ref: newRefdataMetrics(), vi: newVulnintelMetrics()}
	buckets := []float64{.1, .5, 1, 2.5, 5, 10, 30, 60, 120, 300}
	m.scanDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "deckard_scan_duration_seconds", Help: "Duration of check executions.", Buckets: buckets,
	}, []string{"check", "tier"})
	m.scanErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "deckard_scan_errors_total", Help: "Check executions that returned an error.",
	}, []string{"check"})
	m.checksRun = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "deckard_checks_run_total", Help: "Check executions.",
	}, []string{"check", "tier"})
	m.syncDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "deckard_source_sync_duration_seconds", Help: "Duration of source syncs.", Buckets: buckets,
	}, []string{"source"})
	m.queueDepth = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "deckard_queue_depth", Help: "Jobs waiting in a queue.",
	}, []string{"queue"})
	m.invChanges = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "deckard_inventory_changes_total", Help: "Inventory changes by type (added, removed, changed, revived).",
	}, []string{"type"})
	m.collectErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "deckard_metrics_collect_errors_total", Help: "Failed refreshes of store-backed gauges.",
	})
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "deckard_build_info", Help: "Build information; value is always 1.",
	}, []string{"version", "commit", "go_version"})
	build.WithLabelValues(version, commit, runtime.Version()).Set(1)

	m.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.scanDuration, m.scanErrors, m.checksRun, m.syncDuration,
		m.queueDepth, m.invChanges, m.collectErrors, build,
		m.ref.entries, m.ref.total, m.ref,
		m.vi.refresh, m.vi.kevOpen, m.vi,
	)
	m.initTemplateMetrics()
	return m
}

// Registry returns the underlying registry.
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// RegisterState registers the store-backed gauge families.
func (m *Metrics) RegisterState(src StateSource, ttl time.Duration) {
	m.reg.MustRegister(NewCollector(src, ttl, m.collectErrors))
}

// ObserveScan records one check execution.
func (m *Metrics) ObserveScan(check, tier string, d time.Duration, err error) {
	m.checksRun.WithLabelValues(check, tier).Inc()
	m.scanDuration.WithLabelValues(check, tier).Observe(d.Seconds())
	if err != nil {
		m.scanErrors.WithLabelValues(check).Inc()
	}
}

// ObserveSync records a sync duration. Success freshness comes from the store
// (deckard_source_last_success_timestamp) so it survives restarts.
func (m *Metrics) ObserveSync(source string, d time.Duration, _ bool) {
	m.syncDuration.WithLabelValues(source).Observe(d.Seconds())
}

// InventoryChange counts n inventory changes of the given type.
func (m *Metrics) InventoryChange(kind string, n int) {
	if n > 0 {
		m.invChanges.WithLabelValues(kind).Add(float64(n))
	}
}

// SetQueueDepth sets the depth gauge for a queue.
func (m *Metrics) SetQueueDepth(queue string, n int) {
	m.queueDepth.WithLabelValues(queue).Set(float64(n))
}

var (
	descAssets = prometheus.NewDesc("deckard_assets", "Inventory assets by kind, source and scope.", []string{"kind", "source", "scope"}, nil)
	descOpen   = prometheus.NewDesc("deckard_findings_open", "Open findings by severity and check.", []string{"severity", "check"}, nil)
	descLastOK = prometheus.NewDesc("deckard_source_last_success_timestamp", "Unix time of the last successful sync per source.", []string{"source"}, nil)
)

// Collector emits store-backed gauges, refreshing at most once per ttl.
type Collector struct {
	src  StateSource
	ttl  time.Duration
	errs prometheus.Counter
	now  func() time.Time

	mu     sync.Mutex
	at     time.Time
	stats  store.Stats
	syncs  []store.SyncStatus
	loaded bool
}

// NewCollector builds the scrape-time collector. errs may be nil.
func NewCollector(src StateSource, ttl time.Duration, errs prometheus.Counter) *Collector {
	return &Collector{src: src, ttl: ttl, errs: errs, now: time.Now}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descAssets
	ch <- descOpen
	ch <- descLastOK
}

func (c *Collector) refresh() (store.Stats, []store.SyncStatus, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded && c.now().Sub(c.at) < c.ttl {
		return c.stats, c.syncs, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := c.src.Stats(ctx)
	if err == nil {
		var sy []store.SyncStatus
		if sy, err = c.src.ListSyncs(ctx); err == nil {
			c.stats, c.syncs, c.at, c.loaded = st, sy, c.now(), true
		}
	}
	if err != nil && c.errs != nil {
		c.errs.Inc()
	}
	// On failure serve the last good snapshot (if any) rather than nothing.
	return c.stats, c.syncs, c.loaded
}

// Collect implements prometheus.Collector. store.Stats carries separate
// marginals per dimension, so each deckard_assets / deckard_findings_open series
// sets one label and "all" on the others; sum over a single dimension.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	st, syncs, ok := c.refresh()
	if !ok {
		return
	}
	g := prometheus.GaugeValue
	for k, v := range st.AssetsByKind {
		ch <- prometheus.MustNewConstMetric(descAssets, g, float64(v), k, "all", "all")
	}
	for k, v := range st.AssetsBySource {
		ch <- prometheus.MustNewConstMetric(descAssets, g, float64(v), "all", k, "all")
	}
	for k, v := range st.AssetsByScope {
		ch <- prometheus.MustNewConstMetric(descAssets, g, float64(v), "all", "all", k)
	}
	for k, v := range st.FindingsBySev {
		ch <- prometheus.MustNewConstMetric(descOpen, g, float64(v), k, "all")
	}
	for k, v := range st.FindingsByCheck {
		ch <- prometheus.MustNewConstMetric(descOpen, g, float64(v), "all", k)
	}
	for _, s := range syncs {
		if s.LastOK.IsZero() {
			continue
		}
		ch <- prometheus.MustNewConstMetric(descLastOK, g, float64(s.LastOK.Unix()), s.Source)
	}
}
