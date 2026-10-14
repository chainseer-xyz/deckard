package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// IngestStateSource is the slice of store.Store the ingest collector needs.
type IngestStateSource interface {
	ListIngestScopes(ctx context.Context) ([]store.IngestScope, error)
}

// OverflowScope is the scope label shared by a tool's scopes beyond
// IngestOptions.MaxScopesPerTool.
const OverflowScope = "other"

var (
	descIngestOpen = prometheus.NewDesc("deckard_ingest_findings",
		"Open findings posted through the ingest API, by tool (check ext.<tool>).", []string{"tool"}, nil)
	descIngestLastOK = prometheus.NewDesc("deckard_ingest_last_success_timestamp",
		"Unix time of the last ingest applied as complete per tool and scope. A tool's scopes beyond ingest.max_scopes_per_tool are reported as scope=\"other\" with the oldest of their timestamps.",
		[]string{"tool", "scope"}, nil)
	descIngestExpected = prometheus.NewDesc("deckard_ingest_expected_interval_seconds",
		"ingest.tools.<tool>.expected_interval: how often a complete run per scope is expected (only tools that set it).",
		[]string{"tool"}, nil)
	descIngestLastReport = prometheus.NewDesc("deckard_ingest_last_report_timestamp",
		"Unix time of the last accepted report per tool and scope, including incomplete and event-only reports. Overflow scopes use the oldest report timestamp.",
		[]string{"tool", "scope"}, nil)
	descIngestReportExpected = prometheus.NewDesc("deckard_ingest_report_expected_interval_seconds",
		"How often an accepted report per scope is expected; this does not assert complete assessment coverage.",
		[]string{"tool"}, nil)
)

// NewIngestRequests builds deckard_ingest_requests_total{tool,result}. The
// API server registers and feeds it (it bounds the tool label).
func NewIngestRequests() *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "deckard_ingest_requests_total",
		Help: "POST /api/v1/ingest requests by tool and result (ok, partial, replay, rejected, invalid, too_large, rate_limited, disabled, error). Tools not listed in ingest.tools share tool=\"other\" past a cap; unparseable bodies count as tool=\"unknown\".",
	}, []string{"tool", "result"})
}

// IngestOptions configure the ingest collector.
type IngestOptions struct {
	// Expected is ingest.tools.<tool>.expected_interval for tools that set one.
	Expected map[string]time.Duration
	// ExpectedReport tracks accepted partial/event reports independently of complete scans.
	ExpectedReport map[string]time.Duration
	// MaxScopesPerTool caps the scope label per tool (ingest.max_scopes_per_tool).
	MaxScopesPerTool int
	TTL              time.Duration
	Logger           *slog.Logger
}

// IngestCollector emits the store-backed ingest gauges, refreshing at most
// once per TTL. Scopes keep their own series in the order they were first
// ingested, so the set of labelled scopes is stable across scrapes.
type IngestCollector struct {
	src  IngestStateSource
	o    IngestOptions
	errs prometheus.Counter
	now  func() time.Time

	mu     sync.Mutex
	at     time.Time
	scopes []store.IngestScope
	loaded bool
	warned map[string]bool // metric/tool pairs whose scope aggregation was logged
}

// NewIngestCollector builds the collector. errs may be nil.
func NewIngestCollector(src IngestStateSource, o IngestOptions, errs prometheus.Counter) *IngestCollector {
	if o.MaxScopesPerTool < 1 {
		o.MaxScopesPerTool = 50
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &IngestCollector{src: src, o: o, errs: errs, now: time.Now, warned: map[string]bool{}}
}

// RegisterIngest registers the ingest gauges backed by src.
func (m *Metrics) RegisterIngest(src IngestStateSource, o IngestOptions) {
	m.reg.MustRegister(NewIngestCollector(src, o, m.collectErrors))
}

// Describe implements prometheus.Collector.
func (c *IngestCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descIngestOpen
	ch <- descIngestLastOK
	ch <- descIngestExpected
	ch <- descIngestLastReport
	ch <- descIngestReportExpected
}

func (c *IngestCollector) refresh() ([]store.IngestScope, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded && c.now().Sub(c.at) < c.o.TTL {
		return c.scopes, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sc, err := c.src.ListIngestScopes(ctx)
	if err == nil {
		c.scopes, c.at, c.loaded = sc, c.now(), true
	} else if c.errs != nil {
		c.errs.Inc()
	}
	return c.scopes, c.loaded
}

// Collect implements prometheus.Collector.
func (c *IngestCollector) Collect(ch chan<- prometheus.Metric) {
	g := prometheus.GaugeValue
	for tool, iv := range c.o.Expected {
		if iv > 0 {
			ch <- prometheus.MustNewConstMetric(descIngestExpected, g, iv.Seconds(), tool)
		}
	}
	for tool, iv := range c.o.ExpectedReport {
		if iv > 0 {
			ch <- prometheus.MustNewConstMetric(descIngestReportExpected, g, iv.Seconds(), tool)
		}
	}
	scopes, ok := c.refresh()
	if !ok {
		return
	}
	open := map[string]int{}
	for _, s := range scopes {
		open[s.Tool] += s.Open
	}
	for tool, n := range open {
		ch <- prometheus.MustNewConstMetric(descIngestOpen, g, float64(n), tool)
	}
	c.collectTimestamps(ch, scopes, descIngestLastOK, "complete", func(s store.IngestScope) time.Time {
		if model.IsRuntimeTool(s.Tool) {
			return time.Time{}
		}
		return s.CompleteAt
	})
	c.collectTimestamps(ch, scopes, descIngestLastReport, "report", func(s store.IngestScope) time.Time {
		return s.LastAt
	})
}

// Each timestamp family has its own label cap: partial-only reports cannot
// consume the slots reserved for scopes with a complete assessment.
func (c *IngestCollector) collectTimestamps(ch chan<- prometheus.Metric, scopes []store.IngestScope, desc *prometheus.Desc, kind string, timestamp func(store.IngestScope) time.Time) {
	labelled := map[string]int{}
	other := map[string]time.Time{}
	overflow := map[string]int{}
	// ListIngestScopes orders by tool, then first ingest: the oldest
	// MaxScopesPerTool scopes of a tool keep their own series.
	for _, s := range scopes {
		at := timestamp(s)
		if at.IsZero() {
			continue
		}
		// Reserve the synthetic scope even when a producer literally uses it.
		// Otherwise an ordinary series collides with the overflow series.
		if s.Scope != OverflowScope && labelled[s.Tool] < c.o.MaxScopesPerTool {
			labelled[s.Tool]++
			ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(at.Unix()), s.Tool, s.Scope)
			continue
		}
		overflow[s.Tool]++
		if o, seen := other[s.Tool]; !seen || at.Before(o) {
			other[s.Tool] = at
		}
	}
	for tool, t := range other {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(t.Unix()), tool, OverflowScope)
	}
	c.logOverflow(kind, overflow)
}

// logOverflow logs once per family/tool when scopes first enter aggregation.
func (c *IngestCollector) logOverflow(kind string, overflow map[string]int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for tool, n := range overflow {
		key := kind + ":" + tool
		if c.warned[key] {
			continue
		}
		c.warned[key] = true
		c.o.Logger.Warn("ingest: scopes are aggregated as scope=\"other\" because of the label cap or reserved scope name",
			"tool", tool, "timestamp_family", kind, "max_scopes_per_tool", c.o.MaxScopesPerTool, "overflow_scopes", n)
	}
}
