package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TemplateRecorder is the optional extension of Recorder that reports nuclei
// template maintenance (the engine asserts for it); *Metrics implements it.
type TemplateRecorder interface {
	ObserveTemplateUpdate(result string)
	AddNewTemplates(n int)
	SetTemplateStatus(count int, checkedAt time.Time)
}

var _ TemplateRecorder = (*Metrics)(nil)

// templateResults are the only values of the result label.
var templateResults = []string{"ok", "error", "unchanged"}

var (
	descTemplateAge   = prometheus.NewDesc("deckard_nuclei_templates_age_seconds", "Seconds since the nuclei templates were last confirmed current (updated or checked). Absent when deckard does not manage the templates.", nil, nil)
	descTemplateCount = prometheus.NewDesc("deckard_nuclei_template_count", "Templates in the active nuclei template release.", nil, nil)
	descTemplateWarn  = prometheus.NewDesc("deckard_nuclei_templates_max_age_warn_seconds", "Configured nuclei.update.max_age_warn: the template age that should alert.", nil, nil)
)

// templateState holds the last reported template status for scrape-time gauges.
type templateState struct {
	mu        sync.Mutex
	now       func() time.Time
	set       bool
	count     int
	checkedAt time.Time
	warnAfter time.Duration
}

func (s *templateState) Describe(ch chan<- *prometheus.Desc) {
	ch <- descTemplateAge
	ch <- descTemplateCount
	ch <- descTemplateWarn
}

// Collect emits the gauges only once a status was reported, so an operator who
// mounts their own templates (updater disabled) gets no misleading age.
func (s *templateState) Collect(ch chan<- prometheus.Metric) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.warnAfter > 0 {
		ch <- prometheus.MustNewConstMetric(descTemplateWarn, prometheus.GaugeValue, s.warnAfter.Seconds())
	}
	if !s.set {
		return
	}
	age := s.now().Sub(s.checkedAt).Seconds()
	if age < 0 {
		age = 0
	}
	ch <- prometheus.MustNewConstMetric(descTemplateAge, prometheus.GaugeValue, age)
	ch <- prometheus.MustNewConstMetric(descTemplateCount, prometheus.GaugeValue, float64(s.count))
}

func (m *Metrics) initTemplateMetrics() {
	m.templateUpdates = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "deckard_nuclei_template_updates_total", Help: "nuclei template update attempts by result (ok: new release installed, unchanged, error).",
	}, []string{"result"})
	for _, r := range templateResults {
		m.templateUpdates.WithLabelValues(r) // present at zero from the first scrape
	}
	m.newTemplates = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "deckard_nuclei_new_templates_total", Help: "Templates added by nuclei template updates.",
	})
	m.templates = &templateState{now: time.Now}
	m.reg.MustRegister(m.templateUpdates, m.newTemplates, m.templates)
}

// ObserveTemplateUpdate counts one update attempt. Unknown results are
// ignored so callers cannot mint label values.
func (m *Metrics) ObserveTemplateUpdate(result string) {
	for _, r := range templateResults {
		if r == result {
			m.templateUpdates.WithLabelValues(result).Inc()
			return
		}
	}
}

// AddNewTemplates counts templates an update added.
func (m *Metrics) AddNewTemplates(n int) {
	if n > 0 {
		m.newTemplates.Add(float64(n))
	}
}

// SetTemplateStatus records the active release size and when it was last
// confirmed current. A zero checkedAt clears the gauges (nothing installed).
func (m *Metrics) SetTemplateStatus(count int, checkedAt time.Time) {
	m.templates.mu.Lock()
	defer m.templates.mu.Unlock()
	m.templates.set = !checkedAt.IsZero()
	m.templates.count, m.templates.checkedAt = count, checkedAt
}

// SetTemplateMaxAgeWarn publishes nuclei.update.max_age_warn so the staleness
// alert can compare against the operator's own threshold.
func (m *Metrics) SetTemplateMaxAgeWarn(d time.Duration) {
	m.templates.mu.Lock()
	defer m.templates.mu.Unlock()
	m.templates.warnAfter = d
}

// SetClock overrides the clock used to compute the template age (tests).
func (m *Metrics) SetClock(now func() time.Time) {
	m.templates.mu.Lock()
	defer m.templates.mu.Unlock()
	m.templates.now = now
}
