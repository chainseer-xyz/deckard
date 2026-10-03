package metrics_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/chainseer-xyz/deckard/internal/metrics"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type fakeIngestSrc struct {
	scopes []store.IngestScope
	err    error
	calls  int
}

func (f *fakeIngestSrc) ListIngestScopes(context.Context) ([]store.IngestScope, error) {
	f.calls++
	return f.scopes, f.err
}

var it0 = time.Date(2026, 10, 3, 7, 0, 0, 0, time.UTC)

func TestIngestCollector(t *testing.T) {
	src := &fakeIngestSrc{scopes: []store.IngestScope{
		{Tool: "kubescape", Scope: "k8s:prod", CompleteAt: it0, Open: 3},
		{Tool: "prowler", Scope: "aws:111111111111:us-west-2", CompleteAt: it0.Add(time.Hour), Open: 2},
		{Tool: "prowler", Scope: "aws:222222222222:us-west-2", CompleteAt: it0.Add(2 * time.Hour), Open: 1},
		{Tool: "prowler", Scope: "aws:333333333333:us-west-2", CompleteAt: it0.Add(3 * time.Hour)},
		{Tool: "prowler", Scope: "aws:444444444444:us-west-2", CompleteAt: it0.Add(30 * time.Minute)},
		{Tool: "trufflehog", Scope: "github.com/example", Open: 4}, // never complete
	}}
	var logs bytes.Buffer
	c := metrics.NewIngestCollector(src, metrics.IngestOptions{
		Expected:         map[string]time.Duration{"prowler": 24 * time.Hour, "kubescape": 0},
		MaxScopesPerTool: 2, TTL: time.Minute, Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}, nil)

	want := fmt.Sprintf(`
# HELP deckard_ingest_expected_interval_seconds ingest.tools.<tool>.expected_interval: how often a complete run per scope is expected (only tools that set it).
# TYPE deckard_ingest_expected_interval_seconds gauge
deckard_ingest_expected_interval_seconds{tool="prowler"} 86400
# HELP deckard_ingest_findings Open findings posted through the ingest API, by tool (check ext.<tool>).
# TYPE deckard_ingest_findings gauge
deckard_ingest_findings{tool="kubescape"} 3
deckard_ingest_findings{tool="prowler"} 3
deckard_ingest_findings{tool="trufflehog"} 4
# HELP deckard_ingest_last_success_timestamp Unix time of the last ingest applied as complete per tool and scope. A tool's scopes beyond ingest.max_scopes_per_tool are reported as scope="other" with the oldest of their timestamps.
# TYPE deckard_ingest_last_success_timestamp gauge
deckard_ingest_last_success_timestamp{scope="aws:111111111111:us-west-2",tool="prowler"} %d
deckard_ingest_last_success_timestamp{scope="aws:222222222222:us-west-2",tool="prowler"} %d
deckard_ingest_last_success_timestamp{scope="k8s:prod",tool="kubescape"} %d
deckard_ingest_last_success_timestamp{scope="other",tool="prowler"} %d
`, it0.Add(time.Hour).Unix(), it0.Add(2*time.Hour).Unix(), it0.Unix(), it0.Add(30*time.Minute).Unix())
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
	// Cached within the TTL, and the overflow is logged once per tool.
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
	if src.calls != 1 {
		t.Fatalf("store read %d times within the TTL", src.calls)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Fatalf("overflow logged %d times:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "tool=prowler") || !strings.Contains(logs.String(), "overflow_scopes=2") {
		t.Fatalf("overflow log: %s", logs.String())
	}
}

func TestIngestCollectorSurvivesStoreErrors(t *testing.T) {
	src := &fakeIngestSrc{err: errors.New("db down")}
	errs := prometheus.NewCounter(prometheus.CounterOpts{Name: "e", Help: "e"})
	c := metrics.NewIngestCollector(src, metrics.IngestOptions{Expected: map[string]time.Duration{"prowler": time.Hour}}, errs)
	// Only the config-derived gauge; no store-backed series and no panic.
	if n := testutil.CollectAndCount(c); n != 1 {
		t.Fatalf("series = %d, want 1", n)
	}
	if testutil.ToFloat64(errs) != 1 {
		t.Fatal("collect error not counted")
	}
}

func TestRegisterIngestOnTheRegistry(t *testing.T) {
	m := metrics.New("v", "c")
	m.RegisterIngest(&fakeIngestSrc{scopes: []store.IngestScope{{Tool: "gitleaks", Scope: "github.com/example", CompleteAt: it0}}},
		metrics.IngestOptions{TTL: time.Second})
	out := scrape(t, m)
	if !strings.Contains(out, `deckard_ingest_last_success_timestamp{scope="github.com/example",tool="gitleaks"}`) ||
		!strings.Contains(out, `deckard_ingest_findings{tool="gitleaks"} 0`) {
		t.Fatalf("scrape lacks ingest series:\n%s", out)
	}
}
