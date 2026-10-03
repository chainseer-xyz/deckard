package app

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/engine"
)

// TestShutdownFitsChartGracePeriod ties the chart's default
// terminationGracePeriodSeconds to the budget serve.go checks at compile time:
// drain (shutdownGrace) plus the engine's cancel overrun must end before
// Kubernetes sends SIGKILL, or every rollout orphans running jobs.
func TestShutdownFitsChartGracePeriod(t *testing.T) {
	b, err := os.ReadFile("../../deploy/helm/deckard/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^terminationGracePeriodSeconds:\s*(\d+)\s*$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("values.yaml sets no top-level terminationGracePeriodSeconds")
	}
	secs, _ := strconv.Atoi(string(m[1]))
	chart := time.Duration(secs) * time.Second
	if chart != podTerminationGrace {
		t.Errorf("chart grace %v, serve.go podTerminationGrace %v: change them together", chart, podTerminationGrace)
	}
	if need := shutdownGrace + engine.StopOverrun; need >= chart {
		t.Errorf("shutdown needs up to %v, the pod is killed after %v", need, chart)
	}
}
