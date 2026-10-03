package app

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/engine"
)

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestQueuesRegisteredEverywhere fails when a queue is known in one place and
// missing in another: the config's valid names, its defaults, the engine's
// defaults, the config-to-engine mapping, the Helm chart's values and the
// documented defaults. A queue missing from any of them is silently never
// worked, or cannot be tuned.
func TestQueuesRegisteredEverywhere(t *testing.T) {
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Refdata.Enabled = false
	names := slices.Clone(config.QueueNames)
	sort.Strings(names)

	check := func(where string, got map[string]int) {
		t.Helper()
		if keys := sortedKeys(got); !slices.Equal(keys, names) {
			t.Errorf("%s has queues %v, config.QueueNames has %v", where, keys, names)
		}
	}
	check("config defaults (scheduling.queue_workers)", cfg.Scheduling.QueueWorkers)
	check("engine.DefaultQueueWorkers", engine.DefaultQueueWorkers())
	check("app.queueWorkers", queueWorkers(cfg))

	// The same counts, not only the same names.
	for q, n := range engine.DefaultQueueWorkers() {
		if cfg.Scheduling.QueueWorkers[q] != n {
			t.Errorf("queue %s: engine default %d, config default %d", q, n, cfg.Scheduling.QueueWorkers[q])
		}
	}

	// Helm values.
	raw, err := os.ReadFile("../../deploy/helm/deckard/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		Config struct {
			Scheduling struct {
				QueueWorkers map[string]int `yaml:"queue_workers"`
			} `yaml:"scheduling"`
		} `yaml:"config"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	check("deploy/helm/deckard/values.yaml (config.scheduling.queue_workers)", values.Config.Scheduling.QueueWorkers)
	for q, n := range values.Config.Scheduling.QueueWorkers {
		if cfg.Scheduling.QueueWorkers[q] != n {
			t.Errorf("queue %s: chart default %d, config default %d", q, n, cfg.Scheduling.QueueWorkers[q])
		}
	}

	// Documentation: the default cell of the queue_workers row and the
	// per-queue metric label list.
	docs, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	ops, err := os.ReadFile("../../docs/operations.md")
	if err != nil {
		t.Fatal(err)
	}
	for q, n := range cfg.Scheduling.QueueWorkers {
		if want := fmt.Sprintf("%s: %d", q, n); !strings.Contains(string(docs), want) {
			t.Errorf("docs/configuration.md does not document the default %q", want)
		}
	}
	var depthRow string
	for _, line := range strings.Split(string(ops), "\n") {
		if strings.HasPrefix(line, "| `deckard_queue_depth`") {
			depthRow = line
		}
	}
	if depthRow == "" {
		t.Fatal("docs/operations.md has no deckard_queue_depth row")
	}
	for _, q := range names {
		if !strings.Contains(depthRow, q) {
			t.Errorf("docs/operations.md deckard_queue_depth row does not list queue %q", q)
		}
	}
}
