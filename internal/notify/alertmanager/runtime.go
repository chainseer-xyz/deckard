package alertmanager

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// addRuntimeAnnotations exposes only bounded display metadata, never alert
// labels. Event timestamps and counts describe the reported batch, not lifetime
// coverage, and cannot replace the finding's durable first_seen or identity.
func addRuntimeAnnotations(annotations map[string]string, f model.Finding) {
	tool := strings.TrimPrefix(f.Check, model.IngestCheckPrefix)
	if !model.IsRuntimeTool(tool) || f.Check != model.IngestCheck(tool) || f.Source != model.IngestSource(tool) {
		return
	}
	for _, key := range []string{"runtime_cluster_id", "runtime_namespace", "runtime_pod_name", "runtime_rule"} {
		if value, ok := f.Evidence[key].(string); ok {
			setAnn(annotations, key, truncateRunes(strings.TrimSpace(sanitizeValue(value)), maxContext))
		}
	}
	for _, key := range []string{"runtime_first_seen", "runtime_last_seen"} {
		value, _ := f.Evidence[key].(string)
		if at, err := time.Parse(time.RFC3339Nano, value); err == nil && !at.IsZero() {
			setAnn(annotations, key, at.UTC().Format(time.RFC3339Nano))
		}
	}
	if count := runtimeBatchCount(f.Evidence["runtime_batch_count"]); count > 0 {
		setAnn(annotations, "runtime_batch_count", strconv.FormatInt(count, 10))
	}
}

func runtimeBatchCount(value any) int64 {
	var count int64
	switch value := value.(type) {
	case int:
		count = int64(value)
	case int64:
		count = value
	case float64: // JSONB evidence is decoded into float64 after persistence.
		if value < 1 || value > 1e9 || math.IsNaN(value) || math.Trunc(value) != value {
			return 0
		}
		count = int64(value)
	case json.Number:
		var err error
		if count, err = value.Int64(); err != nil {
			return 0
		}
	}
	if count < 1 || count > 1e9 {
		return 0
	}
	return count
}
