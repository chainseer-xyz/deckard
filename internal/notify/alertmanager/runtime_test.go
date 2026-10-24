package alertmanager

import (
	"encoding/json"
	"maps"
	"math"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/chainseer-xyz/deckard/internal/model"
)

func runtimeFinding() model.Finding {
	return finding(func(f *model.Finding) {
		f.Check, f.Source = "ext.tetragon", "ingest:tetragon"
		f.Evidence = map[string]any{
			"runtime_cluster_id": "uid:cluster-a", "runtime_namespace": "apps", "runtime_pod_name": "web-abc",
			"runtime_rule": "sensitive-file-write", "runtime_first_seen": "2026-10-24T12:00:00.123Z",
			"runtime_last_seen": "2026-10-24T14:01:00+02:00", "runtime_batch_count": float64(3),
		}
	})
}

func TestRuntimeAnnotationsDoNotChangeAlertIdentity(t *testing.T) {
	f := runtimeFinding()
	without := f
	without.Evidence = nil
	baseline := buildAlert(without, t0, "")
	want := map[string]string{
		"runtime_cluster_id": "uid:cluster-a", "runtime_namespace": "apps", "runtime_pod_name": "web-abc",
		"runtime_rule": "sensitive-file-write", "runtime_first_seen": "2026-10-24T12:00:00.123Z",
		"runtime_last_seen": "2026-10-24T12:01:00Z", "runtime_batch_count": "3",
	}
	for _, alert := range buildPayload([]model.Finding{f}, []model.Finding{f}, t0, time.Minute, "") {
		if !maps.Equal(alert.Labels, baseline.Labels) {
			t.Errorf("runtime presentation changed the alert identity: %v", alert.Labels)
		}
		for key, value := range want {
			if alert.Annotations[key] != value {
				t.Errorf("annotation %s=%q, want %q", key, alert.Annotations[key], value)
			}
		}
		if alert.Annotations["first_seen"] != f.FirstSeen.UTC().Format(time.RFC3339) {
			t.Error("runtime batch time replaced durable finding first_seen")
		}
	}
	f.Evidence["runtime_namespace"], f.Evidence["runtime_rule"] = "other", "other-policy"
	if changed := buildAlert(f, t0, ""); !maps.Equal(changed.Labels, baseline.Labels) {
		t.Error("changing runtime annotations changed labels")
	}
}

func TestRuntimeAnnotationAllowlistRequiresExactRuntimeLineage(t *testing.T) {
	for _, tool := range []string{"tetragon", "falco"} {
		f := runtimeFinding()
		f.Check, f.Source = model.IngestCheck(tool), model.IngestSource(tool)
		if got := buildAlert(f, t0, "").Annotations["runtime_rule"]; got != "sensitive-file-write" {
			t.Errorf("runtime tool %s annotation=%q", tool, got)
		}
	}
	for _, lineage := range [][2]string{{"http.headers", "native"}, {"ext.other", "ingest:other"}, {"ext.tetragon", "native"}, {"tetragon", "ingest:tetragon"}} {
		f := runtimeFinding()
		f.Check, f.Source = lineage[0], lineage[1]
		for key := range buildAlert(f, t0, "").Annotations {
			if strings.HasPrefix(key, "runtime_") {
				t.Errorf("runtime annotation %s on non-runtime lineage %v", key, lineage)
			}
		}
	}
	f := runtimeFinding()
	f.Evidence["runtime_process_args"] = "SECRET-ARGS"
	f.Evidence["runtime_environment"] = "SECRET-ENV"
	for key := range buildAlert(f, t0, "").Annotations {
		if key == "runtime_process_args" || key == "runtime_environment" {
			t.Errorf("non-allowlisted runtime field became an annotation: %s", key)
		}
	}
}

func TestRuntimeAnnotationsAreBoundedTypedAndSingleLine(t *testing.T) {
	f := runtimeFinding()
	f.Evidence["runtime_namespace"] = "apps\r\n\x00team"
	f.Evidence["runtime_rule"] = strings.Repeat("é", 3000)
	f.Evidence["runtime_pod_name"] = []string{"not-a-string"}
	f.Evidence["runtime_first_seen"] = "SECRET-NOT-A-TIME"
	f.Evidence["runtime_last_seen"] = "0001-01-01T00:00:00Z"
	f.Evidence["runtime_batch_count"] = "SECRET-NOT-A-COUNT"
	a := buildAlert(f, t0, "").Annotations
	for _, key := range []string{"runtime_namespace", "runtime_rule"} {
		value := a[key]
		if value == "" || !utf8.ValidString(value) || len(value) > maxContext+len(truncMarker) || strings.ContainsFunc(value, unicode.IsControl) {
			t.Errorf("runtime annotation %s is missing, unsafe or unbounded", key)
		}
	}
	for _, key := range []string{"runtime_pod_name", "runtime_first_seen", "runtime_last_seen", "runtime_batch_count"} {
		if _, exists := a[key]; exists {
			t.Errorf("invalid runtime field %s should be omitted", key)
		}
	}
}

func TestRuntimeBatchCountAnnotationsAcceptOnlyBoundedPositiveIntegers(t *testing.T) {
	for _, value := range []any{int(3), int64(3), float64(3), json.Number("3")} {
		f := runtimeFinding()
		f.Evidence["runtime_batch_count"] = value
		if got := buildAlert(f, t0, "").Annotations["runtime_batch_count"]; got != "3" {
			t.Errorf("count type %T annotation=%q, want 3", value, got)
		}
	}
	for _, value := range []any{nil, -1, 0, int64(1000000001), 1.5, math.NaN(), math.Inf(1), "3", json.Number("1.5"), json.Number("1000000000000000000000")} {
		f := runtimeFinding()
		f.Evidence["runtime_batch_count"] = value
		if _, exists := buildAlert(f, t0, "").Annotations["runtime_batch_count"]; exists {
			t.Errorf("invalid count type %T became a runtime annotation", value)
		}
	}
}
