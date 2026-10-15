package runtimeevent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestCollectStreamsMoreThanWireLimitWithoutRetainingNativeLogs(t *testing.T) {
	for _, tc := range []struct {
		name          string
		pods, records int
	}{
		{"two sensors exceed normalized wire cap", 2, 768},
		{"one busy sensor exceeds the old ten MiB raw cap", 1, 1536},
		{"one busy sensor retains headroom below the raw cap", 1, 3072},
		{"34 sensor production-sized burst", 34, 256},
	} {
		t.Run(tc.name, func(t *testing.T) { collectLargeTelemetryWindow(t, tc.pods, tc.records) })
	}
}

func collectLargeTelemetryWindow(t *testing.T, count, records int) {
	t.Helper()
	// Generate 12/68 MiB over HTTP from one 8 KiB record, without a large fixture
	// allocation. The normalized report stays under 2 KiB for either sensor set.
	telemetry := []byte(`{"process_exec":{"process":{"arguments":"SECRET-` + strings.Repeat("x", 8192) + `"}}}` + "\n")
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			pods := make([]corev1.Pod, 0, count)
			for i := range count {
				pods = append(pods, sensorPod(fmt.Sprintf("sensor-%02d", i)))
			}
			writePods(w, pods...)
			return
		}
		for range records {
			if _, err := w.Write(telemetry); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(nativeEvent + "\n"))
		later := strings.ReplaceAll(nativeEvent, "12:04:00Z", "12:04:30Z")
		_, _ = w.Write([]byte(later + "\n"))
	})
	collector, err := New(client, validSettings(), WithClock(func() time.Time { return time.Date(2026, 10, 14, 12, 5, 0, 0, time.UTC) }))
	if err != nil {
		t.Fatal(err)
	}
	report, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("bounded native telemetry exceeding the normalized wire cap was rejected: %v", err)
	}
	if report.Complete || len(report.Findings) != 1 {
		t.Fatalf("wrong incomplete incident report: %+v", report)
	}
	evidence := report.Findings[0].Evidence
	if evidence["runtime_batch_count"] != int64(2) || evidence["runtime_first_seen"] != "2026-10-14T12:04:00Z" || evidence["runtime_last_seen"] != "2026-10-14T12:04:30Z" {
		t.Fatalf("cross-stream deduplication or event times lost: %+v", evidence)
	}
	encoded, _ := json.Marshal(report)
	if len(encoded) > 2048 || strings.Contains(string(encoded), "SECRET") {
		t.Fatal("raw telemetry leaked into the normalized envelope")
	}
}

func TestLateInvalidNativeRecordCancelsSiblingAndDiscardsPrefix(t *testing.T) {
	for _, invalid := range []string{`{"process_kprobe":SECRET`, `{"process_throttle":{"type":"THROTTLE_START"}}`, `{"rate_limit_info":{"number_of_dropped_process_events":"1"}}`} {
		t.Run(invalid[:20], func(t *testing.T) {
			started, stopped := make(chan struct{}), make(chan struct{})
			client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/pods") {
					writePods(w, sensorPod("a"), sensorPod("b"))
					return
				}
				if strings.Contains(r.URL.Path, "/a/log") {
					select {
					case <-started:
						_, _ = w.Write([]byte(nativeEvent + "\n" + invalid + "\n"))
					case <-r.Context().Done():
					}
					return
				}
				_, _ = w.Write([]byte(nativeEvent + "\n"))
				w.(http.Flusher).Flush()
				close(started)
				<-r.Context().Done()
				close(stopped)
			})
			collector, err := New(client, validSettings(), WithClock(func() time.Time { return time.Date(2026, 10, 14, 12, 5, 0, 0, time.UTC) }))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			report, err := collector.Collect(ctx)
			if err == nil || errors.Is(err, context.DeadlineExceeded) || report.Findings != nil || report.ObservedAt != nil || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("late bad record was buffered, accepted or exposed: %v", err)
			}
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("invalid record leaked a sibling stream")
			}
		})
	}
}
