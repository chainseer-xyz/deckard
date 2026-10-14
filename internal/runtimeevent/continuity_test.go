package runtimeevent

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPagedPodSetIsCollectedWithoutSilentOmissions(t *testing.T) {
	var logRequests atomic.Int64
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			w.Header().Set("Content-Type", "application/json")
			page := corev1.PodList{TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}, Items: []corev1.Pod{sensorPod("a")}}
			if r.URL.Query().Get("continue") == "next" {
				page.Items = []corev1.Pod{sensorPod("b")}
			} else {
				page.Continue = "next"
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		logRequests.Add(1)
		_, _ = w.Write([]byte(nativeEvent))
	})
	collector, err := New(client, validSettings(), WithClock(func() time.Time { return time.Date(2026, 10, 14, 12, 5, 0, 0, time.UTC) }))
	if err != nil {
		t.Fatal(err)
	}
	report, err := collector.Collect(context.Background())
	if err != nil || len(report.Findings) != 1 || logRequests.Load() != 2 {
		t.Fatalf("paginated sensor set omitted: %+v %v logs=%d", report, err, logRequests.Load())
	}
}

func TestRepeatedPaginationTokenFailsClosed(t *testing.T) {
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/pods") {
			t.Error("inconsistent list triggered log reads")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(corev1.PodList{TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}, ListMeta: metav1.ListMeta{Continue: "loop"}})
	})
	collector, err := New(client, validSettings())
	if err != nil {
		t.Fatal(err)
	}
	if report, err := collector.Collect(context.Background()); err == nil || report.ObservedAt != nil {
		t.Fatalf("inconsistent list accepted: %+v %v", report, err)
	}
}

func TestOverlappingWindowsAndStartupRemainIncomplete(t *testing.T) {
	end := time.Date(2026, 10, 14, 12, 5, 0, 0, time.UTC)
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			pod := sensorPod("new-pod")
			pod.CreationTimestamp = metav1.NewTime(end.Add(-time.Minute))
			writePods(w, pod)
			return
		}
		if r.URL.Query().Get("sinceTime") != end.Add(-time.Hour).Format(time.RFC3339) {
			t.Error("explicit bounded backfill window not used")
		}
		_, _ = w.Write([]byte(nativeEvent))
	})
	settings := validSettings()
	settings.Lookback = time.Hour
	collector, err := New(client, settings, WithClock(func() time.Time { return end }))
	if err != nil {
		t.Fatal(err)
	}
	a, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	end = end.Add(time.Minute)
	b, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.Complete || b.Complete || a.Findings[0].Key != b.Findings[0].Key || a.Findings[0].Evidence["runtime_last_seen"] != b.Findings[0].Evidence["runtime_last_seen"] || !b.ObservedAt.After(*a.ObservedAt) {
		t.Fatalf("overlap/startup invented coverage or changed identity: %+v %+v", a, b)
	}
}

func TestTelemetryOnlyWindowIsNeverComplete(t *testing.T) {
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			writePods(w, sensorPod("a"))
			return
		}
		_, _ = w.Write([]byte(`{"process_exec":{"process":{"arguments":"SECRET"}}}`))
	})
	collector, err := New(client, validSettings())
	if err != nil {
		t.Fatal(err)
	}
	report, err := collector.Collect(context.Background())
	if err != nil || report.Complete || report.Findings == nil || len(report.Findings) != 0 {
		t.Fatalf("telemetry became coverage: %+v %v", report, err)
	}
}
