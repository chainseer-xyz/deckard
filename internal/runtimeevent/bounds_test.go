package runtimeevent

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestNewRejectsUnboundedOrAmbiguousConfiguration(t *testing.T) {
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("constructor contacted Kubernetes")
		http.NotFound(w, r)
	})
	if _, err := New(nil, validSettings()); err == nil {
		t.Error("nil Kubernetes client accepted")
	}
	for name, change := range map[string]func(*Settings){
		"empty namespace": func(s *Settings) { s.Namespace = "" }, "invalid namespace": func(s *Settings) { s.Namespace = "*" },
		"empty selector": func(s *Settings) { s.Selector = "" }, "broad selector": func(s *Settings) { s.Selector = " " }, "invalid selector": func(s *Settings) { s.Selector = "app in (" },
		"missing container": func(s *Settings) { s.Container = "" }, "invalid container": func(s *Settings) { s.Container = "unsafe/name" },
		"display name scope": func(s *Settings) { s.ClusterScope = "marina-staging" }, "missing UID": func(s *Settings) { s.ClusterScope = "k8s:uid:" }, "invalid UID": func(s *Settings) { s.ClusterScope = "k8s:uid:SECRET/token" },
		"excess lookback": func(s *Settings) { s.Lookback = time.Hour + time.Nanosecond }, "negative lookback": func(s *Settings) { s.Lookback = -time.Second },
		"excess timeout": func(s *Settings) { s.Timeout = 3 * time.Minute }, "negative timeout": func(s *Settings) { s.Timeout = -time.Second },
		"excess pods": func(s *Settings) { s.MaxPods = 65 }, "negative pods": func(s *Settings) { s.MaxPods = -1 },
		"excess concurrency": func(s *Settings) { s.Concurrency = 5 }, "negative concurrency": func(s *Settings) { s.Concurrency = -1 },
		"excess pod bytes": func(s *Settings) { s.MaxPodBytes = (10 << 20) + 1 }, "negative pod bytes": func(s *Settings) { s.MaxPodBytes = -1 },
		"excess total bytes": func(s *Settings) { s.MaxTotalBytes = (256 << 20) + 1 }, "negative total bytes": func(s *Settings) { s.MaxTotalBytes = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			settings := validSettings()
			change(&settings)
			if _, err := New(client, settings); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestCollectionFailureReturnsNoAcceptedEnvelope(t *testing.T) {
	for _, failure := range []string{"list denied", "no pods", "wrong container", "too many pods", "pod denied", "truncated JSON", "truncated transport", "per-pod bound", "aggregate bound", "future events"} {
		t.Run(failure, func(t *testing.T) {
			client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/pods") {
					if failure == "list denied" {
						http.Error(w, "SECRET", http.StatusForbidden)
						return
					}
					if failure == "no pods" {
						writePods(w)
						return
					}
					if failure == "too many pods" {
						writePods(w, sensorPod("a"), sensorPod("b"), sensorPod("c"))
						return
					}
					if failure == "wrong container" {
						pod := sensorPod("a")
						pod.Spec.Containers = []corev1.Container{{Name: "tetragon"}}
						writePods(w, pod)
						return
					}
					writePods(w, sensorPod("a"), sensorPod("b"))
					return
				}
				body := nativeEvent
				if strings.Contains(r.URL.Path, "/b/log") {
					switch failure {
					case "pod denied":
						http.Error(w, "SECRET", http.StatusForbidden)
						return
					case "truncated JSON":
						body = `{"process_kprobe":`
					case "truncated transport":
						w.Header().Set("Content-Length", "99999")
					case "future events":
						body = strings.ReplaceAll(body, "12:04:00Z", "12:20:00Z")
					}
				}
				_, _ = w.Write([]byte(body))
			})
			settings := validSettings()
			if failure == "too many pods" {
				settings.MaxPods = 2
			}
			if failure == "per-pod bound" {
				settings.MaxPodBytes = int64(len(nativeEvent) - 1)
			}
			if failure == "aggregate bound" {
				settings.MaxTotalBytes = int64(2*len(nativeEvent) - 1)
			}
			collector, err := New(client, settings, WithClock(func() time.Time { return time.Date(2026, 10, 14, 12, 5, 0, 0, time.UTC) }))
			if err != nil {
				t.Fatal(err)
			}
			report, err := collector.Collect(context.Background())
			if err == nil || report.ObservedAt != nil || report.Findings != nil || report.Tool != "" {
				t.Fatalf("partial collection became accepted envelope: %+v %v", report, err)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("Kubernetes response echoed sensitive data")
			}
		})
	}
}

func TestOverallTimeoutCancelsLogStream(t *testing.T) {
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			writePods(w, sensorPod("a"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	settings := validSettings()
	settings.Timeout = 30 * time.Millisecond
	collector, err := New(client, settings)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	report, err := collector.Collect(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || report.ObservedAt != nil || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("overall timeout not enforced: %+v %v duration=%s", report, err, time.Since(started))
	}
}
