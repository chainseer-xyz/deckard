package runtimeevent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/tetragon"
)

func identicalFailure(got, want error) bool {
	return got == want //nolint:errorlint // Siblings must return the same object, not a wrapper with the same cause.
}

func TestPodListFailureNamesNamespaceWithoutProviderBody(t *testing.T) {
	client := fixtureClient(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "SECRET provider body", http.StatusForbidden)
	})
	collector, err := New(client, validSettings())
	if err != nil {
		t.Fatal(err)
	}
	report, err := collector.Collect(context.Background())
	if !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), `namespace="tetragon"`) || !strings.Contains(err.Error(), "forbidden") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("listing lost namespace or safe cause: %v", err)
	}
	if report.Tool != "" {
		t.Fatal("failed listing produced an upload")
	}
}

func TestLogRequestFailureNamesSensorWithoutProviderBody(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/pods") {
					writePods(w, sensorPod("sensor-a"))
					return
				}
				http.Error(w, "SECRET provider body", status)
			})
			collector, err := New(client, validSettings())
			if err != nil {
				t.Fatal(err)
			}
			report, err := collector.Collect(context.Background())
			want := "forbidden"
			if status == http.StatusNotFound {
				want = "notfound"
			}
			if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "namespace=tetragon pod=sensor-a container=export-stdout") || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("request lost safe reason or sensor: %v", err)
			}
			if status == http.StatusForbidden && !apierrors.IsForbidden(err) || status == http.StatusNotFound && !apierrors.IsNotFound(err) {
				t.Fatalf("request lost typed API cause: %v", err)
			}
			if report.Tool != "" || report.Findings != nil || report.ObservedAt != nil {
				t.Fatal("failed sensor produced an upload")
			}
		})
	}
}

func TestConcurrentHTTPFailuresReturnIdenticalFirstSensorAndCause(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-release:
			status := http.StatusForbidden
			if strings.Contains(r.URL.Path, "/sensor-b/log") {
				status = http.StatusNotFound
			}
			http.Error(w, "SECRET provider body", status)
		case <-r.Context().Done():
		}
	})
	collector, err := New(client, validSettings())
	if err != nil {
		t.Fatal(err)
	}
	accumulator, err := tetragon.NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var total atomic.Int64
	results := make(chan error, 2)
	for _, pod := range []string{"sensor-a", "sensor-b"} {
		go func() { results <- collector.readLog(ctx, pod, &metav1.Time{}, &total, accumulator) }()
	}
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("concurrent requests did not reach the API fixture")
		}
	}
	close(release)
	first, second := <-results, <-results
	var source *tetragon.SourceError
	if first == nil || !identicalFailure(first, second) || !errors.As(first, &source) || strings.Contains(first.Error(), "SECRET") {
		t.Fatalf("HTTP failures lost shared first-error identity: %v / %v", first, second)
	}
	if apierrors.IsForbidden(first) != strings.Contains(source.Source, "pod=sensor-a ") || apierrors.IsNotFound(first) != strings.Contains(source.Source, "pod=sensor-b ") {
		t.Fatalf("HTTP cause was paired with the wrong sensor: %v", first)
	}
	if findings, final := accumulator.Findings(); findings != nil || !identicalFailure(final, first) {
		t.Fatal("HTTP failure permitted a batch or changed the first cause")
	}
}

func TestFirstHTTPFailureSurvivesSiblingCancellation(t *testing.T) {
	bStarted := make(chan struct{})
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			writePods(w, sensorPod("sensor-a"), sensorPod("sensor-b"))
			return
		}
		if strings.Contains(r.URL.Path, "/sensor-a/log") {
			select {
			case <-bStarted:
				http.Error(w, "SECRET", http.StatusForbidden)
			case <-r.Context().Done():
			}
			return
		}
		close(bStarted)
		<-r.Context().Done()
	})
	collector, err := New(client, validSettings())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	report, err := collector.Collect(ctx)
	if err == nil || !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "pod=sensor-a ") || strings.Contains(err.Error(), "sensor-b") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("first request was relabeled or replaced: %v", err)
	}
	if report.Tool != "" {
		t.Fatal("failed request produced an upload")
	}
}

func TestLogTimeoutPreservesContextAndOrigin(t *testing.T) {
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			writePods(w, sensorPod("sensor-a"))
			return
		}
		<-r.Context().Done()
	})
	collector, err := New(client, validSettings())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err = collector.Collect(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "timeout") || !strings.Contains(err.Error(), "pod=sensor-a ") {
		t.Fatalf("timeout lost cause or sensor: %v", err)
	}
}

func TestBudgetFailureNamesCrossingSensorAndActualGlobalCap(t *testing.T) {
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			writePods(w, sensorPod("sensor-a"))
			return
		}
		_, _ = w.Write([]byte(nativeEvent + "\n" + nativeEvent))
	})
	settings := validSettings()
	settings.MaxTotalBytes = int64(len(nativeEvent) + 1)
	collector, err := New(client, settings)
	if err != nil {
		t.Fatal(err)
	}
	report, err := collector.Collect(context.Background())
	if !errors.Is(err, errTotalLogLimit) || !strings.Contains(err.Error(), fmt.Sprintf("%d bytes", settings.MaxTotalBytes)) || !strings.Contains(err.Error(), "across all selected sensors") || !strings.Contains(err.Error(), "pod=sensor-a ") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("global budget lost cap or crossing-read attribution: %v", err)
	}
	if report.Tool != "" {
		t.Fatal("budget failure produced an upload")
	}
}
