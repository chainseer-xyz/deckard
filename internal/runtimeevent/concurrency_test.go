package runtimeevent

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestLogFetchConcurrencyIsBoundedAtFour(t *testing.T) {
	var active, peak atomic.Int64
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	defer finish()
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			pods := []corev1.Pod{}
			for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
				pods = append(pods, sensorPod(name))
			}
			writePods(w, pods...)
			return
		}
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-release:
			_, _ = w.Write([]byte(nativeEvent))
		case <-r.Context().Done():
		}
	})
	collector, err := New(client, validSettings(), WithClock(func() time.Time { return time.Date(2026, 10, 14, 12, 5, 0, 0, time.UTC) }))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := collector.Collect(ctx); done <- err }()
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("four bounded workers did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("more than four concurrent log requests")
	case <-time.After(30 * time.Millisecond):
	}
	finish()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("bounded workers did not finish")
	}
	if peak.Load() != 4 {
		t.Fatalf("unexpected peak concurrency: %d", peak.Load())
	}
}

func TestFailureCancelsSiblingLogStreams(t *testing.T) {
	bStarted := make(chan struct{})
	bCanceled := make(chan struct{})
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			writePods(w, sensorPod("a"), sensorPod("b"))
			return
		}
		if strings.Contains(r.URL.Path, "/a/log") {
			select {
			case <-bStarted:
				http.Error(w, "SECRET", http.StatusForbidden)
			case <-r.Context().Done():
			}
			return
		}
		close(bStarted)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(bCanceled)
	})
	settings := validSettings()
	settings.Concurrency = 2
	collector, err := New(client, settings)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err = collector.Collect(ctx)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unsafe partial collection: %v", err)
	}
	select {
	case <-bStarted:
	default:
		t.Fatal("sibling log stream never started")
	}
	select {
	case <-bCanceled:
	case <-time.After(time.Second):
		t.Fatal("failed collection leaked sibling stream")
	}
}
