package engine

import (
	"context"
	"testing"
	"time"
)

func TestRunRefdataLoopRefreshesAtStartAndStops(t *testing.T) {
	f := &fakeRefresher{}
	e := refdataEngine(t, true, f)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.RunRefdataLoop(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for f.calls.Load() < 1 {
		select {
		case <-deadline:
			t.Fatal("no startup refresh")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not stop")
	}
	// Disabled: returns immediately.
	refdataEngine(t, false, &fakeRefresher{}).RunRefdataLoop(context.Background())
}
