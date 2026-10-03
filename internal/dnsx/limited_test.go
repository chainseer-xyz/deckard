package dnsx

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type countingQuerier struct{ n atomic.Int64 }

func (c *countingQuerier) Query(_ context.Context, name string, qtype uint16) (*Response, error) {
	c.n.Add(1)
	return &Response{Name: name, Type: qtype, Final: name}, nil
}

func TestLimitedSpacesQueriesAtTheCeiling(t *testing.T) {
	q := &countingQuerier{}
	l := NewLimited(q, 50) // one query every 20ms, no burst
	start := time.Now()
	for range 6 {
		if _, err := l.Query(context.Background(), "example.com", dns.TypeA); err != nil {
			t.Fatal(err)
		}
	}
	// Six queries need five intervals; the first one is immediate.
	if el := time.Since(start); el < 90*time.Millisecond {
		t.Errorf("6 queries at 50/s took %v, want >= 100ms (the ceiling was exceeded)", el)
	}
	if l.Sent() != 6 || q.n.Load() != 6 {
		t.Errorf("sent=%d forwarded=%d, want 6", l.Sent(), q.n.Load())
	}
}

func TestLimitedCeilingIsSharedByConcurrentCallers(t *testing.T) {
	q := &countingQuerier{}
	l := NewLimited(q, 100) // 10ms apart
	start := time.Now()
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 3 {
				_, _ = l.Query(context.Background(), "example.com", dns.TypeA)
			}
		}()
	}
	wg.Wait()
	// 30 queries in total need 29 intervals of 10ms, however many goroutines.
	if el := time.Since(start); el < 270*time.Millisecond {
		t.Errorf("30 queries from 10 goroutines at 100/s took %v, want >= 290ms", el)
	}
	if q.n.Load() != 30 {
		t.Errorf("forwarded %d, want 30", q.n.Load())
	}
}

func TestLimitedDoesNotSendWhenTheContextEnds(t *testing.T) {
	q := &countingQuerier{}
	l := NewLimited(q, 1)
	if _, err := l.Query(context.Background(), "a.example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	// The next token is a second away; the context ends first.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := l.Query(ctx, "b.example.com", dns.TypeA)
	if !errors.Is(err, ErrRateWait) {
		t.Fatalf("err = %v, want ErrRateWait", err)
	}
	if q.n.Load() != 1 {
		t.Errorf("forwarded %d queries, want 1: nothing may be sent after the wait failed", q.n.Load())
	}
	// A cancelled context is reported as such.
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if _, err := l.Query(cctx, "c.example.com", dns.TypeA); !errors.Is(err, ErrRateWait) || !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err = %v, want ErrRateWait wrapping context.Canceled", err)
	}
}

func TestLimitedNonPositiveRateFallsBackToOnePerSecond(t *testing.T) {
	q := &countingQuerier{}
	l := NewLimited(q, 0)
	if _, err := l.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.Query(ctx, "example.com", dns.TypeA); !errors.Is(err, ErrRateWait) {
		t.Errorf("second query within 50ms: err = %v, want ErrRateWait (rate 1/s)", err)
	}
}
