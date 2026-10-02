package scope

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

type netipPrefix = netip.Prefix

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestHostLimiterPerHostIsolation(t *testing.T) {
	l := NewHostLimiter(50, 1)
	ctx := context.Background()
	start := time.Now()
	// Different hosts never wait on each other.
	for _, h := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if err := l.Wait(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 15*time.Millisecond {
		t.Fatalf("distinct hosts throttled each other: %v", time.Since(start))
	}
	// Same host: burst 1 then ~20ms spacing at 50/s.
	start = time.Now()
	for i := 0; i < 4; i++ {
		if err := l.Wait(ctx, "d.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 50*time.Millisecond {
		t.Fatalf("same host not throttled: %v", el)
	}
}

func TestHostLimiterNormalisesHost(t *testing.T) {
	l := NewHostLimiter(1, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx, "A.Example.com."); err != nil {
		t.Fatal(err)
	}
	// Same logical host in a different spelling must share the bucket.
	if err := l.Wait(ctx, "a.example.com"); err == nil {
		t.Fatal("expected ctx deadline: buckets must be shared across spellings")
	}
}

func TestHostLimiterContextCancel(t *testing.T) {
	l := NewHostLimiter(0.001, 1)
	_ = l.Wait(context.Background(), "x")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx, "x"); err == nil {
		t.Fatal("cancelled ctx must error")
	}
}

func TestHostLimiterUnlimited(t *testing.T) {
	l := NewHostLimiter(0, 0)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		if err := l.Wait(context.Background(), "x"); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("perSec<=0 must mean unlimited")
	}
}
