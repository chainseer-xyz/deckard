package nuclei

import (
	"context"
	"errors"
	"testing"
)

func TestProcessGateCapacityCancellationAndIdempotentRelease(t *testing.T) {
	gate := NewProcessGate(1)
	release, err := gate.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := gate.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked acquire error = %v, want context cancellation", err)
	}

	release()
	release() // releasing a slot is deliberately idempotent
	second, err := gate.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second()
}

func TestProcessGateDefaultsToOneSlot(t *testing.T) {
	gate := NewProcessGate(0)
	release, err := gate.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
}
