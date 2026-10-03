package nuclei

import (
	"context"
	"sync"
)

// ProcessGate limits the number of nuclei processes alive at once. A nuclei
// process loads the template corpus into its heap, so queue worker count is
// not a safe memory bound by itself.
type ProcessGate struct {
	slots chan struct{}
}

// NewProcessGate returns a process limiter. Non-positive capacities become one.
func NewProcessGate(capacity int) *ProcessGate {
	if capacity < 1 {
		capacity = 1
	}
	return &ProcessGate{slots: make(chan struct{}, capacity)}
}

func (g *ProcessGate) acquire(ctx context.Context) (func(), error) {
	if g == nil {
		return func() {}, nil
	}
	select {
	case g.slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-g.slots }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
