package api

import (
	"sync"
	"sync/atomic"

	"github.com/chainseer-xyz/deckard/internal/store"
)

const subscriberBuffer = 16

// Broadcaster is an in-process pub/sub used to wake SSE streams promptly when
// the engine records a change. Delivery is best-effort: a subscriber whose
// buffer is full drops the event instead of blocking the publisher. SSE
// handlers treat events as wake-up hints and re-read the store, so a dropped
// hint is harmless.
type Broadcaster struct {
	mu      sync.RWMutex
	subs    map[*subscriber]struct{}
	dropped atomic.Uint64
}

type subscriber struct{ ch chan store.Event }

// NewBroadcaster returns an empty Broadcaster.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{subs: map[*subscriber]struct{}{}}
}

// Subscribe returns a channel of events and a cancel func that must be called
// to release it. The channel is never closed by Publish; cancel closes it.
func (b *Broadcaster) Subscribe() (<-chan store.Event, func()) {
	s := &subscriber{ch: make(chan store.Event, subscriberBuffer)}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	return s.ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, s)
			b.mu.Unlock()
			close(s.ch)
		})
	}
}

// Publish delivers e to every subscriber without blocking.
func (b *Broadcaster) Publish(e store.Event) {
	// Holding the read lock across the sends guarantees a concurrent cancel
	// (which needs the write lock before closing) cannot close a channel we
	// are sending on.
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		select {
		case s.ch <- e:
		default:
			b.dropped.Add(1)
		}
	}
}

// Subscribers reports the number of live subscribers.
func (b *Broadcaster) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// Dropped reports how many deliveries were skipped because a subscriber was slow.
func (b *Broadcaster) Dropped() uint64 { return b.dropped.Load() }
