package engine

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strings"
	"sync"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

// keyedSem is a set of counting semaphores addressed by key. Entries are
// removed when idle so the map does not grow with the number of hosts.
type keyedSem struct {
	mu sync.Mutex
	m  map[string]*semEntry
}

type semEntry struct {
	ch   chan struct{}
	refs int
}

func newKeyedSem() *keyedSem { return &keyedSem{m: map[string]*semEntry{}} }

// acquire blocks until a slot (capacity n) for key is free or ctx is done.
func (k *keyedSem) acquire(ctx context.Context, key string, n int) (release func(), err error) {
	if n < 1 {
		n = 1
	}
	key = fmt.Sprintf("%s#%d", key, n)
	k.mu.Lock()
	e, ok := k.m[key]
	if !ok {
		e = &semEntry{ch: make(chan struct{}, n)}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()

	drop := func() {
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
	select {
	case e.ch <- struct{}{}:
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-e.ch
			drop()
		})
	}, nil
}

func (k *keyedSem) size() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}

// limiterSet hands out one scope.HostLimiter per (tier, rate) so every scan of
// the same tier at the same rate shares per-host token buckets.
type limiterSet struct {
	mu sync.Mutex
	m  map[string]*scope.HostLimiter
}

func newLimiterSet() *limiterSet { return &limiterSet{m: map[string]*scope.HostLimiter{}} }

func (l *limiterSet) get(tier model.Tier, perSec float64) *scope.HostLimiter {
	key := fmt.Sprintf("%s|%g", tier, perSec)
	l.mu.Lock()
	defer l.mu.Unlock()
	if h, ok := l.m[key]; ok {
		return h
	}
	burst := int(math.Ceil(perSec))
	if burst < 1 {
		burst = 1
	}
	h := scope.NewHostLimiter(perSec, burst)
	l.m[key] = h
	return h
}

// hostOf returns the network host an asset's probes will hit, used to key
// per-host concurrency.
func hostOf(a model.Asset) string {
	switch a.Kind {
	case model.KindService:
		if ip, ok := assetIP(a); ok {
			return ip.String()
		}
	case model.KindURL:
		if u, err := url.Parse(a.Key); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	return strings.ToLower(strings.TrimSuffix(a.Key, "."))
}
