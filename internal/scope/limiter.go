package scope

import (
	"context"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter throttles outbound operations per target host.
type RateLimiter interface {
	Wait(ctx context.Context, host string) error
}

// HostLimiter is a per-host token bucket (golang.org/x/time/rate). Hosts are
// normalised so spellings of the same name share one bucket.
type HostLimiter struct {
	perSec rate.Limit
	burst  int

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

// NewHostLimiter allows perSec events per second per host with the given
// burst. perSec <= 0 means unlimited; burst < 1 is raised to 1.
func NewHostLimiter(perSec float64, burst int) *HostLimiter {
	l := rate.Limit(perSec)
	if perSec <= 0 {
		l = rate.Inf
	}
	if burst < 1 {
		burst = 1
	}
	return &HostLimiter{perSec: l, burst: burst, limiters: map[string]*rate.Limiter{}}
}

// Wait blocks until host may be contacted or ctx is done.
func (h *HostLimiter) Wait(ctx context.Context, host string) error {
	key, ok := normHost(host)
	if !ok {
		key = strings.ToLower(strings.TrimSpace(host))
	}
	h.mu.Lock()
	lim, ok := h.limiters[key]
	if !ok {
		lim = rate.NewLimiter(h.perSec, h.burst)
		h.limiters[key] = lim
	}
	h.mu.Unlock()
	return lim.Wait(ctx)
}
