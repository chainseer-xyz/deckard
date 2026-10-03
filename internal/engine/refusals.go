package engine

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

// refusalTracker wraps a check's guarded dialer and remembers whether the
// guard refused any connection. A refused dial observed nothing, but many
// checks treat any dial error as "closed" or "not offered"; without this a
// run whose every connection was refused could look clean and resolve
// findings. runCheck marks such a run Partial instead.
type refusalTracker struct {
	d       check.Dialer
	refused atomic.Bool
}

func (t *refusalTracker) note(err error) {
	if err != nil && errors.Is(err, scope.ErrOutOfScope) {
		t.refused.Store(true)
	}
}

func (t *refusalTracker) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := t.d.DialContext(ctx, network, address)
	t.note(err)
	return c, err
}

// timeoutRefusalTracker is a refusalTracker for dialers that also implement
// check.TimeoutDialer, so wrapping never changes what a check can do.
type timeoutRefusalTracker struct{ *refusalTracker }

func (t timeoutRefusalTracker) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	c, err := t.d.(check.TimeoutDialer).DialTimeout(ctx, network, address, timeout)
	t.note(err)
	return c, err
}

// trackRefusals wraps d (nil stays nil) and returns the tracker to consult.
func trackRefusals(d check.Dialer) (check.Dialer, *refusalTracker) {
	if d == nil {
		return nil, &refusalTracker{}
	}
	t := &refusalTracker{d: d}
	if _, ok := d.(check.TimeoutDialer); ok {
		return timeoutRefusalTracker{t}, t
	}
	return t, t
}
