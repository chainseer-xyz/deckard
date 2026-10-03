package dnsx

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/time/rate"
)

// ErrRateWait is returned by Limited.Query when no rate-limit token could be
// had before the context ended. Nothing was sent: it says nothing about the
// name, and callers must treat it as "not asked".
var ErrRateWait = errors.New("dnsx: rate limit wait failed")

// Limited wraps a Querier with a hard ceiling on queries per second. Every
// goroutine that shares the Limited shares the ceiling, so a process builds one
// and hands it to every consumer. The bucket holds a single token: queries are
// spaced 1/perSecond apart and never sent in a burst.
type Limited struct {
	q    Querier
	lim  *rate.Limiter
	sent atomic.Int64
}

// NewLimited limits q to perSecond queries per second (a non-positive rate is
// treated as 1).
func NewLimited(q Querier, perSecond float64) *Limited {
	if perSecond <= 0 {
		perSecond = 1
	}
	return &Limited{q: q, lim: rate.NewLimiter(rate.Limit(perSecond), 1)}
}

// Query waits for a token, then asks the wrapped Querier. It returns an error
// wrapping ErrRateWait (and the context's error) when ctx ends first.
func (l *Limited) Query(ctx context.Context, name string, qtype uint16) (*Response, error) {
	if err := l.lim.Wait(ctx); err != nil {
		// Wait fails fast, with its own error, when the wait would outlast the
		// context's deadline: report it as the context error callers expect.
		if cerr := ctx.Err(); cerr != nil {
			err = cerr
		}
		return nil, fmt.Errorf("%w: %w", ErrRateWait, err)
	}
	l.sent.Add(1)
	return l.q.Query(ctx, name, qtype)
}

// Sent is the number of queries handed to the wrapped Querier so far.
func (l *Limited) Sent() int64 { return l.sent.Load() }
