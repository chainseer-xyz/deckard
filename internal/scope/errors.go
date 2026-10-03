package scope

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
)

var (
	// ErrOutOfScope is returned when a network operation targets something the
	// guard does not permit for the requested tier (not owned, private
	// destination, rebinding, out-of-scope redirect, ...).
	ErrOutOfScope = errors.New("scope: target out of scope")
	// ErrExcluded is returned when the target matches scope.exclude. A
	// refusal for an excluded target satisfies errors.Is for both ErrExcluded
	// and ErrOutOfScope, so callers that only care about "refused" can test
	// ErrOutOfScope.
	ErrExcluded = errors.New("scope: target excluded")
	// ErrTooManyRedirects is returned by guarded HTTP clients when the
	// redirect cap is exceeded.
	ErrTooManyRedirects = errors.New("scope: too many redirects")
)

// RefusalError describes why the guard refused an operation.
type RefusalError struct {
	Op     string // dial, resolve, redirect
	Target string
	Tier   model.Tier
	Class  model.ScopeClass
	Reason string
	kind   error
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("%v: %s %s refused (%s)", e.kind, e.Op, e.Target, e.Reason)
}

// Is makes an excluded refusal match both ErrExcluded and ErrOutOfScope.
func (e *RefusalError) Is(target error) bool {
	if target == e.kind {
		return true
	}
	return e.kind == ErrExcluded && target == ErrOutOfScope
}

// refusalWarnEvery is how often an expected refusal of the same (target,
// reason) is logged at WARN; repeats in between log at DEBUG.
const refusalWarnEvery = time.Hour

// maxThrottled bounds the refusal throttle's memory.
const maxThrottled = 10000

// refusalThrottle remembers when each (target, reason) was last logged at
// WARN. The zero value is ready to use.
type refusalThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time
	now  func() time.Time // test hook; nil => time.Now
}

// warn reports whether this refusal should be logged at WARN, recording it.
func (t *refusalThrottle) warn(target, reason string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if t.now != nil {
		now = t.now()
	}
	k := target + "\x00" + reason
	if at, ok := t.last[k]; ok && now.Sub(at) < refusalWarnEvery {
		return false
	}
	if t.last == nil {
		t.last = map[string]time.Time{}
	}
	if len(t.last) >= maxThrottled {
		for key, at := range t.last {
			if now.Sub(at) >= refusalWarnEvery {
				delete(t.last, key)
			}
		}
		if len(t.last) >= maxThrottled {
			t.last = map[string]time.Time{}
		}
	}
	t.last[k] = now
	return true
}

// refuse logs and counts an EXPECTED refusal (a non-owned destination for the
// tier, a third-party name, an out-of-scope redirect, ...) and returns the
// typed error. These are routine by design, so each distinct (target,
// reason) is logged at WARN at most once per refusalWarnEvery and at DEBUG
// otherwise. An excluded target is never routine and always logs at WARN.
// Every refusal is counted (WithRefusalObserver) whatever its level.
func (g *Guard) refuse(kind error, op string, tier model.Tier, target string, class model.ScopeClass, reason string) error {
	level := slog.LevelDebug
	if errors.Is(kind, ErrExcluded) || g.throttle.warn(target, reason) {
		level = slog.LevelWarn
	}
	return g.refuseAt(level, kind, op, tier, target, class, reason)
}

// refuseAnomaly is refuse for refusals that point at something genuinely
// wrong (a loopback, private or metadata destination, an unparseable
// resolver answer, a forbidden protocol): always logged at WARN.
func (g *Guard) refuseAnomaly(kind error, op string, tier model.Tier, target string, class model.ScopeClass, reason string) error {
	return g.refuseAt(slog.LevelWarn, kind, op, tier, target, class, reason)
}

// refuseAt logs at an explicit level, counts the refusal and returns the
// typed error. Only the log level differs between the refuse variants: the
// returned error is identical.
func (g *Guard) refuseAt(level slog.Level, kind error, op string, tier model.Tier, target string, class model.ScopeClass, reason string) error {
	if g.observe != nil {
		g.observe(string(tier), string(class), reason)
	}
	g.log.Log(context.Background(), level, "scope refusal",
		slog.String("op", op),
		slog.String("target", target),
		slog.String("tier", string(tier)),
		slog.String("class", string(class)),
		slog.String("reason", reason),
		slog.Bool("excluded", errors.Is(kind, ErrExcluded)),
	)
	return &RefusalError{Op: op, Target: target, Tier: tier, Class: class, Reason: reason, kind: kind}
}
