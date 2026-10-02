package scope

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

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

// refuse logs the refusal (structured) and returns the typed error.
func (g *Guard) refuse(kind error, op string, tier model.Tier, target string, class model.ScopeClass, reason string) error {
	return g.refuseAt(slog.LevelWarn, kind, op, tier, target, class, reason)
}

// refuseAt is refuse with an explicit log level. Only the log level differs:
// the returned error is identical.
func (g *Guard) refuseAt(level slog.Level, kind error, op string, tier model.Tier, target string, class model.ScopeClass, reason string) error {
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
