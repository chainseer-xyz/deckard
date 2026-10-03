package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

type errDialer struct{ err error }

func (d errDialer) DialContext(context.Context, string, string) (net.Conn, error) { return nil, d.err }

type errTimeoutDialer struct{ errDialer }

func (d errTimeoutDialer) DialTimeout(context.Context, string, string, time.Duration) (net.Conn, error) {
	return nil, d.err
}

func TestTrackRefusals(t *testing.T) {
	if d, tr := trackRefusals(nil); d != nil || tr.refused.Load() {
		t.Fatal("a nil dialer must stay nil")
	}
	refusal := fmt.Errorf("wrapped: %w", scope.ErrOutOfScope)

	d, tr := trackRefusals(errDialer{errors.New("connection refused")})
	if _, ok := d.(check.TimeoutDialer); ok {
		t.Fatal("wrapping must not add DialTimeout to a dialer without it")
	}
	_, _ = d.DialContext(context.Background(), "tcp", "a:1")
	if tr.refused.Load() {
		t.Fatal("an ordinary dial error is not a scope refusal")
	}

	d, tr = trackRefusals(errTimeoutDialer{errDialer{refusal}})
	td, ok := d.(check.TimeoutDialer)
	if !ok {
		t.Fatal("wrapping must keep DialTimeout (net.ports relies on it)")
	}
	_, err := td.DialTimeout(context.Background(), "tcp", "a:1", time.Second)
	if !errors.Is(err, scope.ErrOutOfScope) || !tr.refused.Load() {
		t.Fatalf("refusal not passed through or not tracked: %v", err)
	}
}
