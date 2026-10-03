package app

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/chainseer-xyz/deckard/internal/check/domain/lookalike"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
)

// nxdomainServer answers every query NXDOMAIN and counts them.
func nxdomainServer(t *testing.T) (addr string, queries *atomic.Int64) {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	queries = new(atomic.Int64)
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), queries
}

// The lookup client sends to scope.resolvers, and only there, at no more than
// checks.domain.lookalike.rate_per_second.
func TestBuildLookupUsesConfiguredResolversAndRate(t *testing.T) {
	addr, queries := nxdomainServer(t)
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Scope.Resolvers = []string{addr}
	cfg.Checks = map[string]map[string]any{lookalike.Name: {"rate_per_second": 25}} // one every 40ms
	a := &App{cfg: cfg}
	lk := a.buildLookup()
	lim, ok := lk.(*dnsx.Limited)
	if !ok {
		t.Fatalf("buildLookup returned %T, want the rate-limited client", lk)
	}

	start := time.Now()
	for range 5 {
		r, err := lk.Query(context.Background(), "exmple.com", dns.TypeNS)
		if err != nil {
			t.Fatal(err)
		}
		if r.State() != dnsx.StateNXDomain {
			t.Fatalf("state = %v", r.State())
		}
	}
	if el := time.Since(start); el < 150*time.Millisecond {
		t.Errorf("5 queries at 25/s took %v: the ceiling was not applied", el)
	}
	if queries.Load() != 5 || lim.Sent() != 5 {
		t.Errorf("the configured resolver saw %d queries (limiter sent %d), want 5", queries.Load(), lim.Sent())
	}
}

func TestBuildLookupDefaultsToTheDefaultRate(t *testing.T) {
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := lookalike.RatePerSecond(cfg.Checks[lookalike.Name]); got != lookalike.DefaultRate {
		t.Errorf("default rate = %v", got)
	}
	if _, ok := (&App{cfg: cfg}).buildLookup().(*dnsx.Limited); !ok {
		t.Error("buildLookup must return the limited client with no configuration")
	}
}
