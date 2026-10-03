package scope

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/chainseer-xyz/deckard/internal/config"
)

// startDNS serves one fixed A record on a local UDP port.
func startDNS(t *testing.T, name, ip string) string {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeA && r.Question[0].Name == name {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP(ip)})
		}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestResolversRouteLookupsToConfiguredServers(t *testing.T) {
	addr := startDNS(t, "app.example.com.", "203.0.113.7")
	g, err := NewGuard(config.ScopeConfig{Include: []string{"*.example.com"}, Resolvers: []string{addr}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := g.resolver.LookupHost(ctx, "app.example.com")
	if err != nil || len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("LookupHost via configured resolver = %v, %v", got, err)
	}
}

func TestResolversRotateToALiveServer(t *testing.T) {
	live := startDNS(t, "app.example.com.", "203.0.113.9")
	dead := "127.0.0.1:1" // nothing listens: a TCP dial would fail, UDP is connectionless
	servers, err := normalizeResolvers([]string{dead, live})
	if err != nil {
		t.Fatal(err)
	}
	r := resolverVia(servers)
	var ok bool
	for i := 0; i < 4 && !ok; i++ { // rotation guarantees the live server leads at least once
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		got, err := r.LookupHost(ctx, "app.example.com")
		cancel()
		ok = err == nil && len(got) == 1 && got[0] == "203.0.113.9"
	}
	if !ok {
		t.Fatal("no lookup reached the live resolver")
	}
}

func TestNormalizeResolvers(t *testing.T) {
	got, err := normalizeResolvers([]string{"1.1.1.1", " 8.8.8.8:5353 ", "2606:4700:4700::1111", "[2001:4860:4860::8888]:53"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.1.1.1:53", "8.8.8.8:5353", "[2606:4700:4700::1111]:53", "[2001:4860:4860::8888]:53"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	for _, bad := range []string{"", "dns.example.com", "1.1.1.1:0", "1.1.1.1:99999", "1.1.1.1:abc"} {
		if _, err := normalizeResolvers([]string{bad}); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
	if _, err := NewGuard(config.ScopeConfig{Include: []string{"a.example.com"}, Resolvers: []string{"not-an-ip"}}); err == nil {
		t.Fatal("NewGuard must reject an invalid resolver")
	}
}
