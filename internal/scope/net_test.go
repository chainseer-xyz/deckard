package scope

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// recordingDialer is the invariant probe: it records every address the guard
// actually hands to the underlying dialer.
type recordingDialer struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]bool // addresses that return an error
}

func (r *recordingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	r.mu.Lock()
	r.calls = append(r.calls, network+"|"+address)
	fail := r.fail[address]
	r.mu.Unlock()
	if fail {
		return nil, errors.New("recording: forced failure")
	}
	c1, c2 := net.Pipe()
	go func() { _ = c2.Close() }()
	return c1, nil
}

func (r *recordingDialer) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// fakeResolver returns a scripted sequence of answers per host (the last
// answer repeats), letting tests simulate DNS rebinding.
type fakeResolver struct {
	mu    sync.Mutex
	seq   map[string][][]string
	count map[string]int
	err   error
	cname map[string]string
}

func newFakeResolver(m map[string][][]string) *fakeResolver {
	return &fakeResolver{seq: m, count: map[string]int{}, cname: map[string]string{}}
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	answers, ok := f.seq[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	i := f.count[host]
	f.count[host]++
	if i >= len(answers) {
		i = len(answers) - 1
	}
	return answers[i], nil
}
func (f *fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count["cname:"+host]++
	return f.cname[host], nil
}
func (f *fakeResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count["txt:"+host]++
	return []string{"v=spf1 -all"}, nil
}
func (f *fakeResolver) LookupNS(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count["ns:"+host]++
	return []string{"ns1.example.com."}, nil
}
func (f *fakeResolver) calls(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count[key]
}

type countingLimiter struct {
	mu    sync.Mutex
	hosts []string
	err   error
}

func (c *countingLimiter) Wait(_ context.Context, host string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hosts = append(c.hosts, host)
	return c.err
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func netGuard(t *testing.T, res *fakeResolver, rec *recordingDialer, extra ...Option) *Guard {
	t.Helper()
	opts := append([]Option{WithResolver(res), WithDialer(rec), WithLogger(quietLogger())}, extra...)
	g, err := NewGuard(config.ScopeConfig{Exclude: []string{"secret.example.com", "10.9.9.9", "198.51.100.0/24"}}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	g.SetZones([]string{"example.com"})
	g.SetOwnedPrefixes(nil)
	return g
}

func TestDialerNeverReachesUnderlyingDialerWhenRefused(t *testing.T) {
	type tc struct {
		name    string
		tier    model.Tier
		class   model.ScopeClass
		address string
		answers [][]string // resolver script for the host
		wantErr error      // nil => must succeed
		wantDst string     // expected underlying dial address when success
	}
	ownedHost := "app.example.com:443"
	tests := []tc{
		{"owned host -> owned-prefix-less public ip (passive ok)", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"93.184.216.34"}}, nil, "93.184.216.34:443"},
		{"owned host -> shared cloudflare ip passive ok", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"104.16.0.1"}}, nil, "104.16.0.1:443"},
		{"owned host -> shared ip active refused", model.TierActive, model.ScopeOwned, ownedHost, [][]string{{"104.16.0.1"}}, ErrOutOfScope, ""},
		{"owned host -> external ip active refused", model.TierActive, model.ScopeOwned, ownedHost, [][]string{{"93.184.216.34"}}, ErrOutOfScope, ""},
		{"owned host -> RFC1918", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"10.0.0.1"}}, ErrOutOfScope, ""},
		{"owned host -> 192.168", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"192.168.1.1"}}, ErrOutOfScope, ""},
		{"owned host -> 172.16", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"172.16.0.1"}}, ErrOutOfScope, ""},
		{"owned host -> loopback", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"127.0.0.1"}}, ErrOutOfScope, ""},
		{"owned host -> v6 loopback", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"::1"}}, ErrOutOfScope, ""},
		{"owned host -> v4-mapped loopback", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"::ffff:127.0.0.1"}}, ErrOutOfScope, ""},
		{"owned host -> aws metadata", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"169.254.169.254"}}, ErrOutOfScope, ""},
		{"owned host -> v4-mapped metadata", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"::ffff:169.254.169.254"}}, ErrOutOfScope, ""},
		{"owned host -> aws v6 metadata", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"fd00:ec2::254"}}, ErrOutOfScope, ""},
		{"owned host -> link-local v6", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"fe80::1"}}, ErrOutOfScope, ""},
		{"owned host -> ULA", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"fc00::1"}}, ErrOutOfScope, ""},
		{"owned host -> unspecified", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"0.0.0.0"}}, ErrOutOfScope, ""},
		{"owned host -> v6 unspecified", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"::"}}, ErrOutOfScope, ""},
		{"owned host -> cgnat/alibaba metadata", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"100.100.100.200"}}, ErrOutOfScope, ""},
		{"owned host -> multicast", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"224.0.0.1"}}, ErrOutOfScope, ""},
		{"owned host -> broadcast/reserved", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"255.255.255.255"}}, ErrOutOfScope, ""},
		{"owned host -> NAT64", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"64:ff9b::7f00:1"}}, ErrOutOfScope, ""},
		{"owned host -> excluded ip", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"198.51.100.9"}}, ErrExcluded, ""},
		{"owned host -> excluded single ip", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"10.9.9.9"}}, ErrExcluded, ""},
		{"mixed answers: good then private", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"93.184.216.34", "10.0.0.1"}}, ErrOutOfScope, ""},
		{"mixed answers: good then metadata", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"93.184.216.34", "169.254.169.254"}}, ErrOutOfScope, ""},
		{"mixed answers: private then good", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"10.0.0.1", "93.184.216.34"}}, ErrOutOfScope, ""},
		{"mixed answers: good then excluded", model.TierPassive, model.ScopeOwned, ownedHost, [][]string{{"93.184.216.34", "198.51.100.1"}}, ErrExcluded, ""},
		{"excluded hostname", model.TierPassive, model.ScopeOwned, "secret.example.com:443", [][]string{{"93.184.216.34"}}, ErrExcluded, ""},
		{"asset class excluded", model.TierPassive, model.ScopeExcluded, ownedHost, [][]string{{"93.184.216.34"}}, ErrExcluded, ""},
		{"external host passive refused (never dial third-party names)", model.TierPassive, model.ScopeExternal, "foo.s3.amazonaws.com:443", [][]string{{"93.184.216.34"}}, ErrOutOfScope, ""},
		{"external host active refused", model.TierActive, model.ScopeExternal, "foo.s3.amazonaws.com:443", [][]string{{"93.184.216.34"}}, ErrOutOfScope, ""},
		{"external host intrusive refused", model.TierIntrusive, model.ScopeExternal, "foo.s3.amazonaws.com:443", [][]string{{"93.184.216.34"}}, ErrOutOfScope, ""},
		{"asset class owned but dialed host external, active", model.TierActive, model.ScopeOwned, "foo.s3.amazonaws.com:443", [][]string{{"93.184.216.34"}}, ErrOutOfScope, ""},
		{"external host -> private", model.TierPassive, model.ScopeExternal, "foo.s3.amazonaws.com:443", [][]string{{"10.0.0.1"}}, ErrOutOfScope, ""},
		{"shared asset class passive ok", model.TierPassive, model.ScopeShared, ownedHost, [][]string{{"104.16.0.1"}}, nil, "104.16.0.1:443"},
		{"shared asset class active refused", model.TierActive, model.ScopeShared, ownedHost, [][]string{{"104.16.0.1"}}, ErrOutOfScope, ""},
		{"unknown tier", "bogus", model.ScopeOwned, ownedHost, [][]string{{"93.184.216.34"}}, ErrOutOfScope, ""},
		{"nxdomain", model.TierPassive, model.ScopeOwned, "nx.example.com:443", nil, errAny, ""},
		// literal IPs: IP-based probing only for owned IPs.
		{"literal external ip passive refused", model.TierPassive, model.ScopeOwned, "93.184.216.34:443", nil, ErrOutOfScope, ""},
		{"literal shared ip passive refused", model.TierPassive, model.ScopeShared, "104.16.0.1:443", nil, ErrOutOfScope, ""},
		{"literal metadata", model.TierPassive, model.ScopeOwned, "169.254.169.254:80", nil, ErrOutOfScope, ""},
		{"literal private unregistered", model.TierActive, model.ScopeOwned, "10.0.0.1:22", nil, ErrOutOfScope, ""},
		{"literal v6 loopback", model.TierActive, model.ScopeOwned, "[::1]:22", nil, ErrOutOfScope, ""},
		{"literal excluded", model.TierActive, model.ScopeOwned, "198.51.100.1:22", nil, ErrExcluded, ""},
		{"literal v4-mapped excluded", model.TierActive, model.ScopeOwned, "[::ffff:10.9.9.9]:22", nil, ErrExcluded, ""},
		{"literal v6 zone id", model.TierActive, model.ScopeOwned, "[fe80::1%en0]:22", nil, ErrOutOfScope, ""},
		// malformed
		{"no port", model.TierPassive, model.ScopeOwned, "app.example.com", nil, errAny, ""},
		{"empty host", model.TierPassive, model.ScopeOwned, ":443", nil, errAny, ""},
		{"bad port", model.TierPassive, model.ScopeOwned, "app.example.com:http", nil, errAny, ""},
		{"host with injection", model.TierPassive, model.ScopeOwned, "evil.net/.example.com:443", nil, errAny, ""},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			res := newFakeResolver(map[string][][]string{})
			host, _, _ := net.SplitHostPort(c.address)
			if c.answers != nil {
				res.seq[host] = c.answers
			}
			rec := &recordingDialer{}
			g := netGuard(t, res, rec)
			d := g.Dialer(c.tier, c.class, nil)
			conn, err := d.DialContext(context.Background(), "tcp", c.address)
			calls := rec.Calls()
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				_ = conn.Close()
				if len(calls) != 1 || calls[0] != "tcp|"+c.wantDst {
					t.Fatalf("underlying dial calls = %v, want exactly tcp|%s (vetted IP, never the hostname)", calls, c.wantDst)
				}
				return
			}
			if err == nil {
				_ = conn.Close()
				t.Fatalf("want error, got success; dial calls %v", calls)
			}
			if !errors.Is(c.wantErr, errAny) && !errors.Is(err, c.wantErr) {
				t.Fatalf("error = %v, want errors.Is %v", err, c.wantErr)
			}
			if len(calls) != 0 {
				t.Fatalf("INVARIANT VIOLATED: underlying dialer invoked for refused dial: %v", calls)
			}
		})
	}
}

var errAny = errors.New("any error")

func TestExcludedErrorIsAlsoOutOfScope(t *testing.T) {
	if !errors.Is(ErrExcluded, ErrOutOfScope) {
		// ErrExcluded itself is a sentinel; refusals built from it must match both.
		res := newFakeResolver(nil)
		rec := &recordingDialer{}
		g := netGuard(t, res, rec)
		_, err := g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "198.51.100.1:80")
		if !errors.Is(err, ErrExcluded) || !errors.Is(err, ErrOutOfScope) {
			t.Fatalf("excluded refusal must match both sentinels: %v", err)
		}
	}
}

func TestDialerRegisteredPrivateIsOwned(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"internal.example.com": {{"10.0.0.5"}}})
	rec := &recordingDialer{}
	g := netGuard(t, res, rec)
	g.SetOwnedPrefixes([]netipPrefix{mustPrefix("10.0.0.0/24")})
	d := g.Dialer(model.TierActive, model.ScopeOwned, nil)
	if c, err := d.DialContext(context.Background(), "tcp", "internal.example.com:22"); err != nil {
		t.Fatalf("registered private IP must be allowed: %v", err)
	} else {
		_ = c.Close()
	}
	if c, err := d.DialContext(context.Background(), "tcp", "10.0.0.6:22"); err != nil {
		t.Fatalf("literal registered private IP must be allowed: %v", err)
	} else {
		_ = c.Close()
	}
	if _, err := d.DialContext(context.Background(), "tcp", "10.0.1.6:22"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("neighbour not registered: %v", err)
	}
	if n := len(rec.Calls()); n != 2 {
		t.Fatalf("calls=%v", rec.Calls())
	}
}

func TestDialerRebinding(t *testing.T) {
	// First lookup returns a good IP, later lookups rebind to internal targets.
	res := newFakeResolver(map[string][][]string{
		"app.example.com": {{"93.184.216.34"}, {"10.0.0.1"}, {"169.254.169.254"}, {"93.184.216.34"}},
	})
	rec := &recordingDialer{}
	g := netGuard(t, res, rec)
	d := g.Dialer(model.TierPassive, model.ScopeOwned, nil)
	wantOK := []bool{true, false, false, true}
	for i, ok := range wantOK {
		c, err := d.DialContext(context.Background(), "tcp", "app.example.com:80")
		if ok != (err == nil) {
			t.Fatalf("dial %d: ok=%v err=%v", i, ok, err)
		}
		if err == nil {
			_ = c.Close()
		} else if !errors.Is(err, ErrOutOfScope) {
			t.Fatalf("dial %d: %v", i, err)
		}
	}
	for _, call := range rec.Calls() {
		if call != "tcp|93.184.216.34:80" {
			t.Fatalf("INVARIANT VIOLATED: rebound address reached the dialer: %v", rec.Calls())
		}
	}
	if len(rec.Calls()) != 2 {
		t.Fatalf("calls=%v", rec.Calls())
	}
}

func TestDialerRebindingMixedSingleAnswer(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"app.example.com": {{"93.184.216.34", "169.254.169.254"}}})
	rec := &recordingDialer{}
	g := netGuard(t, res, rec)
	_, err := g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "app.example.com:80")
	if !errors.Is(err, ErrOutOfScope) || len(rec.Calls()) != 0 {
		t.Fatalf("err=%v calls=%v", err, rec.Calls())
	}
}

func TestDialerFallsBackAcrossVettedIPs(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"app.example.com": {{"93.184.216.34", "93.184.216.35"}}})
	rec := &recordingDialer{fail: map[string]bool{"93.184.216.34:80": true}}
	g := netGuard(t, res, rec)
	c, err := g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "app.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if got := rec.Calls(); len(got) != 2 || got[1] != "tcp|93.184.216.35:80" {
		t.Fatalf("calls=%v", got)
	}
}

func TestDialerNetworks(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"app.example.com": {{"93.184.216.34"}}})
	for _, n := range []string{"tcp", "tcp4", "tcp6", "udp", "udp4"} {
		rec := &recordingDialer{}
		g := netGuard(t, res, rec)
		c, err := g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), n, "app.example.com:53")
		if err != nil {
			t.Errorf("%s: %v", n, err)
			continue
		}
		_ = c.Close()
	}
	for _, n := range []string{"unix", "ip", "ip4:icmp", "", "unixgram"} {
		rec := &recordingDialer{}
		g := netGuard(t, res, rec)
		if _, err := g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), n, "app.example.com:53"); err == nil {
			t.Errorf("network %q must be refused", n)
		}
		if len(rec.Calls()) != 0 {
			t.Errorf("network %q reached dialer", n)
		}
	}
}

func TestDialerRateLimit(t *testing.T) {
	res := newFakeResolver(map[string][][]string{"app.example.com": {{"93.184.216.34"}}})
	rec := &recordingDialer{}
	g := netGuard(t, res, rec)
	lim := &countingLimiter{}
	c, err := g.Dialer(model.TierPassive, model.ScopeOwned, lim).DialContext(context.Background(), "tcp", "app.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(lim.hosts) != 1 || lim.hosts[0] != "app.example.com" {
		t.Fatalf("limiter hosts=%v", lim.hosts)
	}
	lim.err = context.DeadlineExceeded
	if _, err := g.Dialer(model.TierPassive, model.ScopeOwned, lim).DialContext(context.Background(), "tcp", "app.example.com:80"); err == nil {
		t.Fatal("limiter error must abort dial")
	}
	if len(rec.Calls()) != 1 {
		t.Fatalf("dial happened despite limiter error: %v", rec.Calls())
	}
}

func TestResolver(t *testing.T) {
	res := newFakeResolver(map[string][][]string{
		"app.example.com":      {{"93.184.216.34", "198.51.100.1", "2001:db8::1"}},
		"foo.s3.amazonaws.com": {{"52.1.1.1"}},
	})
	res.cname["app.example.com"] = "foo.s3.amazonaws.com."
	rec := &recordingDialer{}
	g := netGuard(t, res, rec)
	ctx := context.Background()

	r := g.Resolver(model.TierPassive, model.ScopeOwned, nil)
	ips, err := r.LookupHost(ctx, "app.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		if ip == "198.51.100.1" {
			t.Fatalf("excluded IP leaked through resolver: %v", ips)
		}
	}
	if len(ips) != 2 {
		t.Fatalf("ips=%v", ips)
	}
	if cn, err := r.LookupCNAME(ctx, "app.example.com"); err != nil || cn != "foo.s3.amazonaws.com." {
		t.Fatalf("cname %q %v", cn, err)
	}
	if _, err := r.LookupTXT(ctx, "app.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.LookupNS(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	// External target lookup (CNAME target fingerprinting) is allowed for a passive owned asset.
	if _, err := r.LookupHost(ctx, "foo.s3.amazonaws.com"); err != nil {
		t.Fatalf("external target lookup should be allowed: %v", err)
	}

	// Excluded names never reach the underlying resolver.
	before := res.calls("secret.example.com") + res.calls("cname:secret.example.com") + res.calls("txt:secret.example.com") + res.calls("ns:secret.example.com")
	for name, f := range map[string]func() error{
		"host":  func() error { _, e := r.LookupHost(ctx, "secret.example.com"); return e },
		"cname": func() error { _, e := r.LookupCNAME(ctx, "x.secret.example.com"); return e },
		"txt":   func() error { _, e := r.LookupTXT(ctx, "SECRET.example.com."); return e },
		"ns":    func() error { _, e := r.LookupNS(ctx, "secret.example.com"); return e },
	} {
		if err := f(); !errors.Is(err, ErrExcluded) {
			t.Errorf("%s: %v", name, err)
		}
	}
	after := res.calls("secret.example.com") + res.calls("cname:secret.example.com") + res.calls("cname:x.secret.example.com") + res.calls("txt:secret.example.com") + res.calls("ns:secret.example.com")
	if before != after {
		t.Fatal("excluded lookup reached underlying resolver")
	}

	// Excluded or disallowed asset class cannot resolve at all.
	rx := g.Resolver(model.TierPassive, model.ScopeExcluded, nil)
	if _, err := rx.LookupHost(ctx, "app.example.com"); !errors.Is(err, ErrExcluded) {
		t.Fatalf("excluded class: %v", err)
	}
	ra := g.Resolver(model.TierActive, model.ScopeExternal, nil)
	if _, err := ra.LookupHost(ctx, "app.example.com"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("active/external: %v", err)
	}
	// Literal excluded IP.
	if _, err := r.LookupHost(ctx, "198.51.100.1"); !errors.Is(err, ErrExcluded) {
		t.Fatalf("literal excluded IP: %v", err)
	}
	// Rate limiter.
	lim := &countingLimiter{}
	rl := g.Resolver(model.TierPassive, model.ScopeOwned, lim)
	_, _ = rl.LookupTXT(ctx, "app.example.com")
	if len(lim.hosts) != 1 || lim.hosts[0] != "app.example.com" {
		t.Fatalf("limiter %v", lim.hosts)
	}
}

// ---- HTTP client ----

type httpEnv struct {
	g     *Guard
	res   *fakeResolver
	hits  map[string]*atomic.Int32
	srvA  *httptest.Server
	srvB  *httptest.Server
	portA string
	portB string
}

func setupHTTP(t *testing.T) *httpEnv {
	t.Helper()
	e := &httpEnv{hits: map[string]*atomic.Int32{"A": {}, "B": {}}}
	e.srvB = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits["B"].Add(1)
		_, _ = io.WriteString(w, "B")
	}))
	t.Cleanup(e.srvB.Close)
	e.srvA = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits["A"].Add(1)
		switch r.URL.Path {
		case "/ok":
			_, _ = io.WriteString(w, "A-ok")
		case "/same":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/to-owned":
			http.Redirect(w, r, "http://other.example.com:"+e.portA+"/ok", http.StatusFound)
		case "/to-external":
			http.Redirect(w, r, "http://evil.test:"+e.portB+"/", http.StatusFound)
		case "/to-lookalike":
			http.Redirect(w, r, "http://evil-example.com:"+e.portB+"/", http.StatusFound)
		case "/to-excluded":
			http.Redirect(w, r, "http://secret.example.com:"+e.portB+"/", http.StatusFound)
		case "/to-ip":
			http.Redirect(w, r, "http://10.0.0.1:"+e.portB+"/", http.StatusFound)
		case "/to-metadata":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		case "/to-ftp":
			http.Redirect(w, r, "ftp://other.example.com/", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(e.srvA.Close)
	e.portA = portOf(t, e.srvA.URL)
	e.portB = portOf(t, e.srvB.URL)
	e.res = newFakeResolver(map[string][][]string{
		"app.example.com":       {{"127.0.0.1"}},
		"other.example.com":     {{"127.0.0.1"}},
		"secret.example.com":    {{"127.0.0.1"}},
		"evil.test":             {{"127.0.0.1"}},
		"evil-example.com":      {{"127.0.0.1"}},
		"rebind.example.com":    {{"127.0.0.1"}, {"10.0.0.1"}},
		"external-app.test":     {{"127.0.0.1"}},
		"external-app.test.net": {{"127.0.0.1"}},
	})
	// The httptest servers live on loopback: the operator owns it explicitly via
	// scope.include (discovered sources can never register loopback).
	g, err := NewGuard(config.ScopeConfig{Include: []string{"127.0.0.1"}, Exclude: []string{"secret.example.com"}}, WithResolver(e.res), WithLogger(quietLogger()))
	if err != nil {
		t.Fatal(err)
	}
	g.SetZones([]string{"example.com"})
	e.g = g
	return e
}

func portOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

// httpGet issues a GET through cl using a context-bound request so tests
// don't rely on the deprecated, context-less (*http.Client).Get.
func httpGet(t *testing.T, cl *http.Client, rawURL string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return cl.Do(req)
}

func TestHTTPClientRedirects(t *testing.T) {
	e := setupHTTP(t)
	cl := e.g.HTTPClient(model.TierPassive, model.ScopeOwned, nil)
	base := "http://app.example.com:" + e.portA

	tests := []struct {
		name    string
		path    string
		wantErr error // nil: success
		wantB   int32 // hits that must have reached server B
		body    string
	}{
		{"no redirect", "/ok", nil, 0, "A-ok"},
		{"same host redirect", "/same", nil, 0, "A-ok"},
		{"redirect to other owned host", "/to-owned", nil, 0, "A-ok"},
		{"redirect to external host", "/to-external", ErrOutOfScope, 0, ""},
		{"redirect to lookalike", "/to-lookalike", ErrOutOfScope, 0, ""},
		{"redirect to excluded host", "/to-excluded", ErrExcluded, 0, ""},
		{"redirect to unregistered private ip literal", "/to-ip", ErrOutOfScope, 0, ""},
		{"redirect to metadata", "/to-metadata", ErrOutOfScope, 0, ""},
		{"redirect to ftp", "/to-ftp", errAny, 0, ""},
		{"redirect loop capped", "/loop", ErrTooManyRedirects, 0, ""},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			e.hits["B"].Store(0)
			resp, err := httpGet(t, cl, base+c.path)
			if resp != nil {
				defer func() { _ = resp.Body.Close() }()
			}
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected err %v", err)
				}
				b, _ := io.ReadAll(resp.Body)
				if string(b) != c.body {
					t.Fatalf("body=%q", b)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error, got status %d", resp.StatusCode)
			}
			if !errors.Is(c.wantErr, errAny) && !errors.Is(err, c.wantErr) {
				t.Fatalf("err=%v want %v", err, c.wantErr)
			}
			if errors.Is(c.wantErr, ErrOutOfScope) || errors.Is(c.wantErr, ErrExcluded) {
				if resp == nil || resp.StatusCode != http.StatusFound {
					t.Fatalf("refused redirect must hand back the 302 response, got %+v", resp)
				}
				if resp.Header.Get("Location") == "" {
					t.Fatal("redirect response should keep its Location header")
				}
			}
			if got := e.hits["B"].Load(); got != c.wantB {
				t.Fatalf("out-of-scope server received %d requests", got)
			}
		})
	}
}

func TestHTTPClientRedirectCap(t *testing.T) {
	e := setupHTTP(t)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer srv.Close()
	e.res.seq["app.example.com"] = [][]string{{"127.0.0.1"}}
	cl := e.g.HTTPClient(model.TierPassive, model.ScopeOwned, nil, WithMaxRedirects(2))
	resp, err := httpGet(t, cl, "http://app.example.com:"+portOf(t, srv.URL)+"/")
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("err=%v", err)
	}
	if n.Load() != 3 { // initial + 2 followed
		t.Fatalf("server saw %d requests, want 3", n.Load())
	}
	if def := e.g.HTTPClient(model.TierPassive, model.ScopeOwned, nil); def.CheckRedirect == nil {
		t.Fatal("default client must have CheckRedirect")
	}
}

func TestHTTPClientDialsUseGuard(t *testing.T) {
	e := setupHTTP(t)
	cl := e.g.HTTPClient(model.TierPassive, model.ScopeOwned, nil)

	// Excluded host: first hop refused at dial time, server never hit.
	e.hits["A"].Store(0)
	if resp, err := httpGet(t, cl, "http://secret.example.com:"+e.portA+"/ok"); !errors.Is(err, ErrExcluded) {
		t.Fatalf("excluded first hop: %v", err)
	} else if resp != nil {
		_ = resp.Body.Close()
	}
	// Literal private IP not registered (10.x): refused.
	if resp, err := httpGet(t, cl, "http://10.0.0.1/"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("literal private: %v", err)
	} else if resp != nil {
		_ = resp.Body.Close()
	}
	// Rebinding: second lookup returns 10.0.0.1.
	if resp, err := httpGet(t, cl, "http://rebind.example.com:"+e.portA+"/ok"); err != nil {
		t.Fatalf("first lookup is loopback-owned and fine: %v", err)
	} else {
		_ = resp.Body.Close()
	}
	if resp, err := httpGet(t, cl, "http://rebind.example.com:"+e.portA+"/ok"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("rebind must be refused: %v", err)
	} else if resp != nil {
		_ = resp.Body.Close()
	}
	if e.hits["A"].Load() != 1 {
		t.Fatalf("A hits=%d", e.hits["A"].Load())
	}
}

func TestHTTPClientIgnoresProxyEnv(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	e := setupHTTP(t)
	cl := e.g.HTTPClient(model.TierPassive, model.ScopeOwned, nil)
	tr, ok := cl.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type %T", cl.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("proxy must be disabled: it would bypass the dialer's destination vetting")
	}
	resp, err := httpGet(t, cl, "http://app.example.com:"+e.portA+"/ok")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func TestHTTPClientRefusesNonOwnedInitialHost(t *testing.T) {
	e := setupHTTP(t)
	// A bare request to a third-party (non-owned) name must never leave the
	// process, regardless of the asset class the caller claims.
	for _, class := range []model.ScopeClass{model.ScopeExternal, model.ScopeOwned} {
		cl := e.g.HTTPClient(model.TierPassive, class, nil)
		e.hits["A"].Store(0)
		resp, err := httpGet(t, cl, "http://external-app.test:"+e.portA+"/same")
		if err == nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, ErrOutOfScope) {
			t.Fatalf("class=%s: request to non-owned host must be refused, err=%v", class, err)
		}
		if got := e.hits["A"].Load(); got != 0 {
			t.Fatalf("class=%s: server was contacted %d times", class, got)
		}
	}
}

func TestHTTPClientTimeout(t *testing.T) {
	e := setupHTTP(t)
	cl := e.g.HTTPClient(model.TierPassive, model.ScopeOwned, nil)
	if cl.Timeout <= 0 || cl.Timeout > time.Minute {
		t.Fatalf("timeout %v", cl.Timeout)
	}
	cl2 := e.g.HTTPClient(model.TierPassive, model.ScopeOwned, nil, WithHTTPTimeout(3*time.Second))
	if cl2.Timeout != 3*time.Second {
		t.Fatalf("timeout %v", cl2.Timeout)
	}
}

// Real net.Dialer path: Control re-check backs up the pre-dial vetting.
func TestDefaultDialerControlRecheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "x") }))
	defer srv.Close()
	port := portOf(t, srv.URL)
	res := newFakeResolver(map[string][][]string{"app.example.com": {{"127.0.0.1"}}})
	g, _ := NewGuard(config.ScopeConfig{}, WithResolver(res), WithLogger(quietLogger()))
	g.SetZones([]string{"example.com"})
	// Loopback NOT owned: real dialer must refuse and never connect.
	_, err := g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "app.example.com:"+port)
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("err=%v", err)
	}
	g, _ = NewGuard(config.ScopeConfig{Include: []string{"127.0.0.1"}}, WithResolver(res), WithLogger(quietLogger()))
	g.SetZones([]string{"example.com"})
	c, err := g.Dialer(model.TierPassive, model.ScopeOwned, nil).DialContext(context.Background(), "tcp", "app.example.com:"+strconv.Itoa(mustAtoi(t, port)))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
