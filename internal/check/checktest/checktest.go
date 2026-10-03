// Package checktest provides fakes and builders for testing checks without a
// network: a scripted Resolver (including NXDOMAIN), a routing Dialer, an HTTP
// client that routes hostnames to httptest servers, and a Target builder.
package checktest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func norm(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

// NXDomain is the error a real resolver returns for a nonexistent name.
func NXDomain(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// Resolver is a scripted check.Resolver. Names are matched case-insensitively
// without trailing dots. Unscripted names answer NXDOMAIN, except LookupCNAME
// which (like net.Resolver) returns the queried name itself with a trailing dot
// when the name has no CNAME but exists.
type Resolver struct {
	Hosts  map[string][]string
	CNAMEs map[string]string
	TXTs   map[string][]string
	NSs    map[string][]string
	// Errs forces a non-NXDOMAIN error for every lookup of that name.
	Errs map[string]error

	mu    sync.Mutex
	Calls []string
}

func (r *Resolver) record(kind, name string) {
	r.mu.Lock()
	r.Calls = append(r.Calls, kind+" "+norm(name))
	r.mu.Unlock()
}

func (r *Resolver) fail(name string) error {
	if err, ok := r.Errs[norm(name)]; ok {
		return err
	}
	return nil
}

func (r *Resolver) LookupHost(_ context.Context, host string) ([]string, error) {
	r.record("host", host)
	if err := r.fail(host); err != nil {
		return nil, err
	}
	if v, ok := r.Hosts[norm(host)]; ok {
		return v, nil
	}
	return nil, NXDomain(host)
}

func (r *Resolver) LookupCNAME(_ context.Context, host string) (string, error) {
	r.record("cname", host)
	if err := r.fail(host); err != nil {
		return "", err
	}
	h := norm(host)
	if v, ok := r.CNAMEs[h]; ok {
		return norm(v) + ".", nil
	}
	if _, ok := r.Hosts[h]; ok {
		return h + ".", nil
	}
	if _, ok := r.TXTs[h]; ok {
		return h + ".", nil
	}
	return "", NXDomain(host)
}

func (r *Resolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	r.record("txt", host)
	if err := r.fail(host); err != nil {
		return nil, err
	}
	if v, ok := r.TXTs[norm(host)]; ok {
		return v, nil
	}
	return nil, NXDomain(host)
}

func (r *Resolver) LookupNS(_ context.Context, host string) ([]string, error) {
	r.record("ns", host)
	if err := r.fail(host); err != nil {
		return nil, err
	}
	if v, ok := r.NSs[norm(host)]; ok {
		return v, nil
	}
	return nil, NXDomain(host)
}

// Dialer routes "host:port" addresses to real local listeners.
type Dialer struct {
	Routes map[string]string // requested addr -> local addr
	mu     sync.Mutex
	Dialed []string
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.Dialed = append(d.Dialed, address)
	d.mu.Unlock()
	to, ok := d.Routes[address]
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("connection refused (no route for %s)", address)}
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, to)
}

// HostClient returns an http.Client that sends requests for "host:port" (port
// defaulting to 80/443 by scheme) to the routed httptest server and trusts any
// certificate. Unrouted hosts fail to connect. Redirects are followed.
func HostClient(routes map[string]*httptest.Server) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			srv, ok := routes[addr]
			if !ok {
				return nil, fmt.Errorf("no route for %s", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		},
		TLSClientConfig:   tlsInsecure(),
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr}
}

// Option customises NewTarget.
type Option func(*check.Target)

// WithResolver sets the target resolver.
func WithResolver(r check.Resolver) Option { return func(t *check.Target) { t.Resolver = r } }

// WithDialer sets the target dialer.
func WithDialer(d check.Dialer) Option { return func(t *check.Target) { t.Dialer = d } }

// WithHTTP sets the target HTTP client.
func WithHTTP(c *http.Client) Option { return func(t *check.Target) { t.HTTP = c } }

// WithIntel sets the third-party metadata client.
func WithIntel(i check.Intel) Option { return func(t *check.Target) { t.Intel = i } }

// WithConfig sets per-check config.
func WithConfig(c map[string]any) Option { return func(t *check.Target) { t.Config = c } }

// WithNeighbours sets graph neighbours.
func WithNeighbours(n ...check.Neighbour) Option {
	return func(t *check.Target) { t.Neighbours = n }
}

// Hostname builds an owned hostname asset in zone.
func Hostname(name, zone string) model.Asset {
	return model.Asset{Kind: model.KindHostname, Key: name, Zone: zone, Scope: model.ScopeOwned}
}

// NewTarget builds a Target for a with an empty Resolver by default.
func NewTarget(a model.Asset, opts ...Option) check.Target {
	t := check.Target{Asset: a, Resolver: &Resolver{}}
	for _, o := range opts {
		o(&t)
	}
	return t
}
