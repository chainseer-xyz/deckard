// Package assessment defines the owned-target network boundary for explicit
// assessments. It does not sandbox subprocesses: runners must separately deny
// direct egress and route all supported traffic through this boundary.
package assessment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

// ErrDenied means an assessment did not completely observe its targets. A
// caller must not reconcile absent findings after any policy error.
var ErrDenied = errors.New("assessment policy denied")

// Limits bounds one assessment session. Byte limits count the cumulative
// request bodies/headers and response bodies/headers across the session, not each URL.
// All fields are mandatory; zero never means unlimited.
type Limits struct {
	MaxRequests      int
	MaxRequestBytes  int64
	MaxResponseBytes int64
	Timeout          time.Duration
}

type policyOptions struct {
	roots   *x509.CertPool
	refresh func(context.Context) error
}

// PolicyOption configures trust and persisted ownership verification.
type PolicyOption func(*policyOptions)

// WithOwnershipRefresh reloads authoritative ownership before initial target
// verification and each request authorization. An unavailable ledger refuses
// the session; callback errors never expose database details to scanners.
func WithOwnershipRefresh(refresh func(context.Context) error) PolicyOption {
	return func(options *policyOptions) { options.refresh = refresh }
}

// WithRootCAs supplies an explicit public trust bundle for private endpoints.
// Construction clones the pool; callers cannot later change session trust.
func WithRootCAs(roots *x509.CertPool) PolicyOption {
	return func(options *policyOptions) {
		if roots != nil {
			options.roots = roots.Clone()
		}
	}
}

// Policy permits only explicitly listed HTTP(S) origins and live owned
// destinations. A refusal is terminal for the session.
type Policy struct {
	guard         *scope.Guard
	origins       map[string]struct{}
	limits        Limits
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	err           error
	requests      int
	requestBytes  int64
	responseBytes int64
	client        *http.Client
	gate          chan struct{}
	refresh       func(context.Context) error
}

// NewPolicy verifies every explicit origin before creating a bounded session.
// Targets are origins, not crawl roots: paths, credentials, query strings and
// fragments are refused. The guard re-verifies ownership during later I/O.
func NewPolicy(ctx context.Context, guard *scope.Guard, targets []string, limits Limits, options ...PolicyOption) (*Policy, error) {
	if guard == nil || len(targets) == 0 || len(targets) > 128 {
		return nil, fmt.Errorf("%w: missing guard or invalid target count", ErrDenied)
	}
	if limits.MaxRequests < 1 || limits.MaxRequests > 10000 || limits.MaxRequestBytes < 1 || limits.MaxRequestBytes > 64<<20 ||
		limits.MaxResponseBytes < 1 || limits.MaxResponseBytes > 64<<20 || limits.Timeout <= 0 || limits.Timeout > time.Hour {
		return nil, fmt.Errorf("%w: invalid assessment limits", ErrDenied)
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	settings := policyOptions{}
	for _, option := range options {
		option(&settings)
	}
	p := &Policy{guard: guard, limits: limits, origins: make(map[string]struct{}), ctx: ctx, cancel: cancel, gate: make(chan struct{}, 1), refresh: settings.refresh}
	if p.refresh != nil && p.refresh(ctx) != nil {
		return nil, p.fail("ownership refresh unavailable")
	}
	for _, target := range targets {
		u, origin, err := normalizeURL(target)
		if err != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery {
			cancel()
			return nil, fmt.Errorf("%w: target must be an HTTP(S) origin", ErrDenied)
		}
		if !guard.VerifyOwnedTarget(ctx, u.Hostname()) {
			cancel()
			return nil, fmt.Errorf("%w: target is not fully owned", ErrDenied)
		}
		p.origins[origin] = struct{}{}
	}
	p.client = guard.HTTPClient(model.TierActive, model.ScopeOwned, nil, scope.WithHTTPTimeout(limits.Timeout))
	transport := p.client.Transport.(*http.Transport)
	transport.MaxResponseHeaderBytes = min(limits.MaxResponseBytes, 64<<10)
	// HTTP/2 may retry REFUSED_STREAM/GOAWAY internally without re-entering
	// policyTransport's request counter. Use single-hop HTTP/1.1 only.
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	transport.TLSClientConfig = &tls.Config{RootCAs: settings.roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	p.client.Transport = &policyTransport{policy: p, base: p.client.Transport}
	// Preserve scanner-visible redirects. Every scanner-followed request must
	// re-enter the proxy and consume its own authorization and request budget.
	p.client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return p, nil
}

// AuthorizeURL permits paths and queries on an explicit origin, after a fresh
// ownership check. It is not a socket boundary; use Do for guarded HTTP I/O.
// Errors intentionally exclude URLs, which may contain secret query values.
func (p *Policy) AuthorizeURL(ctx context.Context, raw string) (*url.URL, error) {
	if ctx.Err() != nil {
		return nil, p.fail("authorization context canceled")
	}
	if err := p.Err(); err != nil {
		return nil, err
	}
	u, origin, err := normalizeURL(raw)
	if err != nil {
		return nil, p.fail("invalid HTTP(S) URL")
	}
	if _, ok := p.origins[origin]; !ok {
		return nil, p.fail("origin is not an explicit target")
	}
	lookupCtx, cancel := context.WithCancel(p.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	if p.refresh != nil && p.refresh(lookupCtx) != nil {
		return nil, p.fail("ownership refresh unavailable")
	}
	if !p.guard.VerifyOwnedTarget(lookupCtx, u.Hostname()) {
		return nil, p.fail("destination is no longer fully owned")
	}
	if ctx.Err() != nil {
		return nil, p.fail("authorization context canceled")
	}
	if err := p.Err(); err != nil {
		return nil, err
	}
	return u, nil
}

// Err reports the first refusal or session cancellation. Any non-nil value
// means the assessment is incomplete, even when a scanner exits successfully.
func (p *Policy) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	return p.ctx.Err()
}

// Close cancels pending I/O. Inspect Err before closing a successful session.
func (p *Policy) Close() { p.cancel() }

func (p *Policy) fail(reason string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		p.err = fmt.Errorf("%w: %s", ErrDenied, reason)
		p.cancel()
	}
	return p.err
}

func normalizeURL(raw string) (*url.URL, string, error) {
	if len(raw) > 4096 || strings.ContainsAny(raw, "\\\r\n\t") {
		return nil, "", ErrDenied
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") || u.Hostname() == "" {
		return nil, "", ErrDenied
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "", ErrDenied
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return nil, "", ErrDenied
		}
		host = address.Unmap().String()
	} else {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || len(host) > 253 {
			return nil, "", ErrDenied
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, "", ErrDenied
			}
			for _, character := range label {
				if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
					return nil, "", ErrDenied
				}
			}
		}
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return nil, "", ErrDenied
	}
	u.Host = net.JoinHostPort(host, strconv.FormatUint(number, 10))
	return u, u.Scheme + "://" + u.Host, nil
}
