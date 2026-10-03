// Package intel is deckard's restricted client for third-party metadata
// services: RDAP registries, Shodan InternetDB and the Wayback Machine CDX API.
//
// Checks use it to ask about the operator's OWN domains and IPs. That is not
// probing an asset, so it does not go through the scope guard (which would
// refuse a registry's address), but it is not a general outbound path either:
//
//   - every request names a registered service (services.go) and the URL's host
//     must be on that service's allow-list: fixed hostnames, plus for RDAP the
//     registry hosts published in IANA's bootstrap file. Nothing in
//     configuration can add a host;
//   - https on port 443 only, at most three redirects, each re-checked against
//     the allow-list; proxies from the environment are ignored; TLS 1.2+ with
//     certificate verification;
//   - the client resolves the host itself, refuses loopback, private,
//     link-local, CGNAT, multicast, unspecified, reserved and cloud-metadata
//     addresses, and dials the address it checked, so DNS rebinding cannot
//     swap it between the check and the connection;
//   - bodies are capped (compressed and decompressed), every attempt has a
//     timeout, each service has a token-bucket rate limit, retries back off
//     with jitter and honour a bounded Retry-After, and answers are cached
//     (single-flight, so concurrent identical requests reach upstream once).
//
// Query strings and response bodies are never logged.
package intel

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// Errors returned by Client. Consumers treat all of them as "no answer":
// none of them is evidence about the asset.
var (
	// ErrDisabled: intel (or this service) is switched off in configuration.
	ErrDisabled = errors.New("intel: disabled")
	// ErrBlocked: the request was refused before any connection (host not on
	// the service's allow-list, non-https, a forbidden address, ...). It
	// indicates a bug in the caller or a misbehaving upstream redirect.
	ErrBlocked = errors.New("intel: request blocked")
	// ErrNotFound: the service answered 404/410.
	ErrNotFound = errors.New("intel: not found")
	// ErrRateLimited: no rate-limit token in time, or 429 after the retries.
	ErrRateLimited = errors.New("intel: rate limited")
	// ErrUnavailable: timeouts, transport errors or 5xx after the retries.
	ErrUnavailable = errors.New("intel: upstream unavailable")
	// ErrTooLarge: the (decompressed) body exceeds the service's size cap.
	ErrTooLarge = errors.New("intel: response exceeds size cap")
	// ErrUnsupported: no RDAP service is published for the domain's TLD.
	ErrUnsupported = errors.New("intel: no rdap service for this tld")
)

// errTooManyRedirects ends a redirect chain; retrying would loop again.
var errTooManyRedirects = fmt.Errorf("stopped after %d redirects", maxRedirects)

// Results recorded in deckard_intel_requests_total.
const (
	ResultOK          = "ok"
	ResultCached      = "cached"
	ResultNotFound    = "not_found"
	ResultRateLimited = "rate_limited"
	ResultError       = "error"
	ResultBlocked     = "blocked"
)

const (
	maxAttempts    = 3
	baseBackoff    = time.Second
	maxRetryAfter  = 30 * time.Second
	maxRedirects   = 3
	bootstrapTTL   = 24 * time.Hour
	bootstrapRetry = 5 * time.Minute
	projectURL     = "https://github.com/chainseer-xyz/deckard"
)

// Response is a successful (or not-found) answer.
type Response struct {
	Status int
	// Header holds only the caching-related response headers (Content-Type,
	// ETag, Last-Modified, Cache-Control, Expires, Age, Date).
	Header http.Header
	Body   []byte
	// Cached is true when the answer came from the client's cache (or was
	// shared with a concurrent identical request).
	Cached bool
}

// Recorder receives the client's metrics. Implementations must be safe for
// concurrent use.
type Recorder interface {
	// IntelRequest counts one Get (or bootstrap load) by result.
	IntelRequest(service, result string)
	// IntelDuration observes one upstream attempt.
	IntelDuration(service string, d time.Duration)
}

type noopRecorder struct{}

func (noopRecorder) IntelRequest(string, string)         {}
func (noopRecorder) IntelDuration(string, time.Duration) {}

// ServiceConfig overrides one service's defaults. Zero values keep the default.
type ServiceConfig struct {
	Disabled         bool
	RatePerSecond    float64
	Timeout          time.Duration
	CacheTTL         time.Duration
	NegativeCacheTTL time.Duration
	MaxBytes         int64
}

// Options configures a Client.
type Options struct {
	// Disabled turns every request into ErrDisabled (air-gapped deployments).
	Disabled bool
	// Version goes into the User-Agent.
	Version string
	// Contact (an e-mail address or URL) is appended to the User-Agent so
	// service operators can reach you.
	Contact  string
	Services map[string]ServiceConfig
	Logger   *slog.Logger
	Recorder Recorder
}

// seams are test hooks; production code never sets them.
type seams struct {
	// resolve returns host's addresses (default: the system resolver).
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// dial connects to an already-vetted ip:port.
	dial  func(ctx context.Context, network, addr string) (net.Conn, error)
	roots *x509.CertPool
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

type service struct {
	spec
	enabled  bool
	timeout  time.Duration
	maxBytes int64
	ttl      time.Duration
	negTTL   time.Duration
	limiter  *rate.Limiter
}

// budget bounds a whole fetch (every attempt and wait).
func (s *service) budget() time.Duration {
	return maxAttempts*s.timeout + (maxAttempts-1)*maxRetryAfter + 5*time.Second
}

// Client is the hardened metadata client. It is safe for concurrent use.
type Client struct {
	disabled bool
	ua       string
	log      *slog.Logger
	rec      Recorder
	svcs     map[string]*service
	hc       *http.Client
	cache    *ttlCache
	sf       singleflight.Group
	seams

	bmu        sync.Mutex
	boot       *Bootstrap
	bootAt     time.Time
	bootFailed time.Time
}

// New builds a client. Unknown service names in o.Services are an error.
func New(o Options) (*Client, error) { return newClient(o, seams{}) }

func newClient(o Options, s seams) (*Client, error) {
	if s.now == nil {
		s.now = time.Now
	}
	if s.sleep == nil {
		s.sleep = sleepCtx
	}
	if s.resolve == nil {
		s.resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if s.dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		s.dial = d.DialContext
	}
	for name := range o.Services {
		if DefaultRate(name) == 0 {
			return nil, fmt.Errorf("intel: unknown service %q (known: %s)", name, strings.Join(ServiceNames(), ", "))
		}
	}
	c := &Client{
		disabled: o.Disabled,
		ua:       userAgent(o.Version, o.Contact),
		log:      o.Logger,
		rec:      o.Recorder,
		svcs:     map[string]*service{},
		seams:    s,
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.rec == nil {
		c.rec = noopRecorder{}
	}
	c.cache = newTTLCache(defaultCacheEntries, func() time.Time { return c.now() })
	for _, sp := range registry {
		sc := o.Services[sp.name]
		sv := &service{spec: sp, enabled: !sc.Disabled, timeout: DefaultTimeout, maxBytes: DefaultMaxBytes,
			ttl: DefaultCacheTTL, negTTL: DefaultNegativeCacheTTL}
		r := sp.rate
		if sc.RatePerSecond > 0 {
			r = sc.RatePerSecond
		}
		if sc.Timeout > 0 {
			sv.timeout = sc.Timeout
		}
		if sc.MaxBytes > 0 {
			sv.maxBytes = sc.MaxBytes
		}
		if sc.CacheTTL > 0 {
			sv.ttl = sc.CacheTTL
		}
		if sc.NegativeCacheTTL > 0 {
			sv.negTTL = sc.NegativeCacheTTL
		}
		sv.limiter = rate.NewLimiter(rate.Limit(r), max(1, int(r)))
		c.svcs[sp.name] = sv
	}
	tr := &http.Transport{
		Proxy:                  nil, // never honour HTTP(S)_PROXY: the allow-list must see the real destination
		DialContext:            c.dialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: s.roots},
		TLSHandshakeTimeout:    10 * time.Second,
		DisableCompression:     true, // gzip is handled (and capped) in readBody
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	c.hc = &http.Client{Transport: tr, CheckRedirect: c.checkRedirect}
	return c, nil
}

func userAgent(version, contact string) string {
	if version == "" {
		version = "dev"
	}
	if contact = strings.TrimSpace(contact); contact != "" {
		return fmt.Sprintf("deckard/%s (+%s; %s)", version, projectURL, contact)
	}
	return fmt.Sprintf("deckard/%s (+%s)", version, projectURL)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type ctxKey struct{}

func withService(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, ctxKey{}, name)
}

func (c *Client) serviceFrom(ctx context.Context) *service {
	name, _ := ctx.Value(ctxKey{}).(string)
	return c.svcs[name]
}

// outcome is the result of one fetch, shared by single-flight followers.
type outcome struct {
	resp   Response
	boot   *Bootstrap
	result string
	err    error
}

// Get fetches rawURL for service. 2xx answers return the response; 404/410
// return ErrNotFound (both are cached). Everything else is an error matching
// one of the package's sentinel errors where one applies.
func (c *Client) Get(ctx context.Context, service, rawURL string) (Response, error) {
	if c == nil || c.disabled {
		return Response{}, ErrDisabled
	}
	svc := c.svcs[service]
	if svc == nil {
		err := fmt.Errorf("%w: unknown service %q", ErrBlocked, service)
		c.finish(service, nil, outcome{result: ResultBlocked, err: err})
		return Response{}, err
	}
	if !svc.enabled {
		return Response{}, ErrDisabled
	}
	u, err := c.vet(ctx, svc, rawURL)
	if err != nil {
		res := ResultError
		if errors.Is(err, ErrBlocked) {
			res = ResultBlocked
		}
		c.finish(service, u, outcome{result: res, err: err})
		return Response{}, err
	}
	key := svc.name + " " + u.String()
	if e, ok := c.cache.get(key); ok {
		o := outcome{resp: e.resp, result: ResultCached}
		if e.notFound {
			o.err = ErrNotFound
		}
		c.finish(service, u, o)
		return copyResponse(o.resp, true), o.err
	}
	o, shared := c.flight(ctx, svc, key, func(fctx context.Context) outcome {
		o := c.do(fctx, svc, u)
		switch o.result {
		case ResultOK:
			c.cache.put(key, cacheEntry{resp: o.resp}, svc.ttl)
		case ResultNotFound:
			c.cache.put(key, cacheEntry{resp: o.resp, notFound: true}, svc.negTTL)
		}
		return o
	})
	if shared && (o.result == ResultOK || o.result == ResultNotFound) {
		o.result = ResultCached
	}
	c.finish(service, u, o)
	return copyResponse(o.resp, shared), o.err
}

// flight runs fn once per key across concurrent callers. fn gets a context
// detached from the caller's cancellation (but bounded by the service budget)
// so one impatient caller cannot fail everyone sharing the call; each caller
// still stops waiting when its own ctx ends. shared is true for callers that
// did not run fn themselves.
func (c *Client) flight(ctx context.Context, svc *service, key string, fn func(context.Context) outcome) (outcome, bool) {
	ran := false
	ch := c.sf.DoChan(key, func() (any, error) {
		ran = true
		fctx, cancel := context.WithTimeout(withService(context.WithoutCancel(ctx), svc.name), svc.budget())
		defer cancel()
		return fn(fctx), nil
	})
	select {
	case <-ctx.Done():
		return outcome{result: ResultError, err: fmt.Errorf("%w: %s: %w", ErrUnavailable, svc.name, ctx.Err())}, false
	case r := <-ch:
		return r.Val.(outcome), !ran
	}
}

func copyResponse(r Response, cached bool) Response {
	r.Body = slices.Clone(r.Body)
	r.Header = r.Header.Clone()
	r.Cached = cached
	return r
}

// finish counts and logs one request: Debug normally, Warn when blocked.
func (c *Client) finish(service string, u *url.URL, o outcome) {
	c.rec.IntelRequest(service, o.result)
	attrs := []any{"service", service, "result", o.result}
	if u != nil {
		// Host and path only: query strings may carry lookup parameters.
		attrs = append(attrs, "host", u.Hostname(), "path", u.EscapedPath())
	}
	if o.resp.Status != 0 {
		attrs = append(attrs, "status", o.resp.Status)
	}
	if o.err != nil {
		attrs = append(attrs, "err", o.err.Error())
	}
	if o.result == ResultBlocked {
		c.log.Warn("intel: request blocked (a bug or a misbehaving upstream redirect)", attrs...)
		return
	}
	c.log.Debug("intel request", attrs...)
}

// vet validates rawURL for svc before anything touches the network (beyond
// loading the RDAP bootstrap, itself an allow-listed request). It returns the
// canonical URL.
func (c *Client) vet(ctx context.Context, svc *service, rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		// The parse error would echo the URL (and its query string).
		return nil, fmt.Errorf("%w: unparseable url", ErrBlocked)
	}
	if err := checkURLShape(u); err != nil {
		return u, err
	}
	host := strings.ToLower(u.Hostname())
	if !slices.Contains(svc.hosts, host) {
		if !svc.bootstrap {
			return u, fmt.Errorf("%w: host %q is not allowed for service %s", ErrBlocked, host, svc.name)
		}
		b, err := c.bootstrap(ctx, svc)
		if err != nil {
			return u, err
		}
		if !b.allows(host) {
			return u, fmt.Errorf("%w: host %q is not an rdap server in the iana bootstrap", ErrBlocked, host)
		}
	}
	cu := *u
	cu.Host, cu.Fragment, cu.RawFragment = host, "", ""
	return &cu, nil
}

func checkURLShape(u *url.URL) error {
	host := u.Hostname()
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%w: scheme %q is not https", ErrBlocked, u.Scheme)
	case u.User != nil:
		return fmt.Errorf("%w: url carries userinfo", ErrBlocked)
	case u.Port() != "" && u.Port() != "443":
		return fmt.Errorf("%w: port %s is not 443", ErrBlocked, u.Port())
	case host == "":
		return fmt.Errorf("%w: url has no host", ErrBlocked)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return fmt.Errorf("%w: ip literal hosts are not allowed", ErrBlocked)
	}
	return nil
}

// hostAllowedNow checks host against svc's allow-list using the bootstrap
// already loaded (redirects and dials never trigger a bootstrap load).
func (c *Client) hostAllowedNow(svc *service, host string) bool {
	host = strings.ToLower(host)
	if slices.Contains(svc.hosts, host) {
		return true
	}
	if !svc.bootstrap {
		return false
	}
	c.bmu.Lock()
	defer c.bmu.Unlock()
	return c.boot.allows(host)
}

// checkRedirect re-applies the allow-list to every redirect hop.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return errTooManyRedirects
	}
	svc := c.serviceFrom(req.Context())
	if svc == nil {
		return fmt.Errorf("%w: redirect outside a service request", ErrBlocked)
	}
	if err := checkURLShape(req.URL); err != nil {
		return fmt.Errorf("redirect: %w", err)
	}
	if !c.hostAllowedNow(svc, req.URL.Hostname()) {
		return fmt.Errorf("%w: redirect to host %q is not allowed for service %s", ErrBlocked, strings.ToLower(req.URL.Hostname()), svc.name)
	}
	return nil
}

// dialContext is the only way the client opens a connection: it re-checks the
// host and port, resolves the host itself, refuses the whole host if any
// address is not public unicast, and dials the vetted IP literal.
func (c *Client) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: bad dial address", ErrBlocked)
	}
	svc := c.serviceFrom(ctx)
	switch {
	case svc == nil:
		return nil, fmt.Errorf("%w: dial outside a service request", ErrBlocked)
	case port != "443":
		return nil, fmt.Errorf("%w: port %s is not 443", ErrBlocked, port)
	case !c.hostAllowedNow(svc, host):
		return nil, fmt.Errorf("%w: dial to host %q is not allowed for service %s", ErrBlocked, host, svc.name)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, fmt.Errorf("%w: ip literal hosts are not allowed", ErrBlocked)
	}
	addrs, err := c.resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}
	for _, a := range addrs {
		if why := blockedReason(a); why != "" {
			return nil, fmt.Errorf("%w: %s resolves to %s (%s)", ErrBlocked, host, a.Unmap(), why)
		}
	}
	var lastErr error
	for _, a := range addrs {
		conn, err := c.dial(ctx, network, netip.AddrPortFrom(a.Unmap(), 443).String())
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// do performs the request with rate limiting and retries.
func (c *Client) do(ctx context.Context, svc *service, u *url.URL) outcome {
	for attempt := 1; ; attempt++ {
		if err := svc.limiter.Wait(ctx); err != nil {
			return outcome{result: ResultRateLimited, err: fmt.Errorf("%w: %s: no token before the deadline", ErrRateLimited, svc.name)}
		}
		start := c.now()
		resp, retryAfter, err := c.once(ctx, svc, u)
		c.rec.IntelDuration(svc.name, c.now().Sub(start))
		var o outcome
		switch {
		case errors.Is(err, ErrBlocked):
			return outcome{result: ResultBlocked, err: err}
		case errors.Is(err, ErrTooLarge):
			return outcome{result: ResultError, err: err}
		case err != nil:
			o = outcome{result: ResultError, err: fmt.Errorf("%w: %s: %w", ErrUnavailable, svc.name, err)}
			if !retryable(err) {
				return o
			}
		case resp.Status >= 200 && resp.Status < 300:
			return outcome{resp: resp, result: ResultOK}
		case resp.Status == http.StatusNotFound || resp.Status == http.StatusGone:
			return outcome{resp: resp, result: ResultNotFound, err: ErrNotFound}
		case resp.Status == http.StatusTooManyRequests:
			o = outcome{resp: resp, result: ResultRateLimited, err: fmt.Errorf("%w: %s: http 429", ErrRateLimited, svc.name)}
		case resp.Status >= 500:
			o = outcome{resp: resp, result: ResultError, err: fmt.Errorf("%w: %s: http %d", ErrUnavailable, svc.name, resp.Status)}
		default:
			return outcome{resp: resp, result: ResultError, err: fmt.Errorf("intel: %s: http %d", svc.name, resp.Status)}
		}
		if attempt >= maxAttempts || ctx.Err() != nil {
			return o
		}
		wait := backoff(attempt)
		if retryAfter > 0 {
			if retryAfter > maxRetryAfter {
				return o // the service asked for longer than we are willing to hold a check
			}
			wait = max(wait, retryAfter)
		}
		if err := c.sleep(ctx, wait); err != nil {
			return o
		}
	}
}

// backoff is exponential with jitter: [d/2, d) for d = base * 2^(attempt-1).
func backoff(attempt int) time.Duration {
	d := baseBackoff << (attempt - 1)
	return d/2 + time.Duration(rand.Int64N(int64(d/2))) // #nosec G404 -- retry jitter, not a secret
}

// retryable reports whether a transport error may succeed on retry.
// Certificate problems and redirect loops will not.
func retryable(err error) bool {
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	return !errors.Is(err, errTooManyRedirects) && !errors.As(err, &cv) && !errors.As(err, &ua) && !errors.As(err, &he) && !errors.As(err, &ci)
}

// once performs one attempt. The returned duration is the server's
// Retry-After (0 when absent or unparseable).
func (c *Client) once(ctx context.Context, svc *service, u *url.URL) (Response, time.Duration, error) {
	actx, cancel := context.WithTimeout(withService(ctx, svc.name), svc.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Response{}, 0, fmt.Errorf("%w: cannot build request", ErrBlocked)
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/rdap+json, application/json;q=0.9, */*;q=0.1")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := c.hc.Do(req) // #nosec G704 -- host vetted against the service allow-list; redirects and dials re-check it
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // *url.Error would echo the full URL, query string included
		}
		return Response{}, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	out := Response{Status: resp.StatusCode, Header: keepHeaders(resp.Header)}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) // let the connection be reused
		return out, retryAfter(resp.Header.Get("Retry-After"), c.now()), nil
	}
	if resp.ContentLength > svc.maxBytes {
		return out, 0, fmt.Errorf("%w (%d > %d bytes)", ErrTooLarge, resp.ContentLength, svc.maxBytes)
	}
	body, err := readBody(resp, svc.maxBytes)
	if err != nil {
		return out, 0, err
	}
	out.Body = body
	return out, 0, nil
}

// readBody reads at most limit bytes of the (possibly gzip-encoded) body; the
// cap applies to the compressed stream and again to the decompressed one, so a
// compression bomb stops at limit.
func readBody(resp *http.Response, limit int64) ([]byte, error) {
	r := io.LimitReader(resp.Body, limit+1)
	switch enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer func() { _ = zr.Close() }()
		r = zr
	default:
		return nil, fmt.Errorf("unsupported content-encoding %q", enc)
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w (> %d bytes)", ErrTooLarge, limit)
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

var keptHeaders = []string{"Content-Type", "ETag", "Last-Modified", "Cache-Control", "Expires", "Age", "Date"}

func keepHeaders(h http.Header) http.Header {
	out := http.Header{}
	for _, k := range keptHeaders {
		if v := h.Values(k); len(v) > 0 {
			out[http.CanonicalHeaderKey(k)] = slices.Clone(v)
		}
	}
	return out
}

// retryAfter parses a Retry-After value (seconds or an HTTP date).
func retryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil {
		if s <= 0 {
			return 0
		}
		return time.Duration(min(s, 86400)) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// RDAPBase returns the RDAP base URL (ending in "/") of the registry serving
// domain's TLD, from IANA's bootstrap file (loaded on first use, refreshed
// every 24h). It returns ErrUnsupported when the TLD has no RDAP service.
func (c *Client) RDAPBase(ctx context.Context, domain string) (string, error) {
	if c == nil || c.disabled {
		return "", ErrDisabled
	}
	svc := c.svcs[ServiceRDAP]
	if !svc.enabled {
		return "", ErrDisabled
	}
	b, err := c.bootstrap(ctx, svc)
	if err != nil {
		return "", err
	}
	base, ok := b.Base(domain)
	if !ok {
		return "", ErrUnsupported
	}
	return base, nil
}

// bootstrap returns the current RDAP bootstrap, loading it when absent or
// older than 24h. A failed refresh keeps serving the previous copy and is not
// retried for bootstrapRetry.
func (c *Client) bootstrap(ctx context.Context, svc *service) (*Bootstrap, error) {
	c.bmu.Lock()
	cur, at, failed := c.boot, c.bootAt, c.bootFailed
	c.bmu.Unlock()
	now := c.now()
	if cur != nil && now.Sub(at) < bootstrapTTL {
		return cur, nil
	}
	if !failed.IsZero() && now.Sub(failed) < bootstrapRetry {
		if cur != nil {
			return cur, nil
		}
		return nil, fmt.Errorf("%w: rdap bootstrap could not be loaded recently; retrying later", ErrUnavailable)
	}
	o, _ := c.flight(ctx, svc, "\x00rdap-bootstrap", c.loadBootstrap)
	if o.err != nil {
		if cur != nil {
			return cur, nil
		}
		return nil, o.err
	}
	return o.boot, nil
}

func (c *Client) loadBootstrap(ctx context.Context) outcome {
	svc := c.svcs[ServiceRDAP]
	u, _ := url.Parse(BootstrapURL)
	o := c.do(ctx, svc, u)
	if o.err == nil {
		b, err := ParseBootstrap(o.resp.Body)
		if err != nil {
			o = outcome{result: ResultError, err: fmt.Errorf("%w: %w", ErrUnavailable, err)}
		} else {
			o.boot = b
		}
	} else if o.result == ResultNotFound {
		o = outcome{resp: o.resp, result: ResultError, err: fmt.Errorf("%w: rdap bootstrap: http %d", ErrUnavailable, o.resp.Status)}
	}
	c.bmu.Lock()
	if o.boot != nil {
		c.boot, c.bootAt, c.bootFailed = o.boot, c.now(), time.Time{}
	} else {
		c.bootFailed = c.now()
	}
	c.bmu.Unlock()
	c.finish(svc.name, u, o)
	return o
}
