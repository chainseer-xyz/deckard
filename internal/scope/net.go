package scope

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// specialPrefixes are destinations that are never legitimate probe targets
// unless the operator explicitly registered them as owned: loopback, private,
// link-local (incl. cloud metadata 169.254.169.254), CGNAT (Alibaba metadata
// 100.100.100.200), documentation, benchmarking, multicast, reserved, NAT64,
// 6to4, Teredo, ULA (fd00:ec2::254 AWS IPv6 metadata).
var specialPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32",
	"2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func isSpecial(ip netip.Addr) bool {
	ip = normAddr(ip)
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
		ip.IsUnspecified() || inAny(specialPrefixes, ip)
}

// isAnomalous reports whether ip is a destination that always points at a
// misconfiguration, DNS rebinding or an attack when it is not explicitly
// owned: loopback, link-local (cloud metadata), multicast, unspecified,
// reserved, and the transition forms that can embed them (the never-ownable
// ranges). Private ranges (RFC1918, ULA, CGNAT) are special too, but
// split-horizon DNS returns them routinely, so they are not anomalous.
func isAnomalous(ip netip.Addr) bool {
	ip = normAddr(ip)
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() ||
		inAny(neverOwnedPrefixes, ip)
}

// stdResolver adapts *net.Resolver to check.Resolver.
type stdResolver struct{ r *net.Resolver }

func (s stdResolver) LookupHost(ctx context.Context, h string) ([]string, error) {
	return s.r.LookupHost(ctx, h)
}
func (s stdResolver) LookupCNAME(ctx context.Context, h string) (string, error) {
	return s.r.LookupCNAME(ctx, h)
}
func (s stdResolver) LookupTXT(ctx context.Context, h string) ([]string, error) {
	return s.r.LookupTXT(ctx, h)
}
func (s stdResolver) LookupNS(ctx context.Context, h string) ([]string, error) {
	ns, err := s.r.LookupNS(ctx, h)
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		out = append(out, n.Host)
	}
	return out, err
}

// classRefusal turns a class that Allowed rejects into the right error.
func (g *Guard) classRefusal(op string, tier model.Tier, target string, class model.ScopeClass, why string) error {
	if class == model.ScopeExcluded {
		return g.refuse(ErrExcluded, op, tier, target, class, "asset is excluded")
	}
	return g.refuse(ErrOutOfScope, op, tier, target, class, why)
}

// vetIP decides whether the resolved/literal destination ip may be connected
// to. viaHostname is true when the connection was requested by (allowed)
// hostname; IP-based probing is only ever allowed for owned IPs.
func (g *Guard) vetIP(op string, tier model.Tier, target string, ip netip.Addr, viaHostname bool) error {
	ip = normAddr(ip)
	class := g.classifyIP(ip)
	switch {
	case class == model.ScopeExcluded:
		return g.refuse(ErrExcluded, op, tier, target+" -> "+ip.String(), class, "destination IP is excluded")
	case class == model.ScopeOwned:
		if !Allowed(tier, class) {
			return g.refuse(ErrOutOfScope, op, tier, target+" -> "+ip.String(), class, "tier not permitted")
		}
		return nil
	case isAnomalous(ip):
		return g.refuseAnomaly(ErrOutOfScope, op, tier, target+" -> "+ip.String(), class, "loopback/link-local/metadata or reserved destination is not owned")
	case isSpecial(ip):
		// Private ranges are routine with split-horizon DNS: throttled.
		return g.refuse(ErrOutOfScope, op, tier, target+" -> "+ip.String(), class, "private destination is not owned")
	case !viaHostname:
		return g.refuse(ErrOutOfScope, op, tier, target, class, "IP-based probing is only allowed for owned IPs")
	case !Allowed(tier, class):
		return g.refuse(ErrOutOfScope, op, tier, target+" -> "+ip.String(), class, "tier requires an owned destination IP")
	}
	return nil
}

// Dialer returns a check.Dialer for probing an asset of class assetClass at
// the given tier. Every DialContext:
//   - requires Allowed(tier, assetClass);
//   - for a hostname: classifies the name, resolves it, vets EVERY resolved IP
//     (all-or-nothing, defending against rebinding and mixed answers) and then
//     dials a vetted IP literal, never the name, so a second lookup cannot
//     change the destination;
//   - for an IP literal: requires an owned IP;
//   - refuses excluded, private, loopback, link-local and metadata destinations
//     unless explicitly owned.
//
// rate may be nil.
func (g *Guard) Dialer(tier model.Tier, assetClass model.ScopeClass, rate RateLimiter) check.Dialer {
	d := &guardedDialer{g: g, tier: tier, class: assetClass, rate: rate, base: g.base}
	if d.base == nil {
		d.base = &net.Dialer{
			Timeout: 10 * time.Second,
			// Last line of defence: re-check the socket's real remote address.
			Control: func(_, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				ip, ok := parseIP(host)
				if !ok {
					return fmt.Errorf("scope: control: bad address %q", address)
				}
				if class := g.classifyIP(ip); class == model.ScopeExcluded {
					return g.refuseAnomaly(ErrExcluded, "dial", tier, address, class, "control: destination IP is excluded")
				} else if class != model.ScopeOwned && isSpecial(ip) {
					return g.refuseAnomaly(ErrOutOfScope, "dial", tier, address, class, "control: special-purpose destination")
				}
				return nil
			},
		}
	}
	return d
}

type guardedDialer struct {
	g     *Guard
	tier  model.Tier
	class model.ScopeClass
	rate  RateLimiter
	base  check.Dialer
}

func (d *guardedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address, 0)
}

// DialTimeout is DialContext with timeout bounding only the lookup and the
// connection attempt, not the wait for a rate-limit token (check.TimeoutDialer).
func (d *guardedDialer) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	return d.dial(ctx, network, address, timeout)
}

func (d *guardedDialer) dial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	g := d.g
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return nil, g.refuseAnomaly(ErrOutOfScope, "dial", d.tier, address+" ("+strconv.Quote(network)+")", d.class, "unsupported network")
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("scope: dial %q: %w", address, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("scope: dial %q: invalid port", address)
	}
	if !Allowed(d.tier, d.class) {
		return nil, g.classRefusal("dial", d.tier, address, d.class, "tier not permitted for asset class")
	}

	if ip, ok := parseIP(host); ok {
		if err := g.vetIP("dial", d.tier, address, ip, false); err != nil {
			return nil, err
		}
		if err := d.wait(ctx, ip.String()); err != nil {
			return nil, err
		}
		ctx, cancel := withTimeout(ctx, timeout)
		defer cancel()
		return d.base.DialContext(ctx, network, net.JoinHostPort(ip.String(), portStr))
	}

	name, ok := normHost(host)
	if !ok {
		return nil, fmt.Errorf("scope: dial %q: invalid hostname", address)
	}
	hostClass := g.classifyName(name)
	// Hostname-based probing is only ever done through a name the operator
	// owns. A third-party name (e.g. a CNAME target) must never be dialled
	// directly, even passively: it is fingerprinted by requesting the owned
	// name that points at it.
	if hostClass != model.ScopeOwned || !Allowed(d.tier, hostClass) {
		return nil, g.classRefusal("dial", d.tier, address, hostClass, "hostname must be owned")
	}
	if err := d.wait(ctx, name); err != nil {
		return nil, err
	}
	ctx, cancel := withTimeout(ctx, timeout)
	defer cancel()
	addrs, err := g.resolver.LookupHost(ctx, name)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	for _, a := range addrs {
		ip, ok := parseIP(a)
		if !ok {
			return nil, g.refuseAnomaly(ErrOutOfScope, "dial", d.tier, address+" -> "+strconv.Quote(a), hostClass, "resolver returned an unparseable address")
		}
		if err := g.vetIP("dial", d.tier, address, ip, true); err != nil {
			return nil, err // all-or-nothing: one bad answer poisons the lookup
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: name, IsNotFound: true}
	}
	var errs []error
	for _, ip := range ips {
		conn, err := d.base.DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

func (d *guardedDialer) wait(ctx context.Context, host string) error {
	if d.rate == nil {
		return nil
	}
	if err := d.rate.Wait(ctx, host); err != nil {
		return fmt.Errorf("%w: %w", check.ErrRateLimited, err)
	}
	return nil
}

// withTimeout bounds ctx by timeout; zero leaves it unchanged.
func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// Resolver returns a scope-aware check.Resolver. Excluded names are never
// looked up; the asset class must permit the tier; IP answers that are
// excluded are dropped from LookupHost results. Names outside the owned zones
// (e.g. CNAME targets) may be looked up, since passive DNS fingerprinting of
// them is a core use.
func (g *Guard) Resolver(tier model.Tier, assetClass model.ScopeClass, rate RateLimiter) check.Resolver {
	return &guardedResolver{g: g, tier: tier, class: assetClass, rate: rate}
}

type guardedResolver struct {
	g     *Guard
	tier  model.Tier
	class model.ScopeClass
	rate  RateLimiter
}

// gate validates host and returns the normalised name (or the IP literal).
func (r *guardedResolver) gate(ctx context.Context, op, host string) (string, error) {
	g := r.g
	if !Allowed(r.tier, r.class) {
		return "", g.classRefusal(op, r.tier, host, r.class, "tier not permitted for asset class")
	}
	if ip, ok := parseIP(host); ok {
		if c := g.classifyIP(ip); c == model.ScopeExcluded {
			return "", g.refuse(ErrExcluded, op, r.tier, host, c, "IP is excluded")
		}
		return ip.String(), nil
	}
	name, ok := normHost(host)
	if !ok {
		return "", fmt.Errorf("scope: %s %q: invalid hostname", op, host)
	}
	if c := g.classifyName(name); c == model.ScopeExcluded {
		return "", g.refuse(ErrExcluded, op, r.tier, name, c, "name is excluded")
	}
	if r.rate != nil {
		if err := r.rate.Wait(ctx, name); err != nil {
			return "", err
		}
	}
	return name, nil
}

func (r *guardedResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	name, err := r.gate(ctx, "resolve", host)
	if err != nil {
		return nil, err
	}
	if _, isIP := parseIP(name); isIP {
		return []string{name}, nil
	}
	addrs, err := r.g.resolver.LookupHost(ctx, name)
	if err != nil {
		return nil, err
	}
	out := addrs[:0:0]
	for _, a := range addrs {
		if ip, ok := parseIP(a); ok && r.g.classifyIP(ip) == model.ScopeExcluded {
			r.g.log.Warn("scope: dropping excluded IP from resolver answer",
				"host", name, "ip", ip.String(), "tier", string(r.tier))
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func (r *guardedResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	name, err := r.gate(ctx, "resolve", host)
	if err != nil {
		return "", err
	}
	return r.g.resolver.LookupCNAME(ctx, name)
}

func (r *guardedResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	name, err := r.gate(ctx, "resolve", host)
	if err != nil {
		return nil, err
	}
	return r.g.resolver.LookupTXT(ctx, name)
}

func (r *guardedResolver) LookupNS(ctx context.Context, host string) ([]string, error) {
	name, err := r.gate(ctx, "resolve", host)
	if err != nil {
		return nil, err
	}
	return r.g.resolver.LookupNS(ctx, name)
}

// ---- HTTP ----

type httpOptions struct {
	maxRedirects int
	timeout      time.Duration
}

// HTTPOption customises Guard.HTTPClient.
type HTTPOption func(*httpOptions)

// WithMaxRedirects sets the redirect cap (default 5).
func WithMaxRedirects(n int) HTTPOption { return func(o *httpOptions) { o.maxRedirects = n } }

// WithHTTPTimeout sets the overall request timeout (default 30s).
func WithHTTPTimeout(d time.Duration) HTTPOption { return func(o *httpOptions) { o.timeout = d } }

// HTTPClient returns an *http.Client whose every connection goes through the
// guarded Dialer (environment proxies are disabled: they would bypass
// destination vetting) and whose redirects are re-validated: a redirect is
// followed only if its target is an owned host or IP, or the very same
// hostname as the original request (and not excluded). Otherwise the redirect
// response is returned unfollowed together with an error matching
// ErrOutOfScope (or ErrExcluded). More than the cap yields ErrTooManyRedirects.
func (g *Guard) HTTPClient(tier model.Tier, assetClass model.ScopeClass, rate RateLimiter, opts ...HTTPOption) *http.Client {
	o := httpOptions{maxRedirects: 5, timeout: 30 * time.Second}
	for _, f := range opts {
		f(&o)
	}
	dialer := g.Dialer(tier, assetClass, rate)
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		// No pooling: every request re-resolves and re-vets its destination.
		DisableKeepAlives: true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   o.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > o.maxRedirects {
				return ErrTooManyRedirects
			}
			return g.checkRedirect(tier, req, via)
		},
	}
}

// redactURL reduces a URL to scheme://host/path for logs and errors: query
// strings and fragments routinely carry signed tokens.
func redactURL(u *url.URL) string {
	r := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	return r.String()
}

func (g *Guard) checkRedirect(tier model.Tier, req *http.Request, via []*http.Request) error {
	target := redactURL(req.URL)
	if s := strings.ToLower(req.URL.Scheme); s != "http" && s != "https" {
		return g.refuse(ErrOutOfScope, "redirect", tier, target, "", "non-http(s) redirect scheme")
	}
	host := req.URL.Hostname()
	class := g.classifyName(host)
	if class == model.ScopeExcluded {
		return g.refuse(ErrExcluded, "redirect", tier, target, class, "redirect target is excluded")
	}
	if class == model.ScopeOwned && Allowed(tier, class) {
		return nil
	}
	if len(via) > 0 && !isIPLiteral(host) {
		orig, ok1 := normHost(via[0].URL.Hostname())
		now, ok2 := normHost(host)
		if ok1 && ok2 && orig == now && Allowed(tier, class) {
			return nil
		}
	}
	// A merely external target (typically an SSO/login redirect) is routine:
	// log it at DEBUG. Anomalous IP literals (loopback, metadata) always log
	// at WARN, private ones at WARN at most hourly.
	const why = "redirect target is not owned and not the original host"
	if ip, ok := parseIP(host); ok && isAnomalous(ip) {
		return g.refuseAnomaly(ErrOutOfScope, "redirect", tier, target, class, why)
	} else if ok && isSpecial(ip) {
		return g.refuse(ErrOutOfScope, "redirect", tier, target, class, why)
	}
	return g.refuseAt(slog.LevelDebug, ErrOutOfScope, "redirect", tier, target, class, why)
}

func isIPLiteral(s string) bool { _, ok := parseIP(s); return ok }
