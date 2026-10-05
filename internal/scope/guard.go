// Package scope is deckard's safety invariant: it decides which assets deckard may
// actively probe (only ones the operator owns) and provides the guarded
// dialer, resolver and HTTP client that are the ONLY network primitives checks
// may use. Classification is fail-closed: anything unparseable, ambiguous or
// unknown is "external", which permits at most passive hostname-based probing.
package scope

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Guard classifies assets and builds scope-enforcing network primitives. It is
// safe for concurrent use.
type Guard struct {
	log      *slog.Logger
	base     check.Dialer   // nil => net.Dialer with a Control re-check
	resolver check.Resolver // underlying DNS

	dnsq    dnsx.Querier // recursive-resolver client behind Guard.DNS
	dnsOnce sync.Once

	throttle refusalThrottle
	observe  func(tier, class, reason string) // refusal counter, may be nil

	// immutable after NewGuard
	maxOwnedHosts uint64
	include       []hostPattern
	exclude       []hostPattern
	excludeNets   []netip.Prefix
	staticOwned   []netip.Prefix

	mu             sync.RWMutex
	zones          []string
	ownedPrefixes  []netip.Prefix
	sharedEmbedded []netip.Prefix
	sharedFile     []netip.Prefix
	sharedLive     []netip.Prefix // in-memory refreshed ranges, see SetSharedRanges
}

type options struct {
	log        *slog.Logger
	base       check.Dialer
	resolver   check.Resolver
	dnsq       dnsx.Querier
	sharedFile string
	observe    func(tier, class, reason string)
}

// Option customises NewGuard.
type Option func(*options)

// WithLogger sets the logger used for refusals (default slog.Default()).
func WithLogger(l *slog.Logger) Option { return func(o *options) { o.log = l } }

// WithRefusalObserver is called for every refusal with its tier, class and
// reason (a fixed string per refusal site, so it is safe as a metric label),
// whatever the log level. It must be safe for concurrent use.
func WithRefusalObserver(f func(tier, class, reason string)) Option {
	return func(o *options) { o.observe = f }
}

// WithDialer replaces the underlying dialer (tests, custom egress). The guard
// only ever hands it vetted IP-literal addresses.
func WithDialer(d check.Dialer) Option { return func(o *options) { o.base = d } }

// WithResolver replaces the underlying DNS resolver.
func WithResolver(r check.Resolver) Option { return func(o *options) { o.resolver = r } }

// WithDNSClient replaces the query client behind Guard.DNS (default: a
// dnsx.Client using the system resolvers). It must only talk to configured
// recursive resolvers.
func WithDNSClient(q dnsx.Querier) Option { return func(o *options) { o.dnsq = q } }

// WithSharedFile loads extra shared-infrastructure CIDRs from path in
// addition to the embedded list.
func WithSharedFile(path string) Option { return func(o *options) { o.sharedFile = path } }

// NewGuard builds a guard from scope config. scope.include entries may be
// hostname globs, IPs or CIDRs (IPs/CIDRs become owned prefixes); scope.exclude
// entries likewise. See hostPattern for glob semantics.
func NewGuard(cfg config.ScopeConfig, opts ...Option) (*Guard, error) {
	var o options
	for _, f := range opts {
		f(&o)
	}
	g := &Guard{log: o.log, base: o.base, resolver: o.resolver, dnsq: o.dnsq, observe: o.observe, maxOwnedHosts: 1024}
	if cfg.MaxCIDRHosts > 0 {
		g.maxOwnedHosts = uint64(cfg.MaxCIDRHosts)
	}
	if g.log == nil {
		g.log = slog.Default()
	}
	if len(cfg.Resolvers) > 0 {
		servers, err := normalizeResolvers(cfg.Resolvers)
		if err != nil {
			return nil, fmt.Errorf("scope.resolvers: %w", err)
		}
		if g.resolver == nil {
			g.resolver = stdResolver{resolverVia(servers)}
		}
		if g.dnsq == nil {
			g.dnsq = dnsx.New(dnsx.WithServers(servers...))
		}
	}
	if g.resolver == nil {
		g.resolver = stdResolver{net.DefaultResolver}
	}
	emb, err := EmbeddedSharedPrefixes()
	if err != nil {
		return nil, err
	}
	g.sharedEmbedded = emb
	if o.sharedFile != "" {
		if err := g.ReloadShared(o.sharedFile); err != nil {
			return nil, err
		}
	}

	for _, e := range cfg.Include {
		e = strings.TrimSpace(e)
		if p, ok := parseNetEntry(e); ok {
			if cfg.MaxCIDRHosts > 0 && config.PrefixHosts(p) > uint64(cfg.MaxCIDRHosts) {
				return nil, fmt.Errorf("scope.include %q: %d hosts exceeds scope.max_cidr_hosts=%d", e, config.PrefixHosts(p), cfg.MaxCIDRHosts)
			}
			g.staticOwned = append(g.staticOwned, p)
			continue
		}
		hp, err := compilePattern(e, true)
		if err != nil {
			return nil, fmt.Errorf("scope.include %q: %w", e, err)
		}
		g.include = append(g.include, hp)
	}
	for _, e := range cfg.Exclude {
		e = strings.TrimSpace(e)
		if p, ok := parseNetEntry(e); ok {
			g.excludeNets = append(g.excludeNets, p)
			continue
		}
		hp, err := compilePattern(e, false)
		if err != nil {
			return nil, fmt.Errorf("scope.exclude %q: %w", e, err)
		}
		g.exclude = append(g.exclude, hp)
	}
	return g, nil
}

func parseNetEntry(s string) (netip.Prefix, bool) {
	p, err := parsePrefixOrAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// SetZones replaces the set of owned zones (e.g. from source sync). Entries
// that are empty, wildcards, invalid or single-label (a TLD would make the
// whole TLD "owned") are ignored and logged.
func (g *Guard) SetZones(zones []string) {
	out := make([]string, 0, len(zones))
	for _, z := range zones {
		n, ok := normHost(z)
		if !ok || strings.Count(n, ".") < 1 || isPublicSuffix(n) {
			if strings.TrimSpace(z) != "" {
				g.log.Warn("scope: ignoring invalid, single-label or public-suffix owned zone", slog.String("zone", z))
			}
			continue
		}
		out = append(out, n)
	}
	g.mu.Lock()
	g.zones = out
	g.mu.Unlock()
}

// SetOwnedPrefixes replaces the dynamically registered owned IP prefixes
// (inventory IPs from owned sources). An IP is owned only if registered here
// or via scope.include; resolving from an owned hostname never makes it so.
func (g *Guard) SetOwnedPrefixes(prefixes []netip.Prefix) {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		p = normPrefix(p)
		// A buggy or compromised source must not be able to make large or
		// internal ranges "owned". Operators who really want to probe a
		// private range declare it explicitly in scope.include.
		if config.PrefixHosts(p) > g.maxOwnedHosts {
			g.log.Warn("scope: ignoring owned prefix larger than scope.max_cidr_hosts", slog.String("prefix", p.String()))
			continue
		}
		if overlapsNeverOwned(p) {
			g.log.Warn("scope: ignoring discovered owned prefix that overlaps loopback, link-local, metadata or reserved space", slog.String("prefix", p.String()))
			continue
		}
		out = append(out, p)
	}
	g.mu.Lock()
	g.ownedPrefixes = out
	g.mu.Unlock()
}

// Classify returns the scope class of an asset. Precedence: excluded > owned >
// shared > external. Unparseable keys and kinds that are not network
// addressable (certificates, cloud resources) are external.
func (g *Guard) Classify(kind model.AssetKind, key string) model.ScopeClass {
	switch kind {
	case model.KindHostname, model.KindZone:
		return g.classifyName(key)
	case model.KindIP:
		return g.classifyIPString(key)
	case model.KindURL:
		u, err := url.Parse(strings.TrimSpace(key))
		if err != nil || u.Hostname() == "" {
			return model.ScopeExternal
		}
		return g.classifyName(u.Hostname())
	case model.KindService:
		key = strings.TrimSuffix(strings.TrimSpace(key), "/tcp")
		if h, _, err := net.SplitHostPort(key); err == nil {
			key = h
		}
		return g.classifyName(key)
	}
	return model.ScopeExternal
}

// classifyName handles hostnames and IP literals given as names.
func (g *Guard) classifyName(s string) model.ScopeClass {
	if ip, ok := parseIP(s); ok {
		return g.classifyIP(ip)
	}
	h, ok := normHost(s)
	if !ok {
		return model.ScopeExternal
	}
	for _, p := range g.exclude {
		if p.match(h) {
			return model.ScopeExcluded
		}
	}
	g.mu.RLock()
	zones := g.zones
	g.mu.RUnlock()
	for _, z := range zones {
		if h == z || strings.HasSuffix(h, "."+z) {
			return model.ScopeOwned
		}
	}
	for _, p := range g.include {
		if p.match(h) {
			return model.ScopeOwned
		}
	}
	return model.ScopeExternal
}

func (g *Guard) classifyIPString(s string) model.ScopeClass {
	ip, ok := parseIP(s)
	if !ok {
		return model.ScopeExternal
	}
	return g.classifyIP(ip)
}

// ClassifyUnregistered classifies an IP like Classify but ignores the
// dynamically registered owned prefixes (SetOwnedPrefixes). The inventory
// vets a registration with it, so an IP's own earlier registration cannot
// vouch for it once its range has become shared or excluded.
func (g *Guard) ClassifyUnregistered(ip string) model.ScopeClass {
	a, ok := parseIP(ip)
	if !ok {
		return model.ScopeExternal
	}
	return g.classifyIPWith(a, false)
}

// classifyIP expects a normalised address (see normAddr).
func (g *Guard) classifyIP(ip netip.Addr) model.ScopeClass {
	return g.classifyIPWith(ip, true)
}

func (g *Guard) classifyIPWith(ip netip.Addr, registered bool) model.ScopeClass {
	ip = normAddr(ip)
	if inAny(g.excludeNets, ip) {
		return model.ScopeExcluded
	}
	if inAny(g.staticOwned, ip) {
		return model.ScopeOwned
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if registered && inAny(g.ownedPrefixes, ip) {
		return model.ScopeOwned
	}
	if inAny(g.sharedEmbedded, ip) || inAny(g.sharedFile, ip) || inAny(g.sharedLive, ip) {
		return model.ScopeShared
	}
	return model.ScopeExternal
}

func inAny(ps []netip.Prefix, ip netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ---- normalisation ----

// normAddr unmaps IPv4-mapped IPv6 and drops any zone.
func normAddr(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

func normPrefix(p netip.Prefix) netip.Prefix {
	a := p.Addr().WithZone("")
	if a.Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96).Masked()
	}
	return netip.PrefixFrom(a, p.Bits()).Masked()
}

// parseIP parses an IP literal tolerating brackets, zones and v4-mapped forms.
func parseIP(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return normAddr(a), true
}

var idnaProfile = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.BidiRule())

// normHost lowercases, strips one trailing dot, converts IDN to punycode and
// validates the result. Underscores are allowed (_dmarc). ok=false for
// anything that is not a plain DNS name.
func normHost(s string) (string, bool) {
	return normName(s, false)
}

func normName(s string, pattern bool) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", false
	}
	if !isASCII(s) {
		a, err := idnaProfile.ToASCII(s)
		if err != nil {
			return "", false
		}
		s = a
	}
	s = strings.ToLower(s)
	if len(s) > 253 {
		return "", false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			case pattern && (c == '*' || c == '?' || c == '[' || c == ']'):
			default:
				return "", false
			}
		}
	}
	return s, true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// ---- hostname patterns ----

// hostPattern is a compiled hostname glob. labels are matched right-aligned
// against the host's labels with path.Match (so '*' never crosses a dot);
// the host may have between minExtra and maxExtra (-1: unbounded) additional
// leading labels.
//
//	include "a.example.com"  exact only             (0,0)
//	include "*.example.com"  subdomains, not apex   (1,inf)
//	exclude "a.example.com"  the name and all below (0,inf)
//	exclude "*.example.com"  subdomains, not apex   (1,inf)
//	exclude "*"              everything             (0,inf)
type hostPattern struct {
	labels   []string
	minExtra int
	maxExtra int
}

func compilePattern(s string, include bool) (hostPattern, error) {
	if s == "" {
		return hostPattern{}, fmt.Errorf("empty pattern")
	}
	n, ok := normName(s, true)
	if !ok {
		return hostPattern{}, fmt.Errorf("not a valid hostname pattern")
	}
	var hp hostPattern
	switch {
	case n == "*" && !include:
		return hostPattern{minExtra: 0, maxExtra: -1}, nil
	case strings.HasPrefix(n, "*."):
		hp = hostPattern{labels: strings.Split(n[2:], "."), minExtra: 1, maxExtra: -1}
	case include:
		hp = hostPattern{labels: strings.Split(n, "."), minExtra: 0, maxExtra: 0}
	default:
		hp = hostPattern{labels: strings.Split(n, "."), minExtra: 0, maxExtra: -1}
	}
	for _, l := range hp.labels {
		if _, err := path.Match(l, ""); err != nil {
			return hostPattern{}, fmt.Errorf("bad glob: %w", err)
		}
	}
	if include {
		// An include that could cover a whole TLD (or everything) would
		// make most of the internet "owned".
		if len(hp.labels) < 2 {
			return hostPattern{}, fmt.Errorf("include pattern must have at least two non-wildcard-prefix labels")
		}
		if strings.ContainsAny(hp.labels[len(hp.labels)-1], "*?[]") {
			return hostPattern{}, fmt.Errorf("include pattern's last label must be literal")
		}
		// The literal tail must reach a registrable domain: "*.co.uk" or
		// "foo.*.com" would otherwise own other people's names.
		if !literalTailRegistrable(hp.labels) {
			return hostPattern{}, fmt.Errorf("include pattern must contain a literal registrable domain (e.g. *.example.com), not a public suffix")
		}
	}
	return hp, nil
}

func (p hostPattern) match(host string) bool {
	hl := strings.Split(host, ".")
	extra := len(hl) - len(p.labels)
	if extra < p.minExtra || (p.maxExtra >= 0 && extra > p.maxExtra) {
		return false
	}
	tail := hl[extra:]
	for i, pl := range p.labels {
		if ok, err := path.Match(pl, tail[i]); err != nil || !ok {
			return false
		}
	}
	return true
}

// isPublicSuffix reports whether name is itself a public suffix (co.uk,
// github.io, com): owning one would own other people's names.
func isPublicSuffix(name string) bool {
	_, err := publicsuffix.EffectiveTLDPlusOne(name)
	return err != nil
}

// literalTailRegistrable reports whether the glob-free labels at the right of
// an include pattern reach past the public suffix, i.e. contain a registrable
// domain.
func literalTailRegistrable(labels []string) bool {
	n := 0
	for i := len(labels) - 1; i >= 0; i-- {
		if strings.ContainsAny(labels[i], "*?[]") {
			break
		}
		n++
	}
	if n == 0 {
		return false
	}
	tail := strings.Join(labels[len(labels)-n:], ".")
	_, err := publicsuffix.EffectiveTLDPlusOne(tail)
	return err == nil
}

// neverOwnedPrefixes can not be registered as owned by a source. They cover
// loopback, link-local (cloud metadata 169.254.169.254), provider metadata
// addresses, multicast/reserved space, and the IPv6 transition forms that can
// embed an IPv4 metadata address. Private ranges (RFC1918, ULA, CGNAT) stay
// ownable because operators legitimately audit their own LAN and cluster
// addresses. An operator who truly needs one of these writes it in
// scope.include, which is explicit configuration rather than discovery.
var neverOwnedPrefixes = mustPrefixes(
	"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "fe80::/10", "ff00::/8", "fd00:ec2::/64",
	"64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "::/96", "::ffff:0:0:0/96",
)

// overlapsNeverOwned reports whether p overlaps a never-ownable range.
func overlapsNeverOwned(p netip.Prefix) bool {
	for _, sp := range neverOwnedPrefixes {
		if sp.Overlaps(p) {
			return true
		}
	}
	return false
}

// normalizeResolvers validates scope.resolvers: each entry must be an IP
// literal with an optional port (default 53). Hostnames are refused because
// resolving them would need a resolver first.
func normalizeResolvers(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, e := range in {
		e = strings.TrimSpace(e)
		host, port := e, "53"
		if h, p, err := net.SplitHostPort(e); err == nil {
			host, port = h, p
		}
		host = strings.Trim(host, "[]")
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("%q is not an IP address with an optional port", e)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%q has an invalid port", e)
		}
		out = append(out, net.JoinHostPort(host, port))
	}
	return out, nil
}

// resolverCooldown is how long a resolver that just failed is skipped.
const resolverCooldown = 30 * time.Second

// dnsServer is one configured resolver and when it may be tried again.
type dnsServer struct {
	addr     string
	badUntil atomic.Int64 // unix nanoseconds
}

// serverSet picks the next healthy resolver, rotating the starting point so
// load spreads, and skips ones that failed recently. The Go resolver asks for a
// connection per attempt and runs A and AAAA lookups concurrently, so a plain
// rotating index can starve a lookup onto a dead server; remembering failures
// makes the next attempt go elsewhere.
type serverSet struct {
	servers []*dnsServer
	next    atomic.Uint32
	now     func() time.Time
}

func newServerSet(addrs []string) *serverSet {
	s := &serverSet{now: time.Now}
	for _, a := range addrs {
		s.servers = append(s.servers, &dnsServer{addr: a})
	}
	return s
}

func (s *serverSet) pick() *dnsServer {
	n := len(s.servers)
	start := int(s.next.Add(1) - 1)
	now := s.now().UnixNano()
	for i := 0; i < n; i++ {
		if sv := s.servers[(start+i)%n]; sv.badUntil.Load() <= now {
			return sv
		}
	}
	return s.servers[start%n] // all recently failed: keep trying, rotating
}

func (s *serverSet) fail(sv *dnsServer) {
	sv.badUntil.Store(s.now().Add(resolverCooldown).UnixNano())
}

// failing reports whether a read error means the resolver is unusable. A
// context cancelled by the caller is not the server's fault.
func failing(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF)
}

// trackedUDP and trackedTCP report resolver failures. They embed the concrete
// connection types so net.Resolver still sees a net.PacketConn for UDP and
// frames its queries correctly.
type trackedUDP struct {
	*net.UDPConn
	onErr func()
}

func (c trackedUDP) Read(b []byte) (int, error) {
	n, err := c.UDPConn.Read(b)
	if failing(err) {
		c.onErr()
	}
	return n, err
}

type trackedTCP struct {
	*net.TCPConn
	onErr func()
}

func (c trackedTCP) Read(b []byte) (int, error) {
	n, err := c.TCPConn.Read(b)
	if failing(err) {
		c.onErr()
	}
	return n, err
}

// resolverVia returns a pure-Go resolver that sends every lookup to servers,
// failing over from one that stops answering.
func resolverVia(servers []string) *net.Resolver {
	set := newServerSet(servers)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			var last error
			for range set.servers {
				sv := set.pick()
				c, err := d.DialContext(ctx, network, sv.addr)
				if err != nil {
					set.fail(sv)
					last = err
					continue
				}
				fail := func() { set.fail(sv) }
				switch conn := c.(type) {
				case *net.UDPConn:
					return trackedUDP{conn, fail}, nil
				case *net.TCPConn:
					return trackedTCP{conn, fail}, nil
				}
				return c, nil
			}
			return nil, last
		},
	}
}
