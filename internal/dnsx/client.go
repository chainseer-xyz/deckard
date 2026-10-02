package dnsx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	// ErrNoServers means no recursive resolver is configured and none could
	// be read from resolv.conf.
	ErrNoServers = errors.New("dnsx: no recursive resolvers configured")
	// ErrInvalidName is returned for names that are not valid DNS names.
	ErrInvalidName = errors.New("dnsx: invalid domain name")
	// ErrUnavailable wraps the last transport error when every attempt
	// failed (timeouts, connection errors). Callers must treat it as
	// "unknown", never as "does not exist".
	ErrUnavailable = errors.New("dnsx: resolver unavailable")
)

// PublicResolvers are well-known public recursive resolvers. They are used
// only when WithPublicFallback is given AND nothing else is configured: deckard
// never sends queries to a third party silently.
var PublicResolvers = []string{"1.1.1.1:53", "9.9.9.9:53", "8.8.8.8:53"}

// Client is a concurrency-safe DNS client. Create with New.
type Client struct {
	servers    []string
	resolvConf string
	fallback   bool
	timeout    time.Duration
	retries    int
	udpSize    uint16
	dnssec     bool

	once    sync.Once
	cfgSrvs []string
}

// Option customises New.
type Option func(*Client)

// WithServers sets the recursive resolvers ("host" or "host:port"). They take
// precedence over resolv.conf.
func WithServers(servers ...string) Option {
	return func(c *Client) { c.servers = append([]string(nil), servers...) }
}

// WithResolvConf overrides the resolv.conf path (default /etc/resolv.conf).
func WithResolvConf(path string) Option { return func(c *Client) { c.resolvConf = path } }

// WithPublicFallback allows falling back to PublicResolvers when no resolver
// is configured and resolv.conf yields none. Off by default.
func WithPublicFallback() Option { return func(c *Client) { c.fallback = true } }

// WithTimeout sets the per-attempt timeout (default 2s).
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }

// WithRetries sets how many additional attempts follow a failed one, rotating
// through the servers (default 2).
func WithRetries(n int) Option { return func(c *Client) { c.retries = n } }

// WithUDPSize sets the advertised EDNS0 buffer size (default 1232).
func WithUDPSize(n uint16) Option { return func(c *Client) { c.udpSize = n } }

// WithDNSSEC sets the DO bit on every query. It is always set for DNSSEC
// record types (DNSKEY, DS, RRSIG, NSEC*).
func WithDNSSEC() Option { return func(c *Client) { c.dnssec = true } }

// New builds a Client. With no options it uses the system resolvers from
// /etc/resolv.conf (read lazily on first query).
func New(opts ...Option) *Client {
	c := &Client{resolvConf: "/etc/resolv.conf", timeout: 2 * time.Second, retries: 2, udpSize: 1232}
	for _, o := range opts {
		o(c)
	}
	if c.retries < 0 {
		c.retries = 0
	}
	if c.timeout <= 0 {
		c.timeout = 2 * time.Second
	}
	return c
}

func withPort(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

// Servers returns the resolvers queries are sent to.
func (c *Client) Servers() ([]string, error) {
	c.once.Do(func() {
		var out []string
		for _, s := range c.servers {
			out = append(out, withPort(s))
		}
		if len(out) == 0 {
			if cfg, err := dns.ClientConfigFromFile(c.resolvConf); err == nil {
				for _, s := range cfg.Servers {
					out = append(out, net.JoinHostPort(s, cfg.Port))
				}
			}
		}
		if len(out) == 0 && c.fallback {
			out = append(out, PublicResolvers...)
		}
		c.cfgSrvs = out
	})
	if len(c.cfgSrvs) == 0 {
		return nil, ErrNoServers
	}
	return c.cfgSrvs, nil
}

func isDNSSECType(t uint16) bool {
	switch t {
	case dns.TypeDNSKEY, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeCDS, dns.TypeCDNSKEY:
		return true
	}
	return false
}

// Query asks the configured resolvers for name/qtype. A reply with any rcode
// (including NXDOMAIN and SERVFAIL) is returned as a Response with a nil
// error; check Response.State. An error wrapping ErrUnavailable means no
// resolver produced a reply in time: treat it as unknown. UDP truncation is
// retried over TCP.
func (c *Client) Query(ctx context.Context, name string, qtype uint16) (*Response, error) {
	servers, err := c.Servers()
	if err != nil {
		return nil, err
	}
	n := Norm(name)
	if _, ok := dns.IsDomainName(n); n == "" || !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(n), qtype)
	m.RecursionDesired = true
	m.SetEdns0(c.udpSize, c.dnssec || isDNSSECType(qtype))

	var lastErr error
	var lastResp *Response
	for i := 0; i <= c.retries; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		srv := servers[i%len(servers)]
		resp, err := c.exchange(ctx, m, srv)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError {
			return resp, nil
		}
		lastResp = resp // SERVFAIL, REFUSED, ...: try another attempt/server
	}
	if lastResp != nil {
		return lastResp, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: %v", ErrUnavailable, lastErr)
}

func (c *Client) exchange(ctx context.Context, m *dns.Msg, srv string) (*Response, error) {
	q := m.Question[0]
	uc := &dns.Client{Net: "udp", Timeout: c.timeout, UDPSize: c.udpSize}
	r, _, err := uc.ExchangeContext(ctx, m.Copy(), srv)
	tcp := false
	if err == nil && r.Truncated {
		tc := &dns.Client{Net: "tcp", Timeout: c.timeout}
		r, _, err = tc.ExchangeContext(ctx, m.Copy(), srv)
		tcp = true
	}
	if err != nil {
		return nil, err
	}
	return ParseMsg(r, q.Name, q.Qtype, srv, tcp), nil
}
