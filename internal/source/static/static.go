// Package static is the operator-declared asset source: hostnames, IPs, CIDRs
// and URLs straight from config. It is the only source that marks IPs as
// explicitly operator-owned (attrs.owned=true).
package static

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

// Source discovers the statically configured assets.
type Source struct {
	cfg          config.SourceConfig
	maxCIDRHosts int
	disc         *source.Discovery
}

// New validates the configuration eagerly so bad input fails at startup.
// CIDR expansion includes every address in the prefix (network and broadcast
// too): the operator declared the whole range as theirs.
func New(cfg config.SourceConfig, maxCIDRHosts int) (*Source, error) {
	s := &Source{cfg: cfg, maxCIDRHosts: maxCIDRHosts}
	d, err := s.build()
	if err != nil {
		return nil, err
	}
	s.disc = d
	return s, nil
}

func (s *Source) Name() string { return s.cfg.Name }
func (s *Source) Type() string { return "static" }

// Discover returns the (constant) snapshot. The result is rebuilt each call so
// callers may mutate it freely.
func (s *Source) Discover(ctx context.Context) (*source.Discovery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.build()
}

func (s *Source) build() (*source.Discovery, error) {
	d := &source.Discovery{}
	seen := map[string]bool{}
	add := func(kind model.AssetKind, key string, attrs map[string]any) {
		id := string(kind) + "\x00" + key
		if seen[id] {
			return
		}
		seen[id] = true
		d.Assets = append(d.Assets, model.AssetInput{Kind: kind, Key: key, Source: s.cfg.Name, Attrs: attrs})
	}
	owned := func() map[string]any { return map[string]any{"owned": true} }
	errf := func(format string, a ...any) error {
		return fmt.Errorf("static source %q: "+format, append([]any{s.cfg.Name}, a...)...)
	}

	for _, h := range s.cfg.Hostnames {
		n := normHost(h)
		if n == "" || strings.ContainsAny(n, " /:@") {
			return nil, errf("invalid hostname %q", h)
		}
		add(model.KindHostname, n, nil)
	}
	for _, v := range s.cfg.IPs {
		a, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil {
			return nil, errf("invalid ip %q", v)
		}
		add(model.KindIP, a.Unmap().String(), owned())
	}
	for _, c := range s.cfg.CIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, errf("invalid cidr %q", c)
		}
		p = p.Masked()
		if n := config.PrefixHosts(p); n > uint64(s.maxCIDRHosts) { // #nosec G115 -- max_cidr_hosts is validated > 0
			return nil, errf("cidr %s has %d addresses, exceeds scope.max_cidr_hosts=%d", c, n, s.maxCIDRHosts)
		}
		for a := p.Addr(); a.IsValid() && p.Contains(a); a = a.Next() {
			add(model.KindIP, a.Unmap().String(), owned())
		}
	}
	for _, raw := range s.cfg.URLs {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, errf("invalid url %q (want http(s)://host[/path])", raw)
		}
		u.Scheme = strings.ToLower(u.Scheme)
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		u.Host = hostPort(host, u.Port())
		u.Fragment = ""
		u.User = nil
		key := u.String()
		add(model.KindURL, key, nil)
		if ip, err := netip.ParseAddr(host); err == nil {
			ipKey := ip.Unmap().String()
			add(model.KindIP, ipKey, owned())
			d.Relations = append(d.Relations, model.RelationInput{FromKind: model.KindIP, FromKey: ipKey, ToKind: model.KindURL, ToKey: key, Type: model.RelServes})
			continue
		}
		add(model.KindHostname, host, nil)
		d.Relations = append(d.Relations, model.RelationInput{FromKind: model.KindHostname, FromKey: host, ToKind: model.KindURL, ToKey: key, Type: model.RelServes})
	}
	return d, nil
}

func hostPort(host, port string) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		return host + ":" + port
	}
	return host
}

func normHost(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
