// Package cloudflare discovers assets from the Cloudflare v4 REST API using a
// read-only API token: zones, DNS records, load balancers and pools, tunnels
// and Spectrum apps.
package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

// ProxyKey is the cloud_resource asset every proxied record points at.
const ProxyKey = "cloudflare:proxy"

// Source is the Cloudflare asset source.
type Source struct {
	name      string
	accountID string
	c         *client
	log       *slog.Logger
}

// Option tweaks a Source (mainly for tests).
type Option func(*Source)

// WithHTTPClient replaces the HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(s *Source) { s.c.http = h } }

// WithRetry sets the retry count and base backoff.
func WithRetry(max int, backoff time.Duration) Option {
	return func(s *Source) { s.c.maxRetries, s.c.backoff = max, backoff }
}

// New builds a Cloudflare source. The token comes from cfg.TokenEnv (via
// getenv) or cfg.Token.
func New(cfg config.SourceConfig, getenv func(string) string, log *slog.Logger, opts ...Option) (*Source, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	token := strings.TrimSpace(cfg.ResolveToken(getenv))
	if token == "" {
		return nil, fmt.Errorf("cloudflare source %q: no API token (set token_env or token)", cfg.Name)
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	s := &Source{
		name:      cfg.Name,
		accountID: cfg.AccountID,
		log:       log.With("source", cfg.Name, "type", "cloudflare"),
		c: &client{
			base: base, token: token, log: log,
			http:       &http.Client{Timeout: defaultTimeout},
			maxRetries: defaultMaxRetries, backoff: defaultBackoff,
		},
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func (s *Source) Name() string { return s.name }
func (s *Source) Type() string { return "cloudflare" }

// API shapes (subset).

type zoneResp struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
}

type dnsRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

type lbResp struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Enabled      bool                `json:"enabled"`
	Proxied      bool                `json:"proxied"`
	DefaultPools []string            `json:"default_pools"`
	FallbackPool string              `json:"fallback_pool"`
	RegionPools  map[string][]string `json:"region_pools"`
	PopPools     map[string][]string `json:"pop_pools"`
	CountryPools map[string][]string `json:"country_pools"`
}

func (l lbResp) poolIDs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(ids ...string) {
		for _, id := range ids {
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	add(l.DefaultPools...)
	add(l.FallbackPool)
	for _, m := range []map[string][]string{l.RegionPools, l.PopPools, l.CountryPools} {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			add(m[k]...)
		}
	}
	return out
}

type poolResp struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Origins []struct {
		Name    string `json:"name"`
		Address string `json:"address"`
		Enabled bool   `json:"enabled"`
	} `json:"origins"`
}

type tunnelResp struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type spectrumResp struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	DNS      struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"dns"`
	OriginDirect []string `json:"origin_direct"`
	OriginDNS    *struct {
		Name string `json:"name"`
	} `json:"origin_dns"`
	OriginPort any `json:"origin_port"`
}

// Discover returns a complete snapshot or an error; features the token cannot
// access (403/404/not enabled) are skipped with a warning, everything else
// failing is a hard error.
func (s *Source) Discover(ctx context.Context) (*source.Discovery, error) {
	b := newBuilder(s.name)

	zq := url.Values{}
	if s.accountID != "" {
		zq.Set("account.id", s.accountID)
	}
	zones, err := listAll[zoneResp](ctx, s.c, "/zones", zq, perPage)
	if err != nil {
		return nil, err
	}
	accounts := map[string]bool{}
	if s.accountID != "" {
		accounts[s.accountID] = true
	}
	for _, z := range zones {
		if z.Account.ID != "" && s.accountID == "" {
			accounts[z.Account.ID] = true
		}
	}
	accountIDs := make([]string, 0, len(accounts))
	for a := range accounts {
		accountIDs = append(accountIDs, a)
	}
	sort.Strings(accountIDs)

	// Pools first so zone-level load balancers can resolve them.
	pools := map[string]poolResp{}
	for _, acct := range accountIDs {
		ps, ok, err := optional(s, ctx, b, "load balancer pools", func() ([]poolResp, error) {
			return listAll[poolResp](ctx, s.c, "/accounts/"+acct+"/load_balancers/pools", nil, perPage)
		})
		if err != nil {
			return nil, err
		}
		if ok {
			for _, p := range ps {
				pools[p.ID] = p
			}
		}
		ts, ok, err := optional(s, ctx, b, "tunnels", func() ([]tunnelResp, error) {
			return listAll[tunnelResp](ctx, s.c, "/accounts/"+acct+"/cfd_tunnel", url.Values{"is_deleted": {"false"}}, perPage)
		})
		if err != nil {
			return nil, err
		}
		if ok {
			for _, t := range ts {
				b.cloudResource("cloudflare:tunnel:"+t.ID, map[string]any{
					"provider": "cloudflare", "type": "tunnel", "name": t.Name, "status": t.Status, "account_id": acct,
				})
			}
		}
	}
	referencedPools := map[string]bool{}

	sort.Slice(zones, func(i, j int) bool { return zones[i].ID < zones[j].ID })
	var outZones []source.Zone
	for _, z := range zones {
		zname := normName(z.Name)
		if zname == "" {
			continue
		}
		outZones = append(outZones, source.Zone{Name: zname, Source: s.name})
		za := b.asset(model.KindZone, zname, zname)
		za.Attrs["zone_id"], za.Attrs["status"], za.Attrs["account_id"] = z.ID, z.Status, z.Account.ID

		recs, err := listAll[dnsRecord](ctx, s.c, "/zones/"+z.ID+"/dns_records", nil, perPage)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			s.addRecord(b, zname, r)
		}

		lbs, ok, err := optional(s, ctx, b, "load balancers", func() ([]lbResp, error) {
			return listAll[lbResp](ctx, s.c, "/zones/"+z.ID+"/load_balancers", nil, perPage)
		})
		if err != nil {
			return nil, err
		}
		if ok {
			for _, lb := range lbs {
				host := normName(lb.Name)
				if host == "" {
					continue
				}
				h := b.host(host, zname)
				h.Attrs["load_balancer"] = true
				h.Attrs["lb_proxied"] = lb.Proxied
				b.rel(model.KindHostname, host, model.KindZone, zname, model.RelInZone)
				for _, pid := range lb.poolIDs() {
					referencedPools[pid] = true
					if p, found := pools[pid]; found {
						s.addPoolOrigins(b, p, host)
					}
				}
			}
		}

		apps, ok, err := optional(s, ctx, b, "spectrum apps", func() ([]spectrumResp, error) {
			return listAll[spectrumResp](ctx, s.c, "/zones/"+z.ID+"/spectrum/apps", nil, perPage)
		})
		if err != nil {
			return nil, err
		}
		if ok {
			for _, app := range apps {
				s.addSpectrum(b, zname, app)
			}
		}
	}

	// Pools no load balancer references still describe origin addresses.
	ids := make([]string, 0, len(pools))
	for id := range pools {
		if !referencedPools[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		s.addPoolOrigins(b, pools[id], "")
	}

	d := b.discovery()
	d.Zones = outZones
	return d, nil
}

// optional runs fn and converts "not available to this token/plan" API errors
// into a skipped feature. Any other error is returned.
func optional[T any](s *Source, ctx context.Context, b *builder, feature string, fn func() ([]T, error)) ([]T, bool, error) {
	v, err := fn()
	if err == nil {
		return v, true, nil
	}
	var ae *apiError
	if errors.As(err, &ae) && ae.notAvailable() {
		s.log.Warn("cloudflare feature skipped", "feature", feature, "path", ae.Path, "status", ae.Status)
		// 403 means the token may not read the feature, so the result can lack
		// assets it produces: partial. 404 / "not enabled" means the zone or plan
		// does not have the feature: nothing to miss.
		if ae.Status == http.StatusForbidden {
			b.skip(fmt.Sprintf("cloudflare %s skipped (HTTP 403, token lacks permission)", feature))
		}
		return nil, false, nil
	}
	return nil, false, err
}

func (s *Source) addRecord(b *builder, zone string, r dnsRecord) {
	name := normName(r.Name)
	if name == "" {
		return
	}
	typ := strings.ToUpper(r.Type)
	h := b.host(name, zone)
	addUniq(h.Attrs, "record_types", typ)
	if _, ok := h.Attrs["ttl"]; !ok {
		h.Attrs["ttl"] = r.TTL
	}
	if r.Proxied {
		h.Attrs["proxied"] = true
	} else if _, ok := h.Attrs["proxied"]; !ok {
		h.Attrs["proxied"] = false
	}
	if strings.HasPrefix(name, "*.") {
		h.Attrs["wildcard"] = true
	}
	addUniq(h.Attrs, "content", r.Content)
	b.rel(model.KindHostname, name, model.KindZone, zone, model.RelInZone)

	switch typ {
	case "A", "AAAA":
		addr, err := netip.ParseAddr(strings.TrimSpace(r.Content))
		if err != nil {
			s.log.Warn("cloudflare: skipping record with invalid IP", "record", name, "type", typ)
			return
		}
		ip := addr.Unmap().String()
		a := b.asset(model.KindIP, ip, "")
		if prev, ok := a.Attrs["proxied"].(bool); ok {
			a.Attrs["proxied"] = prev && r.Proxied
		} else {
			a.Attrs["proxied"] = r.Proxied
		}
		if r.Proxied {
			// The record's IP is the hidden origin, not what the world sees.
			a.Attrs["origin"] = true
			if _, ok := h.Attrs["origin_ip"]; !ok {
				h.Attrs["origin_ip"] = ip
			}
			addUniq(h.Attrs, "origin_ips", ip)
		} else {
			a.Attrs["exposed"] = true
		}
		b.rel(model.KindHostname, name, model.KindIP, ip, model.RelResolvesTo)
	case "CNAME":
		target := normName(r.Content)
		if target != "" {
			b.host(target, "")
			b.rel(model.KindHostname, name, model.KindHostname, target, model.RelCNAMETo)
		}
	}
	if r.Proxied {
		b.cloudResource(ProxyKey, map[string]any{"provider": "cloudflare", "type": "proxy"})
		b.rel(model.KindHostname, name, model.KindCloudResource, ProxyKey, model.RelProxiedBy)
	}
}

// originAsset creates the ip or hostname asset for an origin address and
// returns its (kind, key).
func (s *Source) originAsset(b *builder, addr string) (model.AssetKind, string, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", false
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		key := ip.Unmap().String()
		b.asset(model.KindIP, key, "").Attrs["origin"] = true
		return model.KindIP, key, true
	}
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		key := ap.Addr().Unmap().String()
		b.asset(model.KindIP, key, "").Attrs["origin"] = true
		return model.KindIP, key, true
	}
	host := normName(addr)
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	if host == "" {
		return "", "", false
	}
	b.host(host, "").Attrs["origin"] = true
	return model.KindHostname, host, true
}

func (s *Source) addPoolOrigins(b *builder, p poolResp, lbHost string) {
	for _, o := range p.Origins {
		kind, key, ok := s.originAsset(b, o.Address)
		if !ok {
			continue
		}
		a := b.asset(kind, key, "")
		addUniq(a.Attrs, "pools", p.Name)
		a.Attrs["pool_enabled"] = p.Enabled
		if lbHost != "" {
			b.rel(kind, key, model.KindHostname, lbHost, model.RelOriginOf)
		}
	}
}

func (s *Source) addSpectrum(b *builder, zone string, app spectrumResp) {
	edge := normName(app.DNS.Name)
	if edge == "" {
		return
	}
	proto, port := "tcp", ""
	if p, pt, ok := strings.Cut(strings.ToLower(app.Protocol), "/"); ok {
		proto, port = p, pt
	}
	if port == "" {
		port = originPort(app.OriginPort)
	}
	if port == "" {
		port = "0"
	}
	svcKey := fmt.Sprintf("%s:%s/%s", edge, port, proto)
	svc := b.asset(model.KindService, svcKey, zone)
	svc.Attrs["spectrum"], svc.Attrs["app_id"], svc.Attrs["edge_hostname"] = true, app.ID, edge
	h := b.host(edge, zone)
	h.Attrs["spectrum"] = true
	b.rel(model.KindHostname, edge, model.KindZone, zone, model.RelInZone)
	b.rel(model.KindHostname, edge, model.KindService, svcKey, model.RelExposes)

	var origins []string
	for _, od := range app.OriginDirect {
		if u, err := url.Parse(od); err == nil && u.Hostname() != "" {
			origins = append(origins, u.Hostname())
		} else {
			origins = append(origins, od)
		}
	}
	if app.OriginDNS != nil && app.OriginDNS.Name != "" {
		origins = append(origins, app.OriginDNS.Name)
	}
	for _, o := range origins {
		if kind, key, ok := s.originAsset(b, o); ok {
			b.rel(kind, key, model.KindService, svcKey, model.RelOriginOf)
		}
	}
}

func originPort(v any) string {
	switch t := v.(type) {
	case float64:
		return fmt.Sprintf("%d", int(t))
	case map[string]any:
		st, _ := t["start"].(float64)
		en, _ := t["end"].(float64)
		if st > 0 && en > st {
			return fmt.Sprintf("%d-%d", int(st), int(en))
		}
		if st > 0 {
			return fmt.Sprintf("%d", int(st))
		}
	}
	return ""
}

// normName lowercases and strips whitespace and the trailing root dot.
func normName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
