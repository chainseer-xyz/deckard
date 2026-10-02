// Package probe implements http.probe: liveness, status, title, server
// header, redirect chain and technology tags for owned hostnames and URLs.
//
// Config keys:
//
//	schemes          []string  schemes tried for hostnames (default [https http])
//	timeout_seconds  int       per-request timeout (default 10)
//	max_body_bytes   int       body read cap (default 1048576)
//	owned_zones      []string  zones whose redirect-target hostnames are discovered
package probe

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "http.probe"

// Check is the http.probe check.
type Check struct{ base map[string]any }

// New builds the check.
func New(cfg map[string]any) *Check { return &Check{base: cfg} }

// Checks is the wiring constructor.
func Checks(cfg map[string]map[string]any) []check.Check { return []check.Check{New(cfg[Name])} }

func (*Check) Name() string     { return Name }
func (*Check) Tier() model.Tier { return model.TierPassive }

// Applies matches owned hostnames and URLs.
func (*Check) Applies(a model.Asset) bool {
	return (a.Kind == model.KindHostname || a.Kind == model.KindURL) && a.Scope == model.ScopeOwned
}

// targetURLs lists the URLs to request for the asset.
func targetURLs(a model.Asset, schemes []string) []string {
	if a.Kind == model.KindURL {
		return []string{a.Key}
	}
	host := checkutil.Norm(a.Key)
	out := make([]string, 0, len(schemes))
	for _, s := range schemes {
		out = append(out, s+"://"+host+"/")
	}
	return out
}

// hostOf returns the lowercase hostname (no port) of a URL string.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// Run requests each target URL once through the scoped HTTP client.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	t.Config = cfg
	opts := checkutil.FetchOpts{
		Timeout: time.Duration(checkutil.Int(cfg, "timeout_seconds", 10)) * time.Second,
		MaxBody: int64(checkutil.Int(cfg, "max_body_bytes", int(checkutil.DefaultMaxBody))),
	}
	zones := checkutil.OwnedZones(t)
	res := &check.Result{}
	var results []map[string]any
	techAll := map[string]bool{}
	seenHost := map[string]bool{checkutil.Norm(t.Asset.Key): true, hostOf(t.Asset.Key): true}

	for _, u := range targetURLs(t.Asset, checkutil.Strings(cfg, "schemes", []string{"https", "http"})) {
		r := map[string]any{"url": u}
		resp, err := checkutil.Fetch(ctx, t.HTTP, u, opts)
		if err != nil {
			r["error"] = err.Error()
			results = append(results, r)
			continue
		}
		tech := DetectTech(resp.Header, resp.Body)
		title := ExtractTitle(resp.Body)
		server := resp.Header.Get("Server")
		r["status"], r["title"], r["server"] = resp.Status, title, server
		r["final_url"], r["redirects"], r["tech"] = resp.FinalURL, resp.Hops, tech
		r["truncated"] = resp.Truncated
		results = append(results, r)
		for _, tg := range tech {
			techAll[tg] = true
		}

		zone := t.Asset.Zone
		if z := checkutil.ZoneOf(hostOf(u), zones); z != "" {
			zone = z
		}
		res.Discovered = append(res.Discovered, model.AssetInput{
			Kind: model.KindURL, Key: u, Source: checkutil.Source(Name), Zone: zone,
			Attrs: map[string]any{"live": true, "status": resp.Status, "title": title, "server": server, "tech": tech},
		})
		// In-zone redirect targets become hostname candidates.
		for _, raw := range append(hopTargets(resp.Hops), resp.FinalURL) {
			h := hostOf(raw)
			z := checkutil.ZoneOf(h, zones)
			if h == "" || z == "" || seenHost[h] {
				continue
			}
			seenHost[h] = true
			res.Discovered = append(res.Discovered, model.AssetInput{
				Kind: model.KindHostname, Key: h, Source: checkutil.Source(Name), Zone: z,
			})
		}
	}

	obs := map[string]any{"results": results}
	for _, r := range results { // headline fields from the first live response
		if _, ok := r["status"]; ok {
			for _, k := range []string{"url", "status", "title", "server", "final_url", "redirects"} {
				obs[k] = r[k]
			}
			break
		}
	}
	tech := make([]string, 0, len(techAll))
	for tg := range techAll {
		tech = append(tech, tg)
	}
	obs["tech"] = checkutil.SortedUnique(tech)
	res.Observations = append(res.Observations, model.ObservationInput{Check: Name, Data: obs})
	return res, nil
}

// hopTargets resolves each hop's Location against its URL.
func hopTargets(hops []checkutil.Hop) []string {
	var out []string
	for _, h := range hops {
		if h.Location == "" {
			continue
		}
		base, err := url.Parse(h.URL)
		if err != nil {
			continue
		}
		if ref, err := base.Parse(h.Location); err == nil {
			out = append(out, ref.String())
		}
	}
	return out
}
