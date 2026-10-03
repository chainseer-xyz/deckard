package gcpdns

import (
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

func assetID(kind model.AssetKind, key string) string { return string(kind) + "\x00" + key }

// builder accumulates and de-duplicates assets and relations, in first-seen
// order, so the same name or address in many records yields one merged asset.
type builder struct {
	source   string
	zones    []source.Zone
	zoneSeen map[string]bool
	assets   map[string]*model.AssetInput
	order    []string
	rels     map[model.RelationInput]bool
	relOrder []model.RelationInput
	rtypes   map[string]map[string]bool
	partial  []string
	log      *slog.Logger
}

func newBuilder(src string, log *slog.Logger) *builder {
	return &builder{
		source: src, zoneSeen: map[string]bool{}, assets: map[string]*model.AssetInput{},
		rels: map[model.RelationInput]bool{}, rtypes: map[string]map[string]bool{}, log: log,
	}
}

// skip records something that could not be read, making the discovery partial.
func (b *builder) skip(reason string) { b.partial = append(b.partial, reason) }

func (b *builder) asset(kind model.AssetKind, key, zone string, attrs map[string]any) *model.AssetInput {
	id := assetID(kind, key)
	a, ok := b.assets[id]
	if !ok {
		a = &model.AssetInput{Kind: kind, Key: key, Source: b.source, Zone: zone, Attrs: map[string]any{}}
		b.assets[id] = a
		b.order = append(b.order, id)
	}
	if a.Zone == "" {
		a.Zone = zone
	}
	for k, v := range attrs {
		if _, exists := a.Attrs[k]; !exists {
			a.Attrs[k] = v
		}
	}
	return a
}

func (b *builder) rel(fk model.AssetKind, fkey string, tk model.AssetKind, tkey string, t model.RelationType) {
	r := model.RelationInput{FromKind: fk, FromKey: fkey, ToKind: tk, ToKey: tkey, Type: t}
	if !b.rels[r] {
		b.rels[r] = true
		b.relOrder = append(b.relOrder, r)
	}
}

func (b *builder) addZone(name string, attrs map[string]any) {
	if b.zoneSeen[name] {
		return
	}
	b.zoneSeen[name] = true
	b.zones = append(b.zones, source.Zone{Name: name, Source: b.source})
	b.asset(model.KindZone, name, name, attrs)
}

func (b *builder) noteType(host, rtype string) {
	m := b.rtypes[host]
	if m == nil {
		m = map[string]bool{}
		b.rtypes[host] = m
	}
	m[rtype] = true
}

// answer is every value an RRSet can resolve to, across all routing branches.
type answer struct {
	data      []string
	balancers []InternalLoadBalancer
}

func (a *answer) targets(t *HealthCheckedTargets) {
	if t == nil {
		return
	}
	a.data = append(a.data, t.ExternalEndpoints...)
	a.balancers = append(a.balancers, t.InternalLoadBalancers...)
}

func (a *answer) items(items []PolicyItem) {
	for _, it := range items {
		a.data = append(a.data, it.RRDatas...)
		a.targets(it.HealthCheckedTargets)
	}
}

// collect gathers the plain rrdatas and every routing-policy target. Values
// are returned sorted and de-duplicated so output never depends on API order.
func collect(rs RRSet) answer {
	a := answer{data: slices.Clone(rs.RRDatas)}
	if rp := rs.RoutingPolicy; rp != nil {
		if rp.WRR != nil {
			a.items(rp.WRR.Items)
		}
		if rp.Geo != nil {
			a.items(rp.Geo.Items)
		}
		if pb := rp.PrimaryBackup; pb != nil {
			a.targets(pb.PrimaryTargets)
			if pb.BackupGeoTargets != nil {
				a.items(pb.BackupGeoTargets.Items)
			}
		}
	}
	for i := range a.data {
		a.data[i] = strings.TrimSpace(a.data[i])
	}
	sort.Strings(a.data)
	a.data = slices.Compact(a.data)
	sort.Slice(a.balancers, func(i, j int) bool { return balancerKey(a.balancers[i], "") < balancerKey(a.balancers[j], "") })
	a.balancers = slices.CompactFunc(a.balancers, func(x, y InternalLoadBalancer) bool { return x == y })
	return a
}

func balancerKey(lb InternalLoadBalancer, project string) string {
	if lb.Project != "" {
		project = lb.Project
	}
	return fmt.Sprintf("gcp:ilb:%s:%s:%s", project, lb.Region, lb.IPAddress)
}

func (b *builder) addRRSet(zone, managedZone, project string, rs RRSet) {
	name := normalizeName(rs.Name)
	if name == "" {
		return
	}
	rtype := strings.ToUpper(rs.Type)
	host := b.asset(model.KindHostname, name, zone, map[string]any{"managed_zone": managedZone})
	b.noteType(name, rtype)
	b.rel(model.KindHostname, name, model.KindZone, zone, model.RelInZone)

	ans := collect(rs)
	switch rtype {
	case "A", "AAAA":
		for _, val := range ans.data {
			b.addAddress(name, val)
		}
		for _, lb := range ans.balancers {
			b.addBalancer(name, project, lb)
		}
	case "CNAME":
		for _, val := range ans.data {
			target := normalizeName(val)
			if target == "" {
				continue
			}
			var attrs map[string]any
			if tt := ClassifyTarget(target); tt != "" {
				attrs = map[string]any{"alias_target_type": tt}
				if _, ok := host.Attrs["alias_target"]; !ok {
					host.Attrs["alias_target"], host.Attrs["alias_target_type"] = target, tt
				}
			}
			b.asset(model.KindHostname, target, "", attrs)
			b.rel(model.KindHostname, name, model.KindHostname, target, model.RelCNAMETo)
		}
	}
}

func (b *builder) addAddress(host, val string) string {
	addr, err := netip.ParseAddr(val)
	if err != nil {
		b.log.Warn("gcpdns: skipping unparsable address", "name", host, "value", val)
		return ""
	}
	key := addr.Unmap().String()
	b.asset(model.KindIP, key, "", nil)
	b.rel(model.KindHostname, host, model.KindIP, key, model.RelResolvesTo)
	return key
}

// addBalancer records an internal load balancer a routing policy answers
// with. Like the aws source's internal ELBs it is kept for completeness: the
// address is private, so it is never owned and never probed.
func (b *builder) addBalancer(host, project string, lb InternalLoadBalancer) {
	ip := b.addAddress(host, strings.TrimSpace(lb.IPAddress))
	if ip == "" {
		return
	}
	lb.IPAddress = ip
	rk := balancerKey(lb, project)
	if lb.Project != "" {
		project = lb.Project
	}
	b.asset(model.KindCloudResource, rk, "", map[string]any{
		"provider": "gcp", "resource_type": "load_balancer", "internal": true,
		"gcp.project": project, "gcp.region": lb.Region, "type": lb.LoadBalancerType,
		"ip_protocol": lb.IPProtocol, "port": lb.Port,
	})
	b.rel(model.KindCloudResource, rk, model.KindIP, ip, model.RelExposes)
}

func (b *builder) result() *source.Discovery {
	d := &source.Discovery{Zones: b.zones, Relations: b.relOrder}
	for _, id := range b.order {
		a := b.assets[id]
		if a.Kind == model.KindHostname {
			if m := b.rtypes[a.Key]; len(m) > 0 {
				ts := make([]string, 0, len(m))
				for t := range m {
					ts = append(ts, t)
				}
				sort.Strings(ts)
				a.Attrs["record_types"] = ts
			}
		}
		if len(a.Attrs) == 0 {
			a.Attrs = nil
		}
		d.Assets = append(d.Assets, *a)
	}
	d.Partial, d.PartialReasons = len(b.partial) > 0, b.partial
	return d
}

var octalEscape = regexp.MustCompile(`\\([0-7]{3})`)

// normalizeName lowercases, strips the trailing dot and decodes \ddd octal
// escapes, so a wildcard is "*.example.com" however the API spells it.
func normalizeName(n string) string {
	n = octalEscape.ReplaceAllStringFunc(n, func(m string) string {
		v, err := strconv.ParseUint(m[1:], 8, 8)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
}

// ClassifyTarget names the Google service behind a CNAME target so
// dangling-DNS checks can reason about takeover surface. It returns "" for
// anything that is not a Google-hosted endpoint.
func ClassifyTarget(dns string) string {
	d := normalizeName(dns)
	switch {
	case strings.HasSuffix(d, ".run.app"):
		return "cloud_run"
	case strings.HasSuffix(d, ".appspot.com"):
		return "app_engine"
	case d == "ghs.googlehosted.com" || strings.HasSuffix(d, ".googlehosted.com"):
		return "google_hosted"
	case d == "storage.googleapis.com" || strings.HasSuffix(d, ".storage.googleapis.com"):
		return "gcs"
	case strings.HasSuffix(d, ".cloudfunctions.net"):
		return "cloud_functions"
	case strings.HasSuffix(d, ".web.app") || strings.HasSuffix(d, ".firebaseapp.com"):
		return "firebase"
	}
	return ""
}
