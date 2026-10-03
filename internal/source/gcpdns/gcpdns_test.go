package gcpdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

var _ source.Source = (*Source)(nil)

type fakeAPI struct {
	zones   map[string][]ManagedZone // project -> zones
	rrsets  map[string][]RRSet       // project/zone -> record sets
	zoneErr map[string]error         // project -> error listing zones
	rrErr   map[string]error         // project/zone -> error listing record sets
}

func (f *fakeAPI) ListManagedZones(_ context.Context, project string) ([]ManagedZone, error) {
	if err := f.zoneErr[project]; err != nil {
		return nil, err
	}
	if _, ok := f.zones[project]; !ok {
		return nil, &APIError{Status: http.StatusNotFound, Op: "list managed zones", Message: "project not found"}
	}
	return slices.Clone(f.zones[project]), nil
}

func (f *fakeAPI) ListRRSets(_ context.Context, project, zone string) ([]RRSet, error) {
	if err := f.rrErr[project+"/"+zone]; err != nil {
		return nil, err
	}
	return slices.Clone(f.rrsets[project+"/"+zone]), nil
}

func rr(name, typ string, data ...string) RRSet {
	return RRSet{Name: name, Type: typ, TTL: 300, RRDatas: data}
}

func zone(name, dns, vis, dnssec string) ManagedZone {
	z := ManagedZone{Name: name, DNSName: dns, Visibility: vis, ID: json.Number("1000")}
	if dnssec != "" {
		z.DNSSECConfig = &DNSSECConfig{State: dnssec}
	}
	return z
}

func denied(status int) error {
	return &APIError{Status: status, Op: "list", Message: "forbidden by test"}
}

func fixture() *fakeAPI {
	return &fakeAPI{
		zones: map[string][]ManagedZone{
			"my-project-a": {
				zone("prod", "example.com.", "public", "on"),
				zone("internal", "internal.example.com.", "private", "off"),
				zone("org", "example.org.", "", "transfer"),
			},
			"my-project-b": {zone("net", "example.net.", "public", "")},
		},
		rrsets: map[string][]RRSet{
			"my-project-a/prod": {
				rr("WWW.Example.com.", "A", "192.0.2.10"),
				rr("www.example.com.", "AAAA", "2001:db8::1"),
				rr("*.example.com.", "A", "192.0.2.10"),
				rr("blog.example.com.", "CNAME", "Hosted.Example.net."),
				rr("example.com.", "NS", "ns-cloud-a1.googledomains.com."),
				rr("example.com.", "SOA", "ns-cloud-a1.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300"),
			},
			"my-project-a/internal": {rr("db.internal.example.com.", "A", "10.0.0.5")},
			"my-project-a/org":      {rr("cdn.example.org.", "CNAME", "d.example.org.", "svc-abc-uc.a.run.app.")},
			"my-project-b/net":      {rr("api.example.net.", "A", "198.51.100.7")},
		},
	}
}

func srcCfg(mut ...func(*config.SourceConfig)) config.SourceConfig {
	c := config.SourceConfig{Name: "gcp", Type: "gcpdns", Projects: []string{"my-project-a", "my-project-b"}}
	for _, m := range mut {
		m(&c)
	}
	return c
}

type logBuf struct{ bytes.Buffer }

func discoverWith(t *testing.T, f *fakeAPI, cfg config.SourceConfig) (*source.Discovery, string, error) {
	t.Helper()
	var lb logBuf
	s, err := NewWithAPI(cfg, f, slog.New(slog.NewTextHandler(&lb, nil)))
	if err != nil {
		t.Fatal(err)
	}
	d, derr := s.Discover(context.Background())
	return d, lb.String(), derr
}

func discover(t *testing.T, f *fakeAPI, mut ...func(*config.SourceConfig)) *source.Discovery {
	t.Helper()
	d, _, err := discoverWith(t, f, srcCfg(mut...))
	if err != nil {
		t.Fatal(err)
	}
	checkInvariants(t, d, "gcp")
	return d
}

// checkInvariants is the contract every source result must satisfy: source name
// stamped everywhere, no duplicate assets or relations, every relation endpoint
// is an asset, every zone has its zone asset, and Partial matches its reasons.
func checkInvariants(t *testing.T, d *source.Discovery, name string) {
	t.Helper()
	type id struct {
		k model.AssetKind
		s string
	}
	have := map[id]bool{}
	for _, a := range d.Assets {
		if a.Source != name {
			t.Errorf("asset %s/%s has source %q", a.Kind, a.Key, a.Source)
		}
		if have[id{a.Kind, a.Key}] {
			t.Errorf("duplicate asset %s/%s", a.Kind, a.Key)
		}
		have[id{a.Kind, a.Key}] = true
		if a.Key != strings.ToLower(a.Key) || strings.HasSuffix(a.Key, ".") {
			t.Errorf("asset key %q is not normalised", a.Key)
		}
		if a.Attrs != nil && len(a.Attrs) == 0 {
			t.Errorf("asset %s/%s has empty non-nil attrs", a.Kind, a.Key)
		}
	}
	seen := map[model.RelationInput]bool{}
	for _, r := range d.Relations {
		if seen[r] {
			t.Errorf("duplicate relation %+v", r)
		}
		seen[r] = true
		if !have[id{r.FromKind, r.FromKey}] || !have[id{r.ToKind, r.ToKey}] {
			t.Errorf("relation %+v references a missing asset", r)
		}
	}
	for _, z := range d.Zones {
		if z.Source != name || !have[id{model.KindZone, z.Name}] {
			t.Errorf("zone %+v has no matching zone asset", z)
		}
	}
	if d.Partial != (len(d.PartialReasons) > 0) {
		t.Errorf("Partial=%v with reasons %v", d.Partial, d.PartialReasons)
	}
}

type ak struct {
	k model.AssetKind
	s string
}

func assetSet(d *source.Discovery) map[ak]model.AssetInput {
	m := map[ak]model.AssetInput{}
	for _, a := range d.Assets {
		m[ak{a.Kind, a.Key}] = a
	}
	return m
}

func hasRel(d *source.Discovery, fk model.AssetKind, f string, tk model.AssetKind, to string, t model.RelationType) bool {
	return slices.Contains(d.Relations, model.RelationInput{FromKind: fk, FromKey: f, ToKind: tk, ToKey: to, Type: t})
}

func zoneNames(d *source.Discovery) []string {
	var out []string
	for _, z := range d.Zones {
		out = append(out, z.Name)
	}
	return out
}

func TestDiscoverPublicZonesAcrossProjects(t *testing.T) {
	d := discover(t, fixture())
	if got := zoneNames(d); !slices.Equal(got, []string{"example.com", "example.net", "example.org"}) {
		t.Fatalf("zones (private skipped, both projects scanned): %v", got)
	}
	if d.Partial {
		t.Errorf("unexpectedly partial: %v", d.PartialReasons)
	}
	as := assetSet(d)
	for _, want := range []ak{
		{model.KindZone, "example.com"}, {model.KindHostname, "www.example.com"}, {model.KindHostname, "*.example.com"},
		{model.KindIP, "192.0.2.10"}, {model.KindIP, "2001:db8::1"}, {model.KindHostname, "hosted.example.net"},
		{model.KindHostname, "cdn.example.org"}, {model.KindHostname, "api.example.net"}, {model.KindIP, "198.51.100.7"},
	} {
		if _, ok := as[want]; !ok {
			t.Errorf("missing asset %+v", want)
		}
	}
	for _, leaked := range []ak{{model.KindIP, "10.0.0.5"}, {model.KindHostname, "db.internal.example.com"}, {model.KindZone, "internal.example.com"}} {
		if _, ok := as[leaked]; ok {
			t.Errorf("private zone leaked: %+v", leaked)
		}
	}

	// hostnames sit in their own zone, targets of other names have none
	for key, zone := range map[string]string{"www.example.com": "example.com", "*.example.com": "example.com", "cdn.example.org": "example.org", "api.example.net": "example.net"} {
		if got := as[ak{model.KindHostname, key}].Zone; got != zone {
			t.Errorf("%s zone = %q, want %q", key, got, zone)
		}
		if !hasRel(d, model.KindHostname, key, model.KindZone, zone, model.RelInZone) {
			t.Errorf("missing in_zone relation for %s", key)
		}
	}
	if got := as[ak{model.KindHostname, "hosted.example.net"}].Zone; got != "" {
		t.Errorf("a CNAME target must not be claimed by the zone, zone = %q", got)
	}
	if !hasRel(d, model.KindHostname, "www.example.com", model.KindIP, "2001:db8::1", model.RelResolvesTo) ||
		!hasRel(d, model.KindHostname, "blog.example.com", model.KindHostname, "hosted.example.net", model.RelCNAMETo) {
		t.Errorf("relations missing: %+v", d.Relations)
	}
	if as[ak{model.KindHostname, "www.example.com"}].Attrs["managed_zone"] != "prod" {
		t.Errorf("hostname attrs: %+v", as[ak{model.KindHostname, "www.example.com"}].Attrs)
	}
}

func TestZoneAttrsIncludeDNSSEC(t *testing.T) {
	d := discover(t, fixture())
	as := assetSet(d)
	for zone, want := range map[string]string{"example.com": "on", "example.org": "transfer"} {
		if got := as[ak{model.KindZone, zone}].Attrs["dnssec"]; got != want {
			t.Errorf("%s dnssec = %v, want %s", zone, got, want)
		}
	}
	if _, ok := as[ak{model.KindZone, "example.net"}].Attrs["dnssec"]; ok {
		t.Error("a zone without dnssecConfig must not claim a DNSSEC state")
	}
	za := as[ak{model.KindZone, "example.com"}]
	if za.Zone != "example.com" || za.Attrs["project"] != "my-project-a" || za.Attrs["managed_zone"] != "prod" ||
		za.Attrs["visibility"] != "public" || za.Attrs["zone_id"] != "1000" {
		t.Errorf("zone attrs: %+v", za)
	}
	// "off" is reported as such
	f := fixture()
	f.zones["my-project-a"][0].DNSSECConfig.State = "OFF"
	if got := assetSet(discover(t, f))[ak{model.KindZone, "example.com"}].Attrs["dnssec"]; got != "off" {
		t.Errorf("dnssec = %v, want off", got)
	}
}

func TestEveryRecordType(t *testing.T) {
	f := &fakeAPI{
		zones: map[string][]ManagedZone{"my-project-a": {zone("prod", "example.com.", "public", "")}},
		rrsets: map[string][]RRSet{"my-project-a/prod": {
			rr("example.com.", "NS", "ns1.example.net.", "ns2.example.net."),
			rr("example.com.", "SOA", "ns1.example.net. admin.example.net. 1 2 3 4 5"),
			rr("example.com.", "MX", "10 mail.example.com.", "20 mail2.example.com."),
			rr("example.com.", "TXT", `"v=spf1 -all"`),
			rr("example.com.", "CAA", `0 issue "letsencrypt.org"`),
			rr("_sip._tcp.example.com.", "SRV", "10 5 5060 sip.example.com."),
			rr("sub.example.com.", "NS", "ns1.other.example.", "ns2.other.example."),
			rr("v4.example.com.", "A", "192.0.2.1", "192.0.2.2"),
			rr("v6.example.com.", "AAAA", "2001:db8::2", "::ffff:192.0.2.3"),
			rr("alias.example.com.", "CNAME", "Target.Example.ORG."),
		}},
	}
	d := discover(t, f)
	as := assetSet(d)
	types := func(host string) []string {
		ts, _ := as[ak{model.KindHostname, host}].Attrs["record_types"].([]string)
		return ts
	}
	for host, want := range map[string][]string{
		"example.com":           {"CAA", "MX", "NS", "SOA", "TXT"},
		"_sip._tcp.example.com": {"SRV"},
		"sub.example.com":       {"NS"},
		"v4.example.com":        {"A"},
		"v6.example.com":        {"AAAA"},
		"alias.example.com":     {"CNAME"},
	} {
		if got := types(host); !slices.Equal(got, want) {
			t.Errorf("%s record_types = %v, want %v", host, got, want)
		}
	}
	for host, ips := range map[string][]string{
		"v4.example.com": {"192.0.2.1", "192.0.2.2"},
		"v6.example.com": {"2001:db8::2", "192.0.2.3"}, // IPv4-mapped IPv6 is unmapped
	} {
		for _, ip := range ips {
			if !hasRel(d, model.KindHostname, host, model.KindIP, ip, model.RelResolvesTo) {
				t.Errorf("missing %s resolves_to %s", host, ip)
			}
		}
	}
	if !hasRel(d, model.KindHostname, "alias.example.com", model.KindHostname, "target.example.org", model.RelCNAMETo) {
		t.Error("CNAME target must be lower-cased and dot-stripped")
	}
	// records that are not addresses or CNAMEs add no assets of their own
	for _, a := range d.Assets {
		if a.Kind == model.KindHostname && (strings.Contains(a.Key, "mail") || strings.Contains(a.Key, "ns1")) {
			t.Errorf("unexpected hostname asset %q from a non-address record", a.Key)
		}
	}
}

func TestUnparsableAddressIsSkippedNotFatal(t *testing.T) {
	f := fixture()
	f.rrsets["my-project-a/prod"] = []RRSet{rr("bad.example.com.", "A", "not-an-ip", "192.0.2.9")}
	d, logs, err := discoverWith(t, f, srcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if !hasRel(d, model.KindHostname, "bad.example.com", model.KindIP, "192.0.2.9", model.RelResolvesTo) {
		t.Error("the valid address must still be discovered")
	}
	if !strings.Contains(logs, "unparsable address") {
		t.Errorf("expected a warning, logs: %s", logs)
	}
}

func TestWildcardHandling(t *testing.T) {
	f := fixture()
	f.rrsets["my-project-a/prod"] = []RRSet{
		rr("*.example.com.", "A", "192.0.2.10"),
		rr(`\052.example.com.`, "A", "192.0.2.11"), // escaped spelling of the same name
		rr("*.app.example.com.", "CNAME", "lb.example.net."),
	}
	d := discover(t, f)
	as := assetSet(d)
	n := 0
	for _, a := range d.Assets {
		if a.Kind == model.KindHostname && a.Key == "*.example.com" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("wildcard hostname must appear once, got %d", n)
	}
	for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		if !hasRel(d, model.KindHostname, "*.example.com", model.KindIP, ip, model.RelResolvesTo) {
			t.Errorf("wildcard must resolve to %s", ip)
		}
	}
	if as[ak{model.KindHostname, "*.app.example.com"}].Zone != "example.com" ||
		!hasRel(d, model.KindHostname, "*.app.example.com", model.KindHostname, "lb.example.net", model.RelCNAMETo) {
		t.Errorf("wildcard CNAME: %+v", as[ak{model.KindHostname, "*.app.example.com"}])
	}
}

func TestRoutingPolicyContributesEveryTarget(t *testing.T) {
	ilb := func(ip, region string) InternalLoadBalancer {
		return InternalLoadBalancer{IPAddress: ip, IPProtocol: "tcp", Port: "443", LoadBalancerType: "regionalL4ilb", Project: "my-project-a", Region: region}
	}
	f := fixture()
	f.rrsets["my-project-a/prod"] = []RRSet{
		{Name: "wrr.example.com.", Type: "A", RoutingPolicy: &RoutingPolicy{WRR: &WRRPolicy{Items: []PolicyItem{
			{RRDatas: []string{"192.0.2.1"}},
			{RRDatas: []string{"192.0.2.2", "192.0.2.3"}},
			{HealthCheckedTargets: &HealthCheckedTargets{ExternalEndpoints: []string{"198.51.100.4"}}},
		}}}},
		{Name: "geo.example.com.", Type: "A", RoutingPolicy: &RoutingPolicy{Geo: &GeoPolicy{Items: []PolicyItem{
			{Location: "us-east1", RRDatas: []string{"192.0.2.10"}},
			{Location: "europe-west1", RRDatas: []string{"192.0.2.11"}},
			{Location: "asia-east1", HealthCheckedTargets: &HealthCheckedTargets{InternalLoadBalancers: []InternalLoadBalancer{ilb("10.1.0.5", "asia-east1")}}},
		}}}},
		{Name: "fail.example.com.", Type: "A", RoutingPolicy: &RoutingPolicy{PrimaryBackup: &PrimaryBackupPolicy{
			PrimaryTargets:   &HealthCheckedTargets{InternalLoadBalancers: []InternalLoadBalancer{ilb("10.2.0.5", "us-east1")}},
			BackupGeoTargets: &GeoPolicy{Items: []PolicyItem{{Location: "us", RRDatas: []string{"192.0.2.20"}}, {Location: "eu", RRDatas: []string{"192.0.2.21"}}}},
		}}},
		{Name: "cname.example.com.", Type: "CNAME", RoutingPolicy: &RoutingPolicy{WRR: &WRRPolicy{Items: []PolicyItem{
			{RRDatas: []string{"a.example.net."}}, {RRDatas: []string{"b.example.net."}},
		}}}},
		{Name: "mixed.example.com.", Type: "A", RRDatas: []string{"192.0.2.30"},
			RoutingPolicy: &RoutingPolicy{WRR: &WRRPolicy{Items: []PolicyItem{{RRDatas: []string{"192.0.2.30"}}, {RRDatas: []string{"192.0.2.31"}}}}}},
	}
	d := discover(t, f)
	for host, ips := range map[string][]string{
		"wrr.example.com":   {"192.0.2.1", "192.0.2.2", "192.0.2.3", "198.51.100.4"},
		"geo.example.com":   {"192.0.2.10", "192.0.2.11", "10.1.0.5"},
		"fail.example.com":  {"10.2.0.5", "192.0.2.20", "192.0.2.21"},
		"mixed.example.com": {"192.0.2.30", "192.0.2.31"},
	} {
		for _, ip := range ips {
			if !hasRel(d, model.KindHostname, host, model.KindIP, ip, model.RelResolvesTo) {
				t.Errorf("%s must resolve to %s", host, ip)
			}
		}
	}
	for _, target := range []string{"a.example.net", "b.example.net"} {
		if !hasRel(d, model.KindHostname, "cname.example.com", model.KindHostname, target, model.RelCNAMETo) {
			t.Errorf("cname.example.com must point at %s", target)
		}
	}

	// internal load balancers become cloud resources that expose their address
	as := assetSet(d)
	key := "gcp:ilb:my-project-a:asia-east1:10.1.0.5"
	cr, ok := as[ak{model.KindCloudResource, key}]
	if !ok {
		t.Fatalf("missing load balancer cloud resource %q", key)
	}
	if cr.Attrs["provider"] != "gcp" || cr.Attrs["resource_type"] != "load_balancer" || cr.Attrs["internal"] != true ||
		cr.Attrs["gcp.region"] != "asia-east1" || cr.Attrs["gcp.project"] != "my-project-a" || cr.Attrs["type"] != "regionalL4ilb" {
		t.Errorf("cloud resource attrs: %+v", cr.Attrs)
	}
	if !hasRel(d, model.KindCloudResource, key, model.KindIP, "10.1.0.5", model.RelExposes) {
		t.Error("load balancer must expose its address")
	}
}

func TestClassifyTargets(t *testing.T) {
	f := fixture()
	f.rrsets["my-project-a/prod"] = []RRSet{
		rr("run.example.com.", "CNAME", "svc-abc-uc.a.run.app."),
		rr("plain.example.com.", "CNAME", "host.example.net."),
	}
	as := assetSet(discover(t, f))
	if got := as[ak{model.KindHostname, "svc-abc-uc.a.run.app"}].Attrs["alias_target_type"]; got != "cloud_run" {
		t.Errorf("target type = %v", got)
	}
	if got := as[ak{model.KindHostname, "run.example.com"}].Attrs["alias_target_type"]; got != "cloud_run" {
		t.Errorf("host alias_target_type = %v", got)
	}
	if _, ok := as[ak{model.KindHostname, "host.example.net"}].Attrs["alias_target_type"]; ok {
		t.Error("a third-party target must not be classified")
	}
	for in, want := range map[string]string{
		"svc-abc-uc.a.run.app.": "cloud_run", "proj.appspot.com": "app_engine", "ghs.googlehosted.com.": "google_hosted",
		"c.storage.googleapis.com": "gcs", "storage.googleapis.com": "gcs", "us-central1-p.cloudfunctions.net": "cloud_functions",
		"p.web.app": "firebase", "p.firebaseapp.com": "firebase", "example.net": "", "notrun.app": "",
	} {
		if got := ClassifyTarget(in); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

func TestIncludePrivate(t *testing.T) {
	d := discover(t, fixture(), func(c *config.SourceConfig) { c.IncludePrivate = true })
	if got := zoneNames(d); !slices.Equal(got, []string{"example.com", "example.net", "example.org", "internal.example.com"}) {
		t.Fatalf("zones: %v", got)
	}
	as := assetSet(d)
	if as[ak{model.KindZone, "internal.example.com"}].Attrs["visibility"] != "private" {
		t.Errorf("private zone not labelled: %+v", as[ak{model.KindZone, "internal.example.com"}].Attrs)
	}
	if !hasRel(d, model.KindHostname, "db.internal.example.com", model.KindIP, "10.0.0.5", model.RelResolvesTo) {
		t.Error("private records must be discovered when include_private is set")
	}
}

func TestPrivateZoneNeverShadowsPublicZone(t *testing.T) {
	f := fixture()
	f.zones["my-project-b"] = append(f.zones["my-project-b"], zone("split", "example.com.", "private", ""))
	f.rrsets["my-project-b/split"] = []RRSet{rr("www.example.com.", "A", "10.9.9.9")}
	d := discover(t, f, func(c *config.SourceConfig) { c.IncludePrivate = true })
	if hasRel(d, model.KindHostname, "www.example.com", model.KindIP, "10.9.9.9", model.RelResolvesTo) {
		t.Error("split-horizon private records must not be merged into the public zone")
	}
	if got := assetSet(d)[ak{model.KindZone, "example.com"}].Attrs["visibility"]; got != "public" {
		t.Errorf("zone visibility = %v", got)
	}
}

func TestPeeringZonesAreSkipped(t *testing.T) {
	f := fixture()
	peer := zone("peer", "peer.example.com.", "private", "")
	peer.PeeringConfig = json.RawMessage(`{"targetNetwork":{"networkUrl":"x"}}`)
	f.zones["my-project-a"] = append(f.zones["my-project-a"], peer)
	d := discover(t, f, func(c *config.SourceConfig) { c.IncludePrivate = true })
	if slices.Contains(zoneNames(d), "peer.example.com") {
		t.Error("peering zones serve no records and must be skipped")
	}
}

func TestZoneAllowList(t *testing.T) {
	for name, tc := range map[string]struct {
		zones []string
		want  []string
	}{
		"by managed zone name":       {[]string{"prod"}, []string{"example.com"}},
		"by dns name":                {[]string{"example.org"}, []string{"example.org"}},
		"dns name with dot and case": {[]string{"Example.NET."}, []string{"example.net"}},
		"mixed":                      {[]string{"prod", "example.net"}, []string{"example.com", "example.net"}},
		"unknown entry matches none": {[]string{"nope"}, nil},
		"empty means all":            {nil, []string{"example.com", "example.net", "example.org"}},
	} {
		t.Run(name, func(t *testing.T) {
			d := discover(t, fixture(), func(c *config.SourceConfig) { c.Zones = tc.zones })
			if got := zoneNames(d); !slices.Equal(got, tc.want) {
				t.Errorf("zones = %v, want %v", got, tc.want)
			}
			if tc.zones != nil && tc.want != nil {
				for _, a := range d.Assets {
					if a.Kind == model.KindHostname && a.Zone != "" && !slices.Contains(tc.want, a.Zone) {
						t.Errorf("record from excluded zone %q leaked: %s", a.Zone, a.Key)
					}
				}
			}
		})
	}
}

func TestAllowListCannotExposePrivateZones(t *testing.T) {
	d := discover(t, fixture(), func(c *config.SourceConfig) { c.Zones = []string{"internal"} })
	if len(d.Zones) != 0 {
		t.Errorf("an allow-listed private zone is still private without include_private: %v", zoneNames(d))
	}
}

func reversed(f *fakeAPI) *fakeAPI {
	g := &fakeAPI{zones: map[string][]ManagedZone{}, rrsets: map[string][]RRSet{}}
	for k, v := range f.zones {
		c := slices.Clone(v)
		slices.Reverse(c)
		g.zones[k] = c
	}
	for k, v := range f.rrsets {
		c := slices.Clone(v)
		slices.Reverse(c)
		g.rrsets[k] = c
	}
	return g
}

func TestOutputIsDeterministic(t *testing.T) {
	f := fixture()
	f.rrsets["my-project-a/prod"] = append(f.rrsets["my-project-a/prod"],
		RRSet{Name: "multi.example.com.", Type: "A", RoutingPolicy: &RoutingPolicy{WRR: &WRRPolicy{Items: []PolicyItem{
			{RRDatas: []string{"192.0.2.9"}}, {RRDatas: []string{"192.0.2.8"}}, {RRDatas: []string{"192.0.2.7"}}}}}})
	a, _, err := discoverWith(t, f, srcCfg(func(c *config.SourceConfig) { c.IncludePrivate = true }))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := discoverWith(t, reversed(f), srcCfg(func(c *config.SourceConfig) {
		c.IncludePrivate = true
		slices.Reverse(c.Projects)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("output depends on API/config order:\n%+v\n%+v", a, b)
	}
	if !slices.IsSorted(zoneNames(a)[:3]) {
		t.Errorf("public zones must be sorted: %v", zoneNames(a))
	}
}

func TestDuplicatesAreMerged(t *testing.T) {
	f := fixture()
	// the same public zone name in two projects, and the same record twice
	f.zones["my-project-b"] = append(f.zones["my-project-b"], zone("prod-copy", "example.com.", "public", ""))
	f.rrsets["my-project-b/prod-copy"] = []RRSet{
		rr("www.example.com.", "A", "192.0.2.10"),
		rr("WWW.EXAMPLE.COM.", "A", "192.0.2.10", "192.0.2.10"),
	}
	d := discover(t, f)
	zn, www, ip := 0, 0, 0
	for _, a := range d.Assets {
		switch {
		case a.Kind == model.KindZone && a.Key == "example.com":
			zn++
		case a.Kind == model.KindHostname && a.Key == "www.example.com":
			www++
		case a.Kind == model.KindIP && a.Key == "192.0.2.10":
			ip++
		}
	}
	if zn != 1 || www != 1 || ip != 1 || len(d.Zones) != 3 {
		t.Errorf("zone=%d www=%d ip=%d zones=%v", zn, www, ip, zoneNames(d))
	}
	if got := assetSet(d)[ak{model.KindZone, "example.com"}].Attrs["project"]; got != "my-project-a" {
		t.Errorf("first project (sorted) must own the zone asset, got %v", got)
	}
}

func TestDuplicateProjectsScannedOnce(t *testing.T) {
	d := discover(t, fixture(), func(c *config.SourceConfig) { c.Projects = []string{"my-project-b", "my-project-a", "my-project-b"} })
	if len(d.Zones) != 3 {
		t.Errorf("zones = %v", zoneNames(d))
	}
}

func TestPartialDiscovery(t *testing.T) {
	t.Run("project forbidden", func(t *testing.T) {
		f := fixture()
		f.zoneErr = map[string]error{"my-project-b": denied(http.StatusForbidden)}
		d := discover(t, f)
		if !d.Partial || len(d.PartialReasons) != 1 {
			t.Fatalf("want partial with one reason, got %v %v", d.Partial, d.PartialReasons)
		}
		r := d.PartialReasons[0]
		for _, want := range []string{"my-project-b", "403", "dns.managedZones.list", "roles/dns.reader", "forbidden by test"} {
			if !strings.Contains(r, want) {
				t.Errorf("reason %q lacks %q", r, want)
			}
		}
		if got := zoneNames(d); !slices.Equal(got, []string{"example.com", "example.org"}) {
			t.Errorf("the rest must still be returned, zones = %v", got)
		}
	})
	t.Run("project not found", func(t *testing.T) {
		f := fixture()
		delete(f.zones, "my-project-b")
		d := discover(t, f)
		if !d.Partial || !strings.Contains(d.PartialReasons[0], "my-project-b") || !strings.Contains(d.PartialReasons[0], "404") {
			t.Fatalf("partial=%v reasons=%v", d.Partial, d.PartialReasons)
		}
		if len(d.Zones) != 2 {
			t.Errorf("zones = %v", zoneNames(d))
		}
	})
	t.Run("zone rrsets cannot be listed", func(t *testing.T) {
		for status, e := range map[string]error{
			"403":       denied(http.StatusForbidden),
			"404":       denied(http.StatusNotFound),
			"503":       &APIError{Status: 503, Op: "list record sets", Message: "unavailable"},
			"transport": errors.New("connection reset"),
		} {
			f := fixture()
			f.rrErr = map[string]error{"my-project-a/org": e}
			d := discover(t, f)
			if !d.Partial || len(d.PartialReasons) != 1 {
				t.Fatalf("%s: want partial, got %v %v", status, d.Partial, d.PartialReasons)
			}
			r := d.PartialReasons[0]
			for _, want := range []string{"org", "my-project-a", "dns.resourceRecordSets.list", "roles/dns.reader"} {
				if !strings.Contains(r, want) {
					t.Errorf("%s: reason %q lacks %q", status, r, want)
				}
			}
			as := assetSet(d)
			if _, ok := as[ak{model.KindHostname, "www.example.com"}]; !ok {
				t.Errorf("%s: the other zones must still be returned", status)
			}
			if _, ok := as[ak{model.KindZone, "example.org"}]; !ok {
				t.Errorf("%s: the zone itself is known and must still be reported", status)
			}
			if _, ok := as[ak{model.KindHostname, "cdn.example.org"}]; ok {
				t.Errorf("%s: no records can come from the zone that failed", status)
			}
		}
	})
	t.Run("several failures are all reported", func(t *testing.T) {
		f := fixture()
		f.zoneErr = map[string]error{"my-project-b": denied(http.StatusForbidden)}
		f.rrErr = map[string]error{"my-project-a/prod": denied(http.StatusForbidden)}
		d := discover(t, f)
		if len(d.PartialReasons) != 2 {
			t.Fatalf("reasons: %v", d.PartialReasons)
		}
	})
}

func TestHardFailuresReturnNoDiscovery(t *testing.T) {
	for name, tc := range map[string]struct {
		f    func() *fakeAPI
		want string
	}{
		"every project denied": {func() *fakeAPI {
			f := fixture()
			f.zoneErr = map[string]error{"my-project-a": denied(403), "my-project-b": denied(403)}
			return f
		}, "no project could be listed"},
		"the only project is missing": {func() *fakeAPI { return &fakeAPI{} }, "no project could be listed"},
		"server error listing zones": {func() *fakeAPI {
			f := fixture()
			f.zoneErr = map[string]error{"my-project-a": &APIError{Status: 500, Op: "list", Message: "boom"}}
			return f
		}, "my-project-a"},
		"transport error listing zones": {func() *fakeAPI {
			f := fixture()
			f.zoneErr = map[string]error{"my-project-b": errors.New("connection refused")}
			return f
		}, "connection refused"},
		"credentials fail while listing zones": {func() *fakeAPI {
			f := fixture()
			f.zoneErr = map[string]error{"my-project-a": &CredentialsError{Op: "list", Message: "no ADC"}}
			return f
		}, "credentials"},
		"credentials rejected while listing records": {func() *fakeAPI {
			f := fixture()
			f.rrErr = map[string]error{"my-project-a/prod": &APIError{Status: 401, Op: "list", Message: "expired"}}
			return f
		}, "401"},
	} {
		t.Run(name, func(t *testing.T) {
			d, _, err := discoverWith(t, tc.f(), srcCfg())
			if err == nil || d != nil {
				t.Fatalf("want error and nil discovery, got %v %v", d, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q lacks %q", err, tc.want)
			}
		})
	}
}

func TestCancelledContextIsAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := fixture()
	f.zoneErr = map[string]error{"my-project-a": ctx.Err()}
	s, _ := NewWithAPI(srcCfg(), f, slog.New(slog.DiscardHandler))
	if d, err := s.Discover(ctx); err == nil || d != nil {
		t.Fatalf("want error, got %v %v", d, err)
	}
}

func TestNewRequiresProjects(t *testing.T) {
	if _, err := NewWithAPI(config.SourceConfig{Name: "gcp", Type: "gcpdns"}, &fakeAPI{}, nil); err == nil {
		t.Fatal("projects is required")
	}
	s, err := NewWithAPI(srcCfg(), &fakeAPI{}, nil)
	if err != nil || s.Name() != "gcp" || s.Type() != "gcpdns" {
		t.Fatalf("name/type: %v %v", s, err)
	}
}

// newSourceThroughHTTP wires the real Client, over httptest, into the Source.
func newSourceThroughHTTP(t *testing.T, h http.Handler, log *slog.Logger, mut ...func(*config.SourceConfig)) *Source {
	t.Helper()
	c, _ := testClient(t, h)
	s, err := NewWithAPI(srcCfg(mut...), c, log)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEndToEndOverHTTP(t *testing.T) {
	s := newSourceThroughHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dns/v1/projects/my-project-a/managedZones":
			_, _ = fmt.Fprint(w, `{"managedZones":[
				{"name":"prod","dnsName":"example.com.","id":"42","visibility":"public","dnssecConfig":{"state":"on"}},
				{"name":"priv","dnsName":"corp.example.com.","visibility":"private"}]}`)
		case "/dns/v1/projects/my-project-a/managedZones/prod/rrsets":
			_, _ = fmt.Fprint(w, `{"rrsets":[
				{"name":"www.example.com.","type":"A","ttl":300,"rrdatas":["192.0.2.10"]},
				{"name":"lb.example.com.","type":"A","routingPolicy":{"geo":{"items":[
					{"location":"us","rrdatas":["192.0.2.1"]},{"location":"eu","rrdatas":["192.0.2.2"]}]}}}]}`)
		default:
			http.NotFound(w, r)
		}
	}), nil, func(c *config.SourceConfig) { c.Projects = []string{"my-project-a"} })
	d, err := s.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	checkInvariants(t, d, "gcp")
	if got := zoneNames(d); !slices.Equal(got, []string{"example.com"}) {
		t.Fatalf("zones = %v", got)
	}
	for _, ip := range []string{"192.0.2.10"} {
		if !hasRel(d, model.KindHostname, "www.example.com", model.KindIP, ip, model.RelResolvesTo) {
			t.Errorf("missing %s", ip)
		}
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if !hasRel(d, model.KindHostname, "lb.example.com", model.KindIP, ip, model.RelResolvesTo) {
			t.Errorf("geo target %s not discovered", ip)
		}
	}
	if assetSet(d)[ak{model.KindZone, "example.com"}].Attrs["dnssec"] != "on" || assetSet(d)[ak{model.KindZone, "example.com"}].Attrs["zone_id"] != "42" {
		t.Errorf("zone attrs: %+v", assetSet(d)[ak{model.KindZone, "example.com"}].Attrs)
	}
}

func TestCredentialsNeverReachErrorsLogsOrWarnings(t *testing.T) {
	// A hostile or buggy upstream echoes the bearer token back in its errors.
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, `{"error":{"code":403,"message":"denied for %s on %s"}}`, r.Header.Get("Authorization"), fakeToken)
	})
	check := func(t *testing.T, label, text string) {
		t.Helper()
		if strings.Contains(text, fakeToken) || strings.Contains(text, "ya29.") {
			t.Errorf("%s leaks the credential: %s", label, text)
		}
	}

	t.Run("partial warning and log", func(t *testing.T) {
		var lb logBuf
		two := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/rrsets") {
				echo(w, r)
				return
			}
			if strings.Contains(r.URL.Path, "my-project-b") {
				echo(w, r)
				return
			}
			_, _ = fmt.Fprint(w, `{"managedZones":[{"name":"prod","dnsName":"example.com."}]}`)
		})
		s := newSourceThroughHTTP(t, two, slog.New(slog.NewTextHandler(&lb, &slog.HandlerOptions{Level: slog.LevelDebug})))
		d, err := s.Discover(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !d.Partial || len(d.PartialReasons) != 2 {
			t.Fatalf("want 2 reasons, got %v", d.PartialReasons)
		}
		check(t, "warning", strings.Join(d.PartialReasons, "; "))
		check(t, "log", lb.String())
		if !strings.Contains(strings.Join(d.PartialReasons, ";"), "[REDACTED]") {
			t.Errorf("expected the token to be replaced, got %v", d.PartialReasons)
		}
	})
	t.Run("hard error", func(t *testing.T) {
		var lb logBuf
		s := newSourceThroughHTTP(t, echo, slog.New(slog.NewTextHandler(&lb, nil)))
		d, err := s.Discover(context.Background())
		if err == nil || d != nil {
			t.Fatalf("every project denied must be an error, got %v %v", d, err)
		}
		check(t, "error", err.Error())
		check(t, "log", lb.String())
	})
}

func TestRealClientRetriesInsideDiscover(t *testing.T) {
	var zoneCalls int
	s := newSourceThroughHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/managedZones") {
			zoneCalls++
			if zoneCalls == 1 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			_, _ = fmt.Fprint(w, `{"managedZones":[{"name":"prod","dnsName":"example.com."}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"rrsets":[{"name":"a.example.com.","type":"A","rrdatas":["192.0.2.1"]}]}`)
	}), nil, func(c *config.SourceConfig) { c.Projects = []string{"my-project-a"} })
	start := time.Now()
	d, err := s.Discover(context.Background())
	if err != nil || d.Partial || zoneCalls != 2 {
		t.Fatalf("err=%v partial=%v zoneCalls=%d", err, d != nil && d.Partial, zoneCalls)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("Retry-After must be capped by the client")
	}
}
