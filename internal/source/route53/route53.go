// Package route53 discovers hosted zones, record sets and alias targets from
// AWS Route 53.
package route53

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	sdkroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

// API is the subset of the Route 53 client used by the source. It is
// satisfied by *route53.Client and by test fakes.
type API interface {
	sdkroute53.ListHostedZonesAPIClient
	sdkroute53.ListResourceRecordSetsAPIClient
}

// Source implements source.Source for Route 53.
type Source struct {
	name string
	api  API
	log  *slog.Logger
}

// NewWithAPI builds a Source around an explicit API (used by tests).
func NewWithAPI(name string, api API, log *slog.Logger) *Source {
	if log == nil {
		log = slog.Default()
	}
	return &Source{name: name, api: api, log: log}
}

// New builds a Source from config using the AWS default credential chain.
func New(cfg config.SourceConfig, log *slog.Logger) (source.Source, error) {
	region := cfg.Region
	if region == "" {
		region = "us-east-1" // Route 53 is a global service
	}
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if cfg.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Profile))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("route53 %q: load aws config: %w", cfg.Name, err)
	}
	if cfg.RoleARN != "" {
		awsCfg.Credentials = aws.NewCredentialsCache(
			stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsCfg), cfg.RoleARN))
	}
	client := sdkroute53.NewFromConfig(awsCfg, func(o *sdkroute53.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	})
	return NewWithAPI(cfg.Name, client, log), nil
}

// Constructor matches the registry constructor signature.
func Constructor(cfg config.SourceConfig, _ config.ScopeConfig, _ func(string) string, log *slog.Logger) (source.Source, error) {
	return New(cfg, log)
}

// Name returns the configured instance name.
func (s *Source) Name() string { return s.name }

// Type returns "route53".
func (s *Source) Type() string { return "route53" }

// Discover lists every public hosted zone and its record sets. Any API failure
// aborts with an error and no partial result.
func (s *Source) Discover(ctx context.Context) (*source.Discovery, error) {
	b := newBuilder(s.name)

	zp := sdkroute53.NewListHostedZonesPaginator(s.api, &sdkroute53.ListHostedZonesInput{})
	var zones []types.HostedZone
	for zp.HasMorePages() {
		out, err := zp.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("route53 %q: list hosted zones: %w", s.name, err)
		}
		zones = append(zones, out.HostedZones...)
	}

	for _, z := range zones {
		zoneName := normalizeName(aws.ToString(z.Name))
		if z.Config != nil && z.Config.PrivateZone {
			s.log.Info("route53: skipping private hosted zone", "source", s.name, "zone", zoneName, "id", aws.ToString(z.Id))
			continue
		}
		zoneID := strings.TrimPrefix(aws.ToString(z.Id), "/hostedzone/")
		b.addZone(zoneName, zoneID)

		rp := sdkroute53.NewListResourceRecordSetsPaginator(s.api, &sdkroute53.ListResourceRecordSetsInput{HostedZoneId: z.Id})
		for rp.HasMorePages() {
			out, err := rp.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("route53 %q: list record sets for zone %s: %w", s.name, zoneName, err)
			}
			for _, rr := range out.ResourceRecordSets {
				b.addRecordSet(zoneName, zoneID, rr, s.log)
			}
		}
	}
	return b.result(), nil
}

type builder struct {
	source   string
	zones    []source.Zone
	zoneSeen map[string]bool
	assets   map[string]*model.AssetInput
	order    []string
	rels     map[model.RelationInput]bool
	relOrder []model.RelationInput
	rtypes   map[string]map[string]bool
}

func newBuilder(src string) *builder {
	return &builder{
		source: src, zoneSeen: map[string]bool{}, assets: map[string]*model.AssetInput{},
		rels: map[model.RelationInput]bool{}, rtypes: map[string]map[string]bool{},
	}
}

func assetID(kind model.AssetKind, key string) string { return string(kind) + "\x00" + key }

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

func (b *builder) addZone(name, id string) {
	if b.zoneSeen[name] {
		return
	}
	b.zoneSeen[name] = true
	b.zones = append(b.zones, source.Zone{Name: name, Source: b.source})
	b.asset(model.KindZone, name, name, map[string]any{"hosted_zone_id": id})
}

func (b *builder) noteType(host, rtype string) {
	m := b.rtypes[host]
	if m == nil {
		m = map[string]bool{}
		b.rtypes[host] = m
	}
	m[rtype] = true
}

func (b *builder) addRecordSet(zone, zoneID string, rr types.ResourceRecordSet, log *slog.Logger) {
	name := normalizeName(aws.ToString(rr.Name))
	if name == "" {
		return
	}
	host := b.asset(model.KindHostname, name, zone, map[string]any{"hosted_zone_id": zoneID})
	b.noteType(name, string(rr.Type))
	b.rel(model.KindHostname, name, model.KindZone, zone, model.RelInZone)

	if rr.AliasTarget != nil {
		target := normalizeName(aws.ToString(rr.AliasTarget.DNSName))
		if target == "" {
			return
		}
		tt := ClassifyAliasTarget(target)
		b.asset(model.KindHostname, target, "", map[string]any{"alias_target_type": tt})
		b.rel(model.KindHostname, name, model.KindHostname, target, model.RelAliasTo)
		// The alias record carries the classification too so checks can
		// reason from either end.
		host.Attrs["alias_target"] = target
		host.Attrs["alias_target_type"] = tt
		return
	}

	for _, v := range rr.ResourceRecords {
		val := aws.ToString(v.Value)
		switch rr.Type {
		case types.RRTypeA, types.RRTypeAaaa:
			addr, err := netip.ParseAddr(strings.TrimSpace(val))
			if err != nil {
				log.Warn("route53: skipping unparsable address", "name", name, "value", val)
				continue
			}
			key := addr.Unmap().String()
			b.asset(model.KindIP, key, "", nil)
			b.rel(model.KindHostname, name, model.KindIP, key, model.RelResolvesTo)
		case types.RRTypeCname:
			target := normalizeName(val)
			if target == "" {
				continue
			}
			b.asset(model.KindHostname, target, "", nil)
			b.rel(model.KindHostname, name, model.KindHostname, target, model.RelCNAMETo)
		}
	}
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
	return d
}

var octalEscape = regexp.MustCompile(`\\([0-7]{3})`)

// normalizeName lowercases, strips the trailing dot and decodes Route 53's
// \ddd octal escapes (notably \052 for "*").
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

// ClassifyAliasTarget names the AWS service behind an alias target DNS name so
// dangling-DNS checks can reason about takeover surface.
func ClassifyAliasTarget(dns string) string {
	d := normalizeName(dns)
	switch {
	case strings.HasSuffix(d, ".elb.amazonaws.com") || strings.HasSuffix(d, ".elb.amazonaws.com.cn"):
		return "elb"
	case strings.HasSuffix(d, ".cloudfront.net"):
		return "cloudfront"
	case strings.HasSuffix(d, ".amazonaws.com") && (strings.HasPrefix(d, "s3-website") || strings.Contains(d, ".s3-website")):
		return "s3_website"
	case strings.Contains(d, ".execute-api.") && strings.HasSuffix(d, ".amazonaws.com"):
		return "apigateway"
	case strings.HasSuffix(d, ".awsglobalaccelerator.com"):
		return "globalaccelerator"
	case strings.HasSuffix(d, ".elasticbeanstalk.com"):
		return "elasticbeanstalk"
	case strings.HasSuffix(d, ".vpce.amazonaws.com"):
		return "vpc_endpoint"
	case strings.HasSuffix(d, ".s3.amazonaws.com") || (strings.HasPrefix(d, "s3.") && strings.HasSuffix(d, ".amazonaws.com")):
		return "s3"
	}
	return "other"
}
