// Package aws inventories the public surface of an AWS account: Elastic IPs and
// public EC2 addresses, internet-facing ELBv2 load balancers, their listeners
// and open-to-world security group rules, and CloudFront distributions. It
// only discovers; judging exposure is the job of checks.
package aws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

// EC2API is the subset of the EC2 client used by the source.
type EC2API interface {
	DescribeAddresses(ctx context.Context, in *ec2.DescribeAddressesInput, opts ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
	ec2.DescribeInstancesAPIClient
	ec2.DescribeNetworkInterfacesAPIClient
	ec2.DescribeSecurityGroupsAPIClient
}

// ELBAPI is the subset of the ELBv2 client used by the source.
type ELBAPI interface {
	elasticloadbalancingv2.DescribeLoadBalancersAPIClient
	elasticloadbalancingv2.DescribeListenersAPIClient
}

// CloudFrontAPI is the subset of the CloudFront client used by the source.
type CloudFrontAPI interface {
	cloudfront.ListDistributionsAPIClient
}

// Clients are the per-region service clients.
type Clients struct {
	EC2 EC2API
	ELB ELBAPI
}

// Source implements source.Source for AWS.
type Source struct {
	name     string
	regions  []string
	regional func(region string) Clients
	cf       CloudFrontAPI // nil disables CloudFront
	log      *slog.Logger
}

// NewWithAPI builds a Source around explicit clients (used by tests).
func NewWithAPI(name string, regions []string, regional func(string) Clients, cf CloudFrontAPI, log *slog.Logger) *Source {
	if log == nil {
		log = slog.Default()
	}
	return &Source{name: name, regions: regions, regional: regional, cf: cf, log: log}
}

// Regions resolves the configured region list: regions, else region, else
// us-east-1, de-duplicated.
func Regions(cfg config.SourceConfig) []string {
	var in []string
	switch {
	case len(cfg.Regions) > 0:
		in = cfg.Regions
	case cfg.Region != "":
		in = []string{cfg.Region}
	default:
		in = []string{"us-east-1"}
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// New builds a Source from config using the AWS default credential chain.
func New(cfg config.SourceConfig, log *slog.Logger) (source.Source, error) {
	regions := Regions(cfg)
	load := func(region string) (aws.Config, error) {
		opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
		if cfg.Profile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Profile))
		}
		c, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
		if err != nil {
			return c, fmt.Errorf("aws %q: load aws config for %s: %w", cfg.Name, region, err)
		}
		if cfg.RoleARN != "" {
			c.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(c), cfg.RoleARN))
		}
		return c, nil
	}
	clients := map[string]Clients{}
	for _, r := range regions {
		c, err := load(r)
		if err != nil {
			return nil, err
		}
		clients[r] = Clients{
			EC2: ec2.NewFromConfig(c, func(o *ec2.Options) {
				if cfg.Endpoint != "" {
					o.BaseEndpoint = aws.String(cfg.Endpoint)
				}
			}),
			ELB: elasticloadbalancingv2.NewFromConfig(c, func(o *elasticloadbalancingv2.Options) {
				if cfg.Endpoint != "" {
					o.BaseEndpoint = aws.String(cfg.Endpoint)
				}
			}),
		}
	}
	cfc, err := load("us-east-1") // CloudFront is global
	if err != nil {
		return nil, err
	}
	cf := cloudfront.NewFromConfig(cfc, func(o *cloudfront.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	})
	return NewWithAPI(cfg.Name, regions, func(r string) Clients { return clients[r] }, cf, log), nil
}

// Constructor matches the registry constructor signature.
func Constructor(cfg config.SourceConfig, _ config.ScopeConfig, _ func(string) string, log *slog.Logger) (source.Source, error) {
	return New(cfg, log)
}

// Name returns the configured instance name.
func (s *Source) Name() string { return s.name }

// Type returns "aws".
func (s *Source) Type() string { return "aws" }

func isAccessDenied(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "UnauthorizedOperation", "AccessDenied", "AccessDeniedException", "UnauthorizedAccess":
			return true
		}
	}
	return false
}

// fail wraps an upstream error; permission errors name the IAM action to grant.
func (s *Source) fail(where, action string, err error) error {
	if isAccessDenied(err) {
		return fmt.Errorf("aws %q: %s: access denied calling %s: grant the IAM permission %s: %w", s.name, where, action, action, err)
	}
	return fmt.Errorf("aws %q: %s: %s: %w", s.name, where, action, err)
}

// Discover inventories every configured region plus CloudFront. Any failure of
// a required call aborts with an error and no partial result.
func (s *Source) Discover(ctx context.Context) (*source.Discovery, error) {
	b := newBuilder(s.name)
	for _, region := range s.regions {
		cl := s.regional(region)
		sgOpen, err := s.discoverEC2(ctx, b, region, cl.EC2)
		if err != nil {
			return nil, err
		}
		if err := s.discoverELB(ctx, b, region, cl.ELB, sgOpen); err != nil {
			return nil, err
		}
	}
	if s.cf != nil {
		if err := s.discoverCloudFront(ctx, b); err != nil {
			return nil, err
		}
	}
	return b.result(), nil
}

// ---- EC2 ----

func nameTag(tags []ec2types.Tag) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == "Name" {
			return aws.ToString(t.Value)
		}
	}
	return ""
}

// openFor returns the open-to-world ingress rules of the given security groups.
func openFor(sgOpen map[string][]any, ids []string) []any {
	out := []any{}
	for _, id := range ids {
		out = append(out, sgOpen[id]...)
	}
	return out
}

// discoverEC2 records public EC2 addresses and returns, per security group id,
// its ingress rules open to the world (used for EC2 and ELB resources alike).
func (s *Source) discoverEC2(ctx context.Context, b *builder, region string, api EC2API) (map[string][]any, error) {
	where := "region " + region
	sgOpen := map[string][]any{}
	sp := ec2.NewDescribeSecurityGroupsPaginator(api, &ec2.DescribeSecurityGroupsInput{})
	for sp.HasMorePages() {
		out, err := sp.NextPage(ctx)
		if err != nil {
			return nil, s.fail(where, "ec2:DescribeSecurityGroups", err)
		}
		for _, g := range out.SecurityGroups {
			id := aws.ToString(g.GroupId)
			sgOpen[id] = append(sgOpen[id], openIngress(id, g.IpPermissions)...)
		}
	}

	type eni struct {
		instance string
		sgs      []string
	}
	enis := map[string]eni{}
	np := ec2.NewDescribeNetworkInterfacesPaginator(api, &ec2.DescribeNetworkInterfacesInput{})
	for np.HasMorePages() {
		out, err := np.NextPage(ctx)
		if err != nil {
			return nil, s.fail(where, "ec2:DescribeNetworkInterfaces", err)
		}
		for _, n := range out.NetworkInterfaces {
			id := aws.ToString(n.NetworkInterfaceId)
			e := eni{}
			if n.Attachment != nil {
				e.instance = aws.ToString(n.Attachment.InstanceId)
			}
			for _, g := range n.Groups {
				e.sgs = append(e.sgs, aws.ToString(g.GroupId))
			}
			enis[id] = e
			if n.Association == nil || aws.ToString(n.Association.PublicIp) == "" || aws.ToBool(n.RequesterManaged) {
				continue // not public, or AWS-managed (ELB/NAT; covered by the ELB and EIP paths)
			}
			ipKey, ok := normIP(aws.ToString(n.Association.PublicIp))
			if !ok {
				continue
			}
			owner, name := aws.ToString(n.OwnerId), nameTag(n.TagSet)
			rk := fmt.Sprintf("aws:ec2:%s:%s", region, id)
			b.asset(model.KindIP, ipKey, map[string]any{
				"owned": true, "aws.account": owner, "aws.region": region,
				"aws.resource_id": id, "aws.name": name, "association": "network_interface",
				"security_groups": toAny(e.sgs),
			})
			b.asset(model.KindCloudResource, rk, map[string]any{
				"aws.account": owner, "aws.region": region, "aws.resource_id": id, "aws.name": name,
				"resource_type": "network_interface", "public_ip": ipKey,
				"security_groups": toAny(e.sgs), "open_ingress": openFor(sgOpen, e.sgs),
			})
			b.rel(model.KindCloudResource, rk, model.KindIP, ipKey, model.RelExposes)
		}
	}

	ip := ec2.NewDescribeInstancesPaginator(api, &ec2.DescribeInstancesInput{})
	for ip.HasMorePages() {
		out, err := ip.NextPage(ctx)
		if err != nil {
			return nil, s.fail(where, "ec2:DescribeInstances", err)
		}
		for _, r := range out.Reservations {
			for _, in := range r.Instances {
				if in.State != nil && in.State.Name == ec2types.InstanceStateNameTerminated {
					continue
				}
				id := aws.ToString(in.InstanceId)
				pub := []string{aws.ToString(in.PublicIpAddress)}
				for _, ni := range in.NetworkInterfaces {
					if ni.Association != nil {
						pub = append(pub, aws.ToString(ni.Association.PublicIp))
					}
				}
				var keys []string
				for _, p := range pub {
					if k, ok := normIP(p); ok && !contains(keys, k) {
						keys = append(keys, k)
					}
				}
				if len(keys) == 0 {
					continue
				}
				var sgs []string
				for _, g := range in.SecurityGroups {
					sgs = append(sgs, aws.ToString(g.GroupId))
				}
				acct, name := aws.ToString(r.OwnerId), nameTag(in.Tags)
				rk := fmt.Sprintf("aws:ec2:%s:%s", region, id)
				b.asset(model.KindCloudResource, rk, map[string]any{
					"aws.account": acct, "aws.region": region, "aws.resource_id": id, "aws.name": name,
					"resource_type": "instance", "public_ips": toAny(keys),
					"security_groups": toAny(sgs), "open_ingress": openFor(sgOpen, sgs),
				})
				for _, k := range keys {
					b.asset(model.KindIP, k, map[string]any{
						"owned": true, "aws.account": acct, "aws.region": region,
						"aws.resource_id": id, "aws.name": name, "association": "instance",
						"security_groups": toAny(sgs),
					})
					b.rel(model.KindCloudResource, rk, model.KindIP, k, model.RelExposes)
				}
			}
		}
	}

	// Elastic IPs last so associations can be resolved against the ENI map.
	addrs, err := api.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, s.fail(where, "ec2:DescribeAddresses", err)
	}
	for _, a := range addrs.Addresses {
		k, ok := normIP(aws.ToString(a.PublicIp))
		if !ok {
			continue
		}
		assoc, target := "unassociated", ""
		if id := aws.ToString(a.InstanceId); id != "" {
			assoc, target = "instance", id
		} else if id := aws.ToString(a.NetworkInterfaceId); id != "" {
			assoc, target = "network_interface", id
		}
		var sgs []string
		if e, ok := enis[aws.ToString(a.NetworkInterfaceId)]; ok {
			sgs = e.sgs
			if e.instance != "" {
				assoc, target = "instance", e.instance
			}
		}
		attrs := map[string]any{
			"owned": true, "aws.region": region, "aws.resource_id": aws.ToString(a.AllocationId),
			"aws.name": nameTag(a.Tags), "association": assoc, "elastic_ip": true,
			"security_groups": toAny(sgs),
		}
		if acct := aws.ToString(a.NetworkInterfaceOwnerId); acct != "" {
			attrs["aws.account"] = acct
		}
		if target != "" {
			attrs["associated_resource"] = target
		}
		b.asset(model.KindIP, k, attrs)
		if target != "" {
			b.relIfAsset(model.KindCloudResource, fmt.Sprintf("aws:ec2:%s:%s", region, target), model.KindIP, k, model.RelExposes)
		}
	}
	return sgOpen, nil
}

func openIngress(sg string, perms []ec2types.IpPermission) []any {
	var out []any
	for _, p := range perms {
		proto := aws.ToString(p.IpProtocol)
		if proto == "-1" {
			proto = "all"
		}
		add := func(cidr string) {
			e := map[string]any{"sg": sg, "protocol": proto, "cidr": cidr}
			if p.FromPort != nil {
				e["from_port"] = int(*p.FromPort)
			}
			if p.ToPort != nil {
				e["to_port"] = int(*p.ToPort)
			}
			out = append(out, e)
		}
		for _, r := range p.IpRanges {
			if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
				add("0.0.0.0/0")
			}
		}
		for _, r := range p.Ipv6Ranges {
			if aws.ToString(r.CidrIpv6) == "::/0" {
				add("::/0")
			}
		}
	}
	return out
}

// ---- ELBv2 ----

func (s *Source) discoverELB(ctx context.Context, b *builder, region string, api ELBAPI, sgOpen map[string][]any) error {
	where := "region " + region
	lp := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(api, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	for lp.HasMorePages() {
		out, err := lp.NextPage(ctx)
		if err != nil {
			return s.fail(where, "elasticloadbalancing:DescribeLoadBalancers", err)
		}
		for _, lb := range out.LoadBalancers {
			dns := strings.ToLower(strings.TrimSuffix(aws.ToString(lb.DNSName), "."))
			if dns == "" {
				continue
			}
			arn := aws.ToString(lb.LoadBalancerArn)
			internal := lb.Scheme != elbtypes.LoadBalancerSchemeEnumInternetFacing
			rk := fmt.Sprintf("aws:elbv2:%s:%s", region, aws.ToString(lb.LoadBalancerName))
			common := map[string]any{
				"aws.account": accountFromARN(arn), "aws.region": region, "aws.name": aws.ToString(lb.LoadBalancerName),
				"type": string(lb.Type), "arn": arn, "scheme": string(lb.Scheme), "vpc": aws.ToString(lb.VpcId),
				"security_groups": toAny(lb.SecurityGroups), "internal": internal,
			}
			if internal {
				// Recorded for completeness; not public, so never owned and no listeners.
				b.asset(model.KindHostname, dns, copyAttrs(common))
				b.asset(model.KindCloudResource, rk, withAttr(common, "resource_type", "load_balancer"))
				b.rel(model.KindCloudResource, rk, model.KindHostname, dns, model.RelExposes)
				continue
			}
			var listeners []any
			plainHTTP := false
			type ls struct {
				port  int
				proto string
			}
			var lss []ls
			dp := elasticloadbalancingv2.NewDescribeListenersPaginator(api, &elasticloadbalancingv2.DescribeListenersInput{LoadBalancerArn: lb.LoadBalancerArn})
			for dp.HasMorePages() {
				lo, err := dp.NextPage(ctx)
				if err != nil {
					return s.fail(where, "elasticloadbalancing:DescribeListeners", err)
				}
				for _, l := range lo.Listeners {
					action := ""
					if len(l.DefaultActions) > 0 {
						action = string(l.DefaultActions[0].Type)
					}
					port := int(aws.ToInt32(l.Port))
					listeners = append(listeners, map[string]any{"port": port, "protocol": string(l.Protocol), "default_action": action})
					lss = append(lss, ls{port, string(l.Protocol)})
					if l.Protocol == elbtypes.ProtocolEnumHttp {
						plainHTTP = true
					}
				}
			}
			if listeners == nil {
				listeners = []any{}
			}
			ha := copyAttrs(common)
			ha["owned"] = true
			ha["listeners"] = listeners
			ha["has_http_listener"] = plainHTTP
			b.asset(model.KindHostname, dns, ha)
			ra := withAttr(common, "resource_type", "load_balancer")
			ra["lb_dns"] = dns
			ra["listeners"] = listeners
			ra["has_http_listener"] = plainHTTP
			ra["open_ingress"] = openFor(sgOpen, lb.SecurityGroups)
			b.asset(model.KindCloudResource, rk, ra)
			b.rel(model.KindCloudResource, rk, model.KindHostname, dns, model.RelExposes)
			for _, l := range lss {
				sk := fmt.Sprintf("%s:%d/tcp", dns, l.port)
				b.asset(model.KindService, sk, map[string]any{"owned": true, "protocol": l.proto, "port": l.port})
				b.rel(model.KindHostname, dns, model.KindService, sk, model.RelExposes)
			}
		}
	}
	return nil
}

// ---- CloudFront ----

func (s *Source) discoverCloudFront(ctx context.Context, b *builder) error {
	p := cloudfront.NewListDistributionsPaginator(s.cf, &cloudfront.ListDistributionsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			if isAccessDenied(err) {
				s.log.Warn("aws: skipping CloudFront, access denied; grant cloudfront:ListDistributions to inventory it", "source", s.name, "error", err)
				b.skip("cloudfront skipped (access denied)")
				return nil
			}
			return s.fail("cloudfront", "cloudfront:ListDistributions", err)
		}
		if out.DistributionList == nil {
			continue
		}
		for _, d := range out.DistributionList.Items {
			dom := strings.ToLower(strings.TrimSuffix(aws.ToString(d.DomainName), "."))
			if dom == "" {
				continue
			}
			id := aws.ToString(d.Id)
			var aliases []string
			if d.Aliases != nil {
				for _, a := range d.Aliases.Items {
					if n := strings.ToLower(strings.TrimSuffix(a, ".")); n != "" {
						aliases = append(aliases, n)
					}
				}
			}
			arn := aws.ToString(d.ARN)
			common := map[string]any{
				"aws.account": accountFromARN(arn), "aws.resource_id": id, "arn": arn,
				"enabled": aws.ToBool(d.Enabled), "aliases": toAny(aliases), "cloudfront": true,
			}
			b.asset(model.KindHostname, dom, withAttr(common, "owned", true))
			rk := "aws:cloudfront:" + id
			b.asset(model.KindCloudResource, rk, withAttr(common, "resource_type", "cloudfront_distribution"))
			b.rel(model.KindCloudResource, rk, model.KindHostname, dom, model.RelExposes)
			for _, a := range aliases {
				b.asset(model.KindHostname, a, map[string]any{"owned": true, "cloudfront_distribution": id})
				b.rel(model.KindHostname, dom, model.KindHostname, a, model.RelServes)
			}
			if d.Origins == nil {
				continue
			}
			for _, o := range d.Origins.Items {
				host := strings.ToLower(strings.TrimSuffix(aws.ToString(o.DomainName), "."))
				if host == "" {
					continue
				}
				attrs := map[string]any{"cloudfront_origin": true, "origin_id": aws.ToString(o.Id)}
				if o.S3OriginConfig != nil || strings.Contains(host, ".s3.") || strings.Contains(host, ".s3-") {
					attrs["origin_type"] = "s3"
				}
				if k, ok := normIP(host); ok {
					b.asset(model.KindIP, k, attrs)
					b.rel(model.KindIP, k, model.KindHostname, dom, model.RelOriginOf)
				} else {
					b.asset(model.KindHostname, host, attrs)
					b.rel(model.KindHostname, host, model.KindHostname, dom, model.RelOriginOf)
				}
			}
		}
	}
	return nil
}

// ---- helpers ----

func normIP(v string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		return "", false
	}
	return a.Unmap().String(), true
}

func accountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 4 {
		return parts[4]
	}
	return ""
}

func toAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func copyAttrs(m map[string]any) map[string]any {
	o := make(map[string]any, len(m)+2)
	for k, v := range m {
		o[k] = v
	}
	return o
}

func withAttr(m map[string]any, k string, v any) map[string]any {
	o := copyAttrs(m)
	o[k] = v
	return o
}

type builder struct {
	source   string
	assets   map[string]*model.AssetInput
	order    []string
	rels     map[model.RelationInput]bool
	relOrder []model.RelationInput
	partial  []string
}

// skip records a feature that could not be read (access denied), making the
// discovery partial.
func (b *builder) skip(reason string) { b.partial = append(b.partial, reason) }

func newBuilder(src string) *builder {
	return &builder{source: src, assets: map[string]*model.AssetInput{}, rels: map[model.RelationInput]bool{}}
}

func assetID(kind model.AssetKind, key string) string { return string(kind) + "\x00" + key }

// asset upserts; the first writer of an attribute wins, except that owned=true
// is sticky so an owned classification is never lost to a later merge.
func (b *builder) asset(kind model.AssetKind, key string, attrs map[string]any) {
	id := assetID(kind, key)
	a, ok := b.assets[id]
	if !ok {
		a = &model.AssetInput{Kind: kind, Key: key, Source: b.source, Attrs: map[string]any{}}
		b.assets[id] = a
		b.order = append(b.order, id)
	}
	for k, v := range attrs {
		if _, exists := a.Attrs[k]; !exists || (k == "owned" && v == true) {
			a.Attrs[k] = v
		}
	}
}

func (b *builder) rel(fk model.AssetKind, fkey string, tk model.AssetKind, tkey string, t model.RelationType) {
	r := model.RelationInput{FromKind: fk, FromKey: fkey, ToKind: tk, ToKey: tkey, Type: t}
	if !b.rels[r] {
		b.rels[r] = true
		b.relOrder = append(b.relOrder, r)
	}
}

// relIfAsset adds the relation only when the from-asset exists.
func (b *builder) relIfAsset(fk model.AssetKind, fkey string, tk model.AssetKind, tkey string, t model.RelationType) {
	if _, ok := b.assets[assetID(fk, fkey)]; ok {
		b.rel(fk, fkey, tk, tkey, t)
	}
}

func (b *builder) result() *source.Discovery {
	d := &source.Discovery{Relations: b.relOrder, Partial: len(b.partial) > 0, PartialReasons: b.partial}
	ids := append([]string(nil), b.order...)
	sort.Strings(ids)
	for _, id := range ids {
		d.Assets = append(d.Assets, *b.assets[id])
	}
	return d
}
