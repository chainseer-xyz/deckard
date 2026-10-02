package aws

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/smithy-go"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

var _ source.Source = (*Source)(nil)

const acct = "111122223333"

func page(tok *string) int {
	if tok == nil {
		return 0
	}
	n, _ := strconv.Atoi(*tok)
	return n
}

func next(end, total int) *string {
	if end < total {
		return aws.String(strconv.Itoa(end))
	}
	return nil
}

type fakeEC2 struct {
	sgs       []ec2types.SecurityGroup
	enis      []ec2types.NetworkInterface
	instances []ec2types.Reservation
	addrs     []ec2types.Address
	pageSize  int
	errs      map[string]error // by op name
}

func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, in *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if e := f.errs["sg"]; e != nil {
		return nil, e
	}
	s := page(in.NextToken)
	end := min(s+f.pageSize, len(f.sgs))
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.sgs[s:end], NextToken: next(end, len(f.sgs))}, nil
}

func (f *fakeEC2) DescribeNetworkInterfaces(_ context.Context, in *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	if e := f.errs["eni"]; e != nil {
		return nil, e
	}
	s := page(in.NextToken)
	end := min(s+f.pageSize, len(f.enis))
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: f.enis[s:end], NextToken: next(end, len(f.enis))}, nil
}

func (f *fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if e := f.errs["inst"]; e != nil {
		return nil, e
	}
	s := page(in.NextToken)
	end := min(s+f.pageSize, len(f.instances))
	return &ec2.DescribeInstancesOutput{Reservations: f.instances[s:end], NextToken: next(end, len(f.instances))}, nil
}

func (f *fakeEC2) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	if e := f.errs["addr"]; e != nil {
		return nil, e
	}
	return &ec2.DescribeAddressesOutput{Addresses: f.addrs}, nil
}

type fakeELB struct {
	lbs       []elbtypes.LoadBalancer
	listeners map[string][]elbtypes.Listener
	pageSize  int
	errs      map[string]error
	lcalls    int
}

func (f *fakeELB) DescribeLoadBalancers(_ context.Context, in *elasticloadbalancingv2.DescribeLoadBalancersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	if e := f.errs["lb"]; e != nil {
		return nil, e
	}
	s := page(in.Marker)
	end := min(s+f.pageSize, len(f.lbs))
	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{LoadBalancers: f.lbs[s:end], NextMarker: next(end, len(f.lbs))}, nil
}

func (f *fakeELB) DescribeListeners(_ context.Context, in *elasticloadbalancingv2.DescribeListenersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
	f.lcalls++
	if e := f.errs["listener"]; e != nil {
		return nil, e
	}
	ls := f.listeners[aws.ToString(in.LoadBalancerArn)]
	s := page(in.Marker)
	end := min(s+f.pageSize, len(ls))
	return &elasticloadbalancingv2.DescribeListenersOutput{Listeners: ls[s:end], NextMarker: next(end, len(ls))}, nil
}

type fakeCF struct {
	dists    []cftypes.DistributionSummary
	pageSize int
	err      error
}

func (f *fakeCF) ListDistributions(_ context.Context, in *cloudfront.ListDistributionsInput, _ ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	s := page(in.Marker)
	end := min(s+f.pageSize, len(f.dists))
	dl := &cftypes.DistributionList{Items: f.dists[s:end], IsTruncated: aws.Bool(end < len(f.dists))}
	if end < len(f.dists) {
		dl.NextMarker = aws.String(strconv.Itoa(end))
	}
	return &cloudfront.ListDistributionsOutput{DistributionList: dl}, nil
}

func denied(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: "not authorized"}
}

func newSrc(regional map[string]Clients, cf CloudFrontAPI, regions ...string) *Source {
	return NewWithAPI("aws-test", regions, func(r string) Clients { return regional[r] }, cf, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func find(t *testing.T, d *source.Discovery, kind model.AssetKind, key string) model.AssetInput {
	t.Helper()
	for _, a := range d.Assets {
		if a.Kind == kind && a.Key == key {
			return a
		}
	}
	t.Fatalf("asset %s %q not found", kind, key)
	return model.AssetInput{}
}

func has(d *source.Discovery, kind model.AssetKind, key string) bool {
	for _, a := range d.Assets {
		if a.Kind == kind && a.Key == key {
			return true
		}
	}
	return false
}

func hasRel(d *source.Discovery, fk model.AssetKind, fkey string, tk model.AssetKind, tkey string, typ model.RelationType) bool {
	for _, r := range d.Relations {
		if r.FromKind == fk && r.FromKey == fkey && r.ToKind == tk && r.ToKey == tkey && r.Type == typ {
			return true
		}
	}
	return false
}

func s(v string) *string { return aws.String(v) }

func baseEC2(pageSize int) *fakeEC2 {
	return &fakeEC2{
		pageSize: pageSize,
		sgs: []ec2types.SecurityGroup{
			{GroupId: s("sg-open"), IpPermissions: []ec2types.IpPermission{
				{IpProtocol: s("tcp"), FromPort: aws.Int32(22), ToPort: aws.Int32(22), IpRanges: []ec2types.IpRange{{CidrIp: s("0.0.0.0/0")}}},
				{IpProtocol: s("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443), Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: s("::/0")}}},
				{IpProtocol: s("-1"), IpRanges: []ec2types.IpRange{{CidrIp: s("0.0.0.0/0")}}},
				{IpProtocol: s("tcp"), FromPort: aws.Int32(3306), ToPort: aws.Int32(3306), IpRanges: []ec2types.IpRange{{CidrIp: s("10.0.0.0/8")}}},
			}},
			{GroupId: s("sg-closed"), IpPermissions: []ec2types.IpPermission{
				{IpProtocol: s("tcp"), FromPort: aws.Int32(80), ToPort: aws.Int32(80), IpRanges: []ec2types.IpRange{{CidrIp: s("198.51.100.0/24")}}},
			}},
		},
		instances: []ec2types.Reservation{
			{OwnerId: s(acct), Instances: []ec2types.Instance{{
				InstanceId: s("i-pub"), PublicIpAddress: s("203.0.113.10"),
				Tags:           []ec2types.Tag{{Key: s("Name"), Value: s("web-1")}},
				SecurityGroups: []ec2types.GroupIdentifier{{GroupId: s("sg-open")}},
				State:          &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
			}}},
			{OwnerId: s(acct), Instances: []ec2types.Instance{{
				InstanceId: s("i-priv"), SecurityGroups: []ec2types.GroupIdentifier{{GroupId: s("sg-closed")}},
				State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
			}}},
			{OwnerId: s(acct), Instances: []ec2types.Instance{{
				InstanceId: s("i-dead"), PublicIpAddress: s("203.0.113.99"),
				State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameTerminated},
			}}},
		},
		enis: []ec2types.NetworkInterface{
			{NetworkInterfaceId: s("eni-pub"), OwnerId: s(acct), Association: &ec2types.NetworkInterfaceAssociation{PublicIp: s("203.0.113.20")},
				Groups: []ec2types.GroupIdentifier{{GroupId: s("sg-open")}}},
			{NetworkInterfaceId: s("eni-priv"), OwnerId: s(acct)},
			{NetworkInterfaceId: s("eni-elb"), OwnerId: s(acct), RequesterManaged: aws.Bool(true),
				Association: &ec2types.NetworkInterfaceAssociation{PublicIp: s("203.0.113.77")}},
		},
		addrs: []ec2types.Address{
			{PublicIp: s("203.0.113.10"), AllocationId: s("eipalloc-1"), InstanceId: s("i-pub"), NetworkInterfaceId: s("eni-x")},
			{PublicIp: s("203.0.113.30"), AllocationId: s("eipalloc-2"), Tags: []ec2types.Tag{{Key: s("Name"), Value: s("spare")}}},
		},
	}
}

func arn(region, name string) string {
	return "arn:aws:elasticloadbalancing:" + region + ":" + acct + ":loadbalancer/app/" + name + "/abc"
}

func baseELB(region string, pageSize int) *fakeELB {
	pub, priv := arn(region, "pub"), arn(region, "priv")
	return &fakeELB{
		pageSize: pageSize,
		lbs: []elbtypes.LoadBalancer{
			{LoadBalancerArn: s(pub), LoadBalancerName: s("pub"), DNSName: s("PUB-123." + region + ".elb.amazonaws.com"),
				Scheme: elbtypes.LoadBalancerSchemeEnumInternetFacing, Type: elbtypes.LoadBalancerTypeEnumApplication,
				VpcId: s("vpc-1"), SecurityGroups: []string{"sg-open"}},
			{LoadBalancerArn: s(priv), LoadBalancerName: s("priv"), DNSName: s("internal-priv-9." + region + ".elb.amazonaws.com"),
				Scheme: elbtypes.LoadBalancerSchemeEnumInternal, Type: elbtypes.LoadBalancerTypeEnumNetwork, VpcId: s("vpc-1")},
		},
		listeners: map[string][]elbtypes.Listener{
			pub: {
				{Port: aws.Int32(80), Protocol: elbtypes.ProtocolEnumHttp, DefaultActions: []elbtypes.Action{{Type: elbtypes.ActionTypeEnumRedirect}}},
				{Port: aws.Int32(443), Protocol: elbtypes.ProtocolEnumHttps, DefaultActions: []elbtypes.Action{{Type: elbtypes.ActionTypeEnumForward}}},
			},
			priv: {{Port: aws.Int32(5432), Protocol: elbtypes.ProtocolEnumTcp}},
		},
	}
}

func TestDiscoverEC2(t *testing.T) {
	e, l := baseEC2(1), baseELB("us-east-1", 1) // page size 1 forces pagination everywhere
	d, err := newSrc(map[string]Clients{"us-east-1": {EC2: e, ELB: l}}, nil, "us-east-1").Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ip := find(t, d, model.KindIP, "203.0.113.10")
	if ip.Attrs["owned"] != true || ip.Attrs["aws.account"] != acct || ip.Attrs["aws.region"] != "us-east-1" ||
		ip.Attrs["aws.name"] != "web-1" || ip.Attrs["association"] != "instance" || ip.Attrs["elastic_ip"] != true {
		t.Errorf("instance EIP attrs: %v", ip.Attrs)
	}
	if sg, _ := ip.Attrs["security_groups"].([]any); len(sg) != 0 && sg[0] != "sg-open" {
		t.Errorf("sgs: %v", sg)
	}
	inst := find(t, d, model.KindCloudResource, "aws:ec2:us-east-1:i-pub")
	if inst.Attrs["resource_type"] != "instance" {
		t.Errorf("instance attrs: %v", inst.Attrs)
	}
	if !hasRel(d, model.KindCloudResource, "aws:ec2:us-east-1:i-pub", model.KindIP, "203.0.113.10", model.RelExposes) {
		t.Error("instance should expose its IP")
	}

	// ENI with public IP
	find(t, d, model.KindIP, "203.0.113.20")
	find(t, d, model.KindCloudResource, "aws:ec2:us-east-1:eni-pub")
	if !hasRel(d, model.KindCloudResource, "aws:ec2:us-east-1:eni-pub", model.KindIP, "203.0.113.20", model.RelExposes) {
		t.Error("ENI should expose its IP")
	}

	// unassociated EIP is still an owned ip, with no cloud_resource edge
	spare := find(t, d, model.KindIP, "203.0.113.30")
	if spare.Attrs["association"] != "unassociated" || spare.Attrs["owned"] != true || spare.Attrs["aws.name"] != "spare" {
		t.Errorf("spare EIP: %v", spare.Attrs)
	}
	for _, r := range d.Relations {
		if r.ToKey == "203.0.113.30" || r.FromKey == "203.0.113.30" {
			t.Errorf("unassociated EIP should have no relations: %+v", r)
		}
	}

	// not public / terminated / AWS-managed are skipped
	for _, k := range []string{"i-priv", "i-dead", "eni-priv", "eni-elb"} {
		if has(d, model.KindCloudResource, "aws:ec2:us-east-1:"+k) {
			t.Errorf("%s should be skipped", k)
		}
	}
	if has(d, model.KindIP, "203.0.113.99") || has(d, model.KindIP, "203.0.113.77") {
		t.Error("terminated/managed IPs should not be inventoried")
	}
}

func TestSecurityGroupOpenIngress(t *testing.T) {
	e := baseEC2(2)
	d, err := newSrc(map[string]Clients{"r": {EC2: e, ELB: &fakeELB{}}}, nil, "r").Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	inst := find(t, d, model.KindCloudResource, "aws:ec2:r:i-pub")
	open, _ := inst.Attrs["open_ingress"].([]any)
	if len(open) != 3 {
		t.Fatalf("want 3 world-open rules (ssh v4, 443 v6, all), got %v", open)
	}
	first := open[0].(map[string]any)
	if first["sg"] != "sg-open" || first["protocol"] != "tcp" || first["from_port"] != 22 || first["cidr"] != "0.0.0.0/0" {
		t.Errorf("rule 0: %v", first)
	}
	if open[1].(map[string]any)["cidr"] != "::/0" || open[2].(map[string]any)["protocol"] != "all" {
		t.Errorf("rules: %v", open)
	}
	for _, o := range open {
		if o.(map[string]any)["from_port"] == 3306 {
			t.Error("private cidr rule must not be listed")
		}
	}
}

func TestELBInternetFacingVsInternal(t *testing.T) {
	d, err := newSrc(map[string]Clients{"us-east-1": {EC2: baseEC2(10), ELB: baseELB("us-east-1", 1)}}, nil, "us-east-1").Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dns := "pub-123.us-east-1.elb.amazonaws.com"
	h := find(t, d, model.KindHostname, dns)
	if h.Attrs["type"] != "application" || h.Attrs["scheme"] != "internet-facing" || h.Attrs["vpc"] != "vpc-1" ||
		h.Attrs["owned"] != true || h.Attrs["internal"] != false || h.Attrs["has_http_listener"] != true || h.Attrs["arn"] == "" {
		t.Errorf("hostname attrs: %v", h.Attrs)
	}
	ls, _ := h.Attrs["listeners"].([]any)
	if len(ls) != 2 || ls[0].(map[string]any)["port"] != 80 || ls[1].(map[string]any)["default_action"] != "forward" {
		t.Errorf("listeners: %v", ls)
	}
	find(t, d, model.KindService, dns+":80/tcp")
	find(t, d, model.KindService, dns+":443/tcp")
	if !hasRel(d, model.KindHostname, dns, model.KindService, dns+":443/tcp", model.RelExposes) {
		t.Error("hostname should expose service")
	}
	cr := find(t, d, model.KindCloudResource, "aws:elbv2:us-east-1:pub")
	if o, _ := cr.Attrs["open_ingress"].([]any); len(o) != 3 {
		t.Errorf("LB open ingress: %v", cr.Attrs["open_ingress"])
	}

	internal := "internal-priv-9.us-east-1.elb.amazonaws.com"
	ih := find(t, d, model.KindHostname, internal)
	if ih.Attrs["internal"] != true || ih.Attrs["owned"] == true {
		t.Errorf("internal LB attrs: %v", ih.Attrs)
	}
	find(t, d, model.KindCloudResource, "aws:elbv2:us-east-1:priv")
	if has(d, model.KindService, internal+":5432/tcp") {
		t.Error("internal LB must not produce service assets")
	}
}

func TestMultiRegion(t *testing.T) {
	cl := map[string]Clients{}
	for _, r := range []string{"us-east-1", "eu-west-1"} {
		e := baseEC2(10)
		e.addrs = nil
		cl[r] = Clients{EC2: e, ELB: baseELB(r, 10)}
	}
	d, err := newSrc(cl, nil, "us-east-1", "eu-west-1").Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"us-east-1", "eu-west-1"} {
		find(t, d, model.KindCloudResource, "aws:ec2:"+r+":i-pub")
		find(t, d, model.KindHostname, "pub-123."+r+".elb.amazonaws.com")
	}
}

func cfDists() []cftypes.DistributionSummary {
	return []cftypes.DistributionSummary{
		{Id: s("E1"), ARN: s("arn:aws:cloudfront::" + acct + ":distribution/E1"), DomainName: s("d111.cloudfront.net"), Enabled: aws.Bool(true),
			Aliases: &cftypes.Aliases{Items: []string{"WWW.example.com", "cdn.example.com"}},
			Origins: &cftypes.Origins{Items: []cftypes.Origin{
				{Id: s("s3"), DomainName: s("assets.s3.amazonaws.com"), S3OriginConfig: &cftypes.S3OriginConfig{}},
				{Id: s("api"), DomainName: s("origin.example.com")},
				{Id: s("ip"), DomainName: s("203.0.113.55")},
			}}},
		{Id: s("E2"), ARN: s("arn:aws:cloudfront::" + acct + ":distribution/E2"), DomainName: s("d222.cloudfront.net"), Enabled: aws.Bool(false)},
	}
}

func TestCloudFront(t *testing.T) {
	cl := map[string]Clients{"r": {EC2: &fakeEC2{}, ELB: &fakeELB{}}}
	d, err := newSrc(cl, &fakeCF{dists: cfDists(), pageSize: 1}, "r").Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Partial {
		t.Errorf("complete sync marked partial: %v", d.PartialReasons)
	}
	dom := find(t, d, model.KindHostname, "d111.cloudfront.net")
	if dom.Attrs["aws.resource_id"] != "E1" || dom.Attrs["owned"] != true {
		t.Errorf("dist attrs: %v", dom.Attrs)
	}
	find(t, d, model.KindHostname, "d222.cloudfront.net")
	find(t, d, model.KindCloudResource, "aws:cloudfront:E1")
	for _, a := range []string{"www.example.com", "cdn.example.com"} {
		find(t, d, model.KindHostname, a)
		if !hasRel(d, model.KindHostname, "d111.cloudfront.net", model.KindHostname, a, model.RelServes) {
			t.Errorf("distribution should serve %s", a)
		}
	}
	s3 := find(t, d, model.KindHostname, "assets.s3.amazonaws.com")
	if s3.Attrs["origin_type"] != "s3" {
		t.Errorf("s3 origin attrs: %v", s3.Attrs)
	}
	find(t, d, model.KindHostname, "origin.example.com")
	find(t, d, model.KindIP, "203.0.113.55")
	if !hasRel(d, model.KindHostname, "origin.example.com", model.KindHostname, "d111.cloudfront.net", model.RelOriginOf) ||
		!hasRel(d, model.KindIP, "203.0.113.55", model.KindHostname, "d111.cloudfront.net", model.RelOriginOf) {
		t.Error("origins should be origin_of the distribution")
	}
}

func TestAccessDenied(t *testing.T) {
	tests := []struct {
		name    string
		mut     func(e *fakeEC2, l *fakeELB, cf *fakeCF)
		wantErr string // empty means success
	}{
		{"ec2 describe addresses", func(e *fakeEC2, _ *fakeELB, _ *fakeCF) {
			e.errs = map[string]error{"addr": denied("UnauthorizedOperation")}
		}, "ec2:DescribeAddresses"},
		{"ec2 describe instances", func(e *fakeEC2, _ *fakeELB, _ *fakeCF) {
			e.errs = map[string]error{"inst": denied("UnauthorizedOperation")}
		}, "ec2:DescribeInstances"},
		{"ec2 describe enis", func(e *fakeEC2, _ *fakeELB, _ *fakeCF) {
			e.errs = map[string]error{"eni": denied("UnauthorizedOperation")}
		}, "ec2:DescribeNetworkInterfaces"},
		{"ec2 describe sgs", func(e *fakeEC2, _ *fakeELB, _ *fakeCF) {
			e.errs = map[string]error{"sg": denied("UnauthorizedOperation")}
		}, "ec2:DescribeSecurityGroups"},
		{"elb describe lbs", func(_ *fakeEC2, l *fakeELB, _ *fakeCF) { l.errs = map[string]error{"lb": denied("AccessDenied")} }, "elasticloadbalancing:DescribeLoadBalancers"},
		{"elb describe listeners", func(_ *fakeEC2, l *fakeELB, _ *fakeCF) { l.errs = map[string]error{"listener": denied("AccessDenied")} }, "elasticloadbalancing:DescribeListeners"},
		{"cloudfront denied is optional", func(_ *fakeEC2, _ *fakeELB, cf *fakeCF) { cf.err = denied("AccessDenied") }, ""},
		{"cloudfront other error is fatal", func(_ *fakeEC2, _ *fakeELB, cf *fakeCF) { cf.err = errors.New("throttled") }, "cloudfront:ListDistributions"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, l, cf := baseEC2(10), baseELB("r", 10), &fakeCF{dists: cfDists(), pageSize: 10}
			tc.mut(e, l, cf)
			d, err := newSrc(map[string]Clients{"r": {EC2: e, ELB: l}}, cf, "r").Discover(context.Background())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("optional denial must not fail: %v", err)
				}
				if has(d, model.KindHostname, "d111.cloudfront.net") {
					t.Error("denied CloudFront should be skipped")
				}
				if !d.Partial || len(d.PartialReasons) != 1 {
					t.Errorf("denied CloudFront must mark the discovery partial: %v %v", d.Partial, d.PartialReasons)
				}
				find(t, d, model.KindIP, "203.0.113.10") // rest of the inventory is intact
				return
			}
			if err == nil {
				t.Fatal("want error")
			}
			if d != nil {
				t.Error("error must come with no Discovery")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q should name %s", err, tc.wantErr)
			}
			if strings.Contains(tc.name, "denied") || strings.HasPrefix(tc.name, "ec2") || strings.HasPrefix(tc.name, "elb") {
				if !strings.Contains(err.Error(), "access denied") {
					t.Errorf("error %q should say access denied", err)
				}
			}
		})
	}
}

func TestPartialFailureSecondRegion(t *testing.T) {
	good := Clients{EC2: baseEC2(10), ELB: baseELB("us-east-1", 10)}
	bad := baseEC2(10)
	bad.errs = map[string]error{"inst": errors.New("boom")}
	d, err := newSrc(map[string]Clients{"us-east-1": good, "eu-west-1": {EC2: bad, ELB: &fakeELB{}}}, nil, "us-east-1", "eu-west-1").Discover(context.Background())
	if err == nil || d != nil {
		t.Fatalf("want error and nil discovery, got %v %v", d, err)
	}
	if !strings.Contains(err.Error(), "eu-west-1") {
		t.Errorf("error should name the region: %v", err)
	}
}

func TestRegions(t *testing.T) {
	tests := []struct {
		cfg  config.SourceConfig
		want string
	}{
		{config.SourceConfig{}, "us-east-1"},
		{config.SourceConfig{Region: "eu-west-1"}, "eu-west-1"},
		{config.SourceConfig{Region: "eu-west-1", Regions: []string{"a", "b", "a"}}, "a,b"},
	}
	for _, tc := range tests {
		if got := strings.Join(Regions(tc.cfg), ","); got != tc.want {
			t.Errorf("Regions(%+v) = %s, want %s", tc.cfg, got, tc.want)
		}
	}
}

func TestNewBuildsWithoutNetwork(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	src, err := Constructor(config.SourceConfig{Name: "x", Type: "aws", Regions: []string{"us-east-1", "eu-west-1"}, Endpoint: "http://127.0.0.1:1"}, config.ScopeConfig{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if src.Type() != "aws" || src.Name() != "x" {
		t.Errorf("%s %s", src.Type(), src.Name())
	}
}
