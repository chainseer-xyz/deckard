package route53

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

var _ source.Source = (*Source)(nil)

type fakeAPI struct {
	zones      []types.HostedZone
	records    map[string][]types.ResourceRecordSet
	pageSize   int
	failZones  bool
	failRecord string // zone id whose record listing fails
}

func (f *fakeAPI) ListHostedZones(_ context.Context, in *sdkroute53.ListHostedZonesInput, _ ...func(*sdkroute53.Options)) (*sdkroute53.ListHostedZonesOutput, error) {
	if f.failZones {
		return nil, errors.New("boom")
	}
	start := 0
	if in.Marker != nil {
		start, _ = strconv.Atoi(*in.Marker)
	}
	end := min(start+f.pageSize, len(f.zones))
	out := &sdkroute53.ListHostedZonesOutput{HostedZones: f.zones[start:end]}
	if end < len(f.zones) {
		out.IsTruncated = true
		out.NextMarker = aws.String(strconv.Itoa(end))
	}
	return out, nil
}

func (f *fakeAPI) ListResourceRecordSets(_ context.Context, in *sdkroute53.ListResourceRecordSetsInput, _ ...func(*sdkroute53.Options)) (*sdkroute53.ListResourceRecordSetsOutput, error) {
	id := aws.ToString(in.HostedZoneId)
	if id == f.failRecord {
		return nil, errors.New("throttled")
	}
	recs := f.records[id]
	start := 0
	if in.StartRecordName != nil {
		start, _ = strconv.Atoi(*in.StartRecordName)
	}
	end := min(start+f.pageSize, len(recs))
	out := &sdkroute53.ListResourceRecordSetsOutput{ResourceRecordSets: recs[start:end]}
	if end < len(recs) {
		out.IsTruncated = true
		out.NextRecordName = aws.String(strconv.Itoa(end))
		out.NextRecordType = types.RRTypeA
	}
	return out, nil
}

func rec(name string, t types.RRType, vals ...string) types.ResourceRecordSet {
	r := types.ResourceRecordSet{Name: aws.String(name), Type: t}
	for _, v := range vals {
		r.ResourceRecords = append(r.ResourceRecords, types.ResourceRecord{Value: aws.String(v)})
	}
	return r
}

func alias(name, target string) types.ResourceRecordSet {
	return types.ResourceRecordSet{Name: aws.String(name), Type: types.RRTypeA, AliasTarget: &types.AliasTarget{DNSName: aws.String(target)}}
}

func fixture() *fakeAPI {
	return &fakeAPI{
		pageSize: 2,
		zones: []types.HostedZone{
			{Id: aws.String("/hostedzone/ZPUB1"), Name: aws.String("example.com."), Config: &types.HostedZoneConfig{}},
			{Id: aws.String("/hostedzone/ZPRIV"), Name: aws.String("internal.example.com."), Config: &types.HostedZoneConfig{PrivateZone: true}},
			{Id: aws.String("/hostedzone/ZPUB2"), Name: aws.String("example.org."), Config: &types.HostedZoneConfig{}},
		},
		records: map[string][]types.ResourceRecordSet{
			"/hostedzone/ZPUB1": {
				rec("WWW.Example.com.", types.RRTypeA, "192.0.2.10"),
				rec("www.example.com.", types.RRTypeAaaa, "2001:db8::1"),
				rec("\\052.example.com.", types.RRTypeA, "192.0.2.10"),
				rec("blog.example.com.", types.RRTypeCname, "Hosted.Example.net."),
				alias("lb.example.com.", "dualstack.my-lb-123.us-east-1.elb.amazonaws.com."),
			},
			"/hostedzone/ZPRIV": {rec("db.internal.example.com.", types.RRTypeA, "10.0.0.5")},
			"/hostedzone/ZPUB2": {alias("cdn.example.org.", "d111111abcdef8.cloudfront.net.")},
		},
	}
}

func discover(t *testing.T, f *fakeAPI) (*source.Discovery, error) {
	t.Helper()
	return NewWithAPI("aws-prod", f, slog.New(slog.NewTextHandler(io.Discard, nil))).Discover(context.Background())
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
	for _, r := range d.Relations {
		if r.FromKind == fk && r.FromKey == f && r.ToKind == tk && r.ToKey == to && r.Type == t {
			return true
		}
	}
	return false
}

func TestDiscover(t *testing.T) {
	d, err := discover(t, fixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Zones) != 2 || d.Zones[0].Name != "example.com" || d.Zones[1].Name != "example.org" {
		t.Fatalf("zones (private must be skipped, pagination followed): %+v", d.Zones)
	}
	as := assetSet(d)
	for _, want := range []ak{
		{model.KindZone, "example.com"}, {model.KindHostname, "www.example.com"},
		{model.KindHostname, "*.example.com"}, {model.KindIP, "192.0.2.10"}, {model.KindIP, "2001:db8::1"},
		{model.KindHostname, "hosted.example.net"}, {model.KindHostname, "cdn.example.org"},
	} {
		if _, ok := as[want]; !ok {
			t.Errorf("missing asset %+v", want)
		}
	}
	if _, ok := as[ak{model.KindIP, "10.0.0.5"}]; ok {
		t.Error("private zone leaked")
	}
	n := 0
	for _, a := range d.Assets {
		if a.Kind == model.KindHostname && a.Key == "www.example.com" {
			n++
		}
		if a.Source != "aws-prod" {
			t.Errorf("source not set: %+v", a)
		}
	}
	if n != 1 {
		t.Errorf("www deduped? got %d", n)
	}
	if !hasRel(d, model.KindHostname, "www.example.com", model.KindIP, "2001:db8::1", model.RelResolvesTo) ||
		!hasRel(d, model.KindHostname, "blog.example.com", model.KindHostname, "hosted.example.net", model.RelCNAMETo) ||
		!hasRel(d, model.KindHostname, "lb.example.com", model.KindHostname, "dualstack.my-lb-123.us-east-1.elb.amazonaws.com", model.RelAliasTo) {
		t.Errorf("relations missing: %+v", d.Relations)
	}
	if got := as[ak{model.KindHostname, "dualstack.my-lb-123.us-east-1.elb.amazonaws.com"}].Attrs["alias_target_type"]; got != "elb" {
		t.Errorf("alias type %v", got)
	}
	if got := as[ak{model.KindHostname, "d111111abcdef8.cloudfront.net"}].Attrs["alias_target_type"]; got != "cloudfront" {
		t.Errorf("alias type %v", got)
	}
}

func TestClassifyAliasTarget(t *testing.T) {
	tests := map[string]string{
		"dualstack.x-1.us-east-1.elb.amazonaws.com.":               "elb",
		"d111.cloudfront.net":                                      "cloudfront",
		"s3-website-us-east-1.amazonaws.com.":                      "s3_website",
		"s3-website.eu-central-1.amazonaws.com":                    "s3_website",
		"bucket.s3-website-us-west-2.amazonaws.com":                "s3_website",
		"abc123.execute-api.us-east-1.amazonaws.com":               "apigateway",
		"example-accel.awsglobalaccelerator.com":                   "globalaccelerator",
		"myapp.us-east-1.elasticbeanstalk.com":                     "elasticbeanstalk",
		"vpce-0123-abc.vpce-svc-0123.us-east-1.vpce.amazonaws.com": "vpc_endpoint",
		"other.example.net":                                        "other",
	}
	for in, want := range tests {
		if got := ClassifyAliasTarget(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	tests := map[string]string{
		"\\052.Example.COM.":  "*.example.com",
		"a\\052b.example.com": "a*b.example.com",
		"plain.example.com":   "plain.example.com",
	}
	for in, want := range tests {
		if got := normalizeName(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestPartialFailureReturnsErrorNoDiscovery(t *testing.T) {
	for name, mut := range map[string]func(*fakeAPI){
		"zones":   func(f *fakeAPI) { f.failZones = true },
		"records": func(f *fakeAPI) { f.failRecord = "/hostedzone/ZPUB2" },
	} {
		t.Run(name, func(t *testing.T) {
			f := fixture()
			mut(f)
			d, err := discover(t, f)
			if err == nil || d != nil {
				t.Fatalf("want error and nil discovery, got %v %v", d, err)
			}
		})
	}
}
