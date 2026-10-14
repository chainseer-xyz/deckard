package identity

import (
	"reflect"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
)

const testARN = "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/public/abc123"

func TestParseAWSARN(t *testing.T) {
	for _, raw := range []string{
		testARN,
		"arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-123",
		"arn:aws-us-gov:ec2:us-gov-west-1:123456789012:instance/i-123",
		"arn:aws:cloudfront::123456789012:distribution/E123",
		"arn:aws:s3:::example-bucket",
		"arn:aws:iam::aws:policy/ReadOnlyAccess",
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := ParseAWSARN(raw)
			if err != nil || got.String() != raw {
				t.Fatalf("ParseAWSARN() = %v, %v", got, err)
			}
		})
	}
	for _, raw := range []string{
		"", "i-123", "aws:ec2:us-west-2:i-123", "arn:aws:ec2:us-west-2:123:instance/i-123",
		"arn:other:ec2:us-west-2:123456789012:instance/i-123",
		"arn:aws::us-west-2:123456789012:instance/i-123", "arn:aws:ec2:us-west-2:123456789012:",
		" " + testARN, testARN + " ", testARN + "\n", "arn:AWS:ec2:us-west-2:123456789012:instance/i-123",
	} {
		t.Run("invalid/"+raw, func(t *testing.T) {
			if _, err := ParseAWSARN(raw); err == nil {
				t.Fatal("accepted an incomplete or noncanonical ARN")
			}
		})
	}
}

func TestARNMetadataConsistency(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		ev   map[string]any
		ok   bool
	}{
		{"full ARN alone", testARN, nil, true},
		{"native Prowler", testARN, map[string]any{"provider": "aws", "account": "123456789012", "region": "us-west-2"}, true},
		{"Prowler App omits account", testARN, map[string]any{"region": "us-west-2"}, true},
		{"other provider", testARN, map[string]any{"provider": "azure"}, false},
		{"other account", testARN, map[string]any{"account": "210987654321"}, false},
		{"other region", testARN, map[string]any{"region": "us-east-1"}, false},
		{"other partition", testARN, map[string]any{"partition": "aws-cn"}, false},
		{"wrong metadata type", testARN, map[string]any{"account": 123456789012}, false},
		{"resource name is not identity", "public", map[string]any{"account": "123456789012", "region": "us-west-2"}, false},
		{"global resource context region", "arn:aws:cloudfront::123456789012:distribution/E123", map[string]any{"region": "us-east-1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := FromProwler(tc.key, tc.ev)
			if ok != tc.ok || ok && got.String() != tc.key {
				t.Fatalf("FromProwler() = %v, %v", got, ok)
			}
		})
	}
	if _, ok := FromSourceFact(map[string]any{"arn": testARN, "aws.account": "210987654321"}); ok {
		t.Fatal("accepted a contradictory source account")
	}
	if _, ok := FromSourceFact(map[string]any{"arn": testARN, "aws.region": "us-east-1"}); ok {
		t.Fatal("accepted a contradictory source region")
	}
	if _, ok := FromSourceFact(map[string]any{"arn": testARN, "aws.partition": "aws-cn"}); ok {
		t.Fatal("accepted a contradictory source partition")
	}
}

func identityAsset(id int64, raw string) model.Asset {
	return model.Asset{ID: id, Kind: model.KindCloudResource, Key: "native-resource", Source: "aws-staging",
		Scope: model.ScopeExternal, Reporters: []string{"aws-staging"},
		SourceFacts: map[string]model.SourceFact{"aws-staging": {Attrs: map[string]any{"arn": raw}}}}
}

func TestClaimsUseOnlyCurrentAuthoritativeFacts(t *testing.T) {
	a := identityAsset(17, testARN)
	a.Attrs = map[string]any{"arn": "arn:aws:cloudfront::123456789012:distribution/OTHER"}
	a.SourceFacts["withdrawn"] = model.SourceFact{Attrs: map[string]any{"arn": a.Attrs["arn"]}}
	got := Claims(a)
	if len(got) != 1 || got[0].AssetID != 17 || got[0].Reporter != "aws-staging" || got[0].Identity.String() != testARN {
		t.Fatalf("Claims() = %#v", got)
	}
	if a.Scope != model.ScopeExternal || a.Source != "aws-staging" || !reflect.DeepEqual(a.Reporters, []string{"aws-staging"}) {
		t.Fatal("identity extraction changed authority or scope")
	}
	a.Reporters = nil
	if len(Claims(a)) != 0 {
		t.Fatal("accepted a fact without a current reporter")
	}
	a = identityAsset(17, testARN)
	a.SourceFacts = nil
	a.Attrs = map[string]any{"arn": testARN}
	if len(Claims(a)) != 0 {
		t.Fatal("borrowed unattributed canonical attributes")
	}
	a = identityAsset(17, testARN)
	a.Reporters = []string{"aws-staging", "aws-other", "aws-staging", "ingest:prowler"}
	a.SourceFacts["aws-other"] = model.SourceFact{Attrs: map[string]any{"arn": testARN}}
	a.SourceFacts["ingest:prowler"] = model.SourceFact{Attrs: map[string]any{"arn": "arn:aws:cloudfront::123456789012:distribution/OTHER"}}
	if got := Claims(a); len(got) != 2 || got[0].Reporter != "aws-other" || got[1].Reporter != "aws-staging" {
		t.Fatalf("duplicate or ingest reporters affected claims: %#v", got)
	}
	a = identityAsset(17, testARN)
	a.Reporters = append(a.Reporters, "aws-other")
	a.SourceFacts["aws-other"] = model.SourceFact{Attrs: map[string]any{"arn": "arn:aws:elasticloadbalancing:us-west-2:210987654321:loadbalancer/app/public/abc123"}}
	if len(Claims(a)) != 0 {
		t.Fatal("accepted conflicting resource identities on one asset")
	}
}

func TestIndexRefusesAmbiguityAndNeverInfersIdentity(t *testing.T) {
	id, err := ParseAWSARN(testARN)
	if err != nil {
		t.Fatal(err)
	}
	a := identityAsset(17, testARN)
	b := identityAsset(18, testARN)
	for _, assets := range [][]model.Asset{{a, b}, {b, a}, {a, b, a}} {
		if got, ok := NewIndex(assets).Resolve(id); ok {
			t.Fatalf("ambiguous identity resolved to %d", got)
		}
	}
	conflicting := identityAsset(18, testARN)
	conflicting.Reporters = append(conflicting.Reporters, "aws-other")
	conflicting.SourceFacts["aws-other"] = model.SourceFact{Attrs: map[string]any{"arn": "arn:aws:cloudfront::123456789012:distribution/OTHER"}}
	for _, assets := range [][]model.Asset{{a, conflicting}, {conflicting, a}} {
		if got, ok := NewIndex(assets).Resolve(id); ok {
			t.Fatalf("conflicting authority disappeared from ambiguity detection: %d", got)
		}
	}
	removed := time.Now()
	b.RemovedAt = &removed
	index := NewIndex([]model.Asset{a, b, a})
	if got, ok := index.Resolve(id); !ok || got != 17 {
		t.Fatalf("unique live identity = %d, %v", got, ok)
	}
	for _, raw := range []string{
		"arn:aws-cn:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/public/abc123",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/public/abc123",
		"arn:aws:elasticloadbalancing:us-west-2:210987654321:loadbalancer/app/public/abc123",
		"arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/Public/abc123",
	} {
		other, err := ParseAWSARN(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := index.Resolve(other); ok {
			t.Fatalf("different exact identity resolved to %d", got)
		}
	}
	a.Kind = model.KindHostname
	if got, ok := NewIndex([]model.Asset{a}).Resolve(id); ok {
		t.Fatalf("network asset used as metadata identity: %d", got)
	}
	var empty Index
	for _, index := range []*Index{nil, &empty} {
		if got, ok := index.Resolve(id); ok || got != 0 {
			t.Fatalf("empty index = %d, %v", got, ok)
		}
	}
}
