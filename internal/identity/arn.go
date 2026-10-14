// Package identity derives exact metadata identities. A match is not an
// ownership claim and must never grant permission to probe an asset.
package identity

import (
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// AWSARN preserves every identity component, including case in Resource.
// Parsing checks syntax, not whether AWS issued the ARN or the caller owns it.
type AWSARN struct {
	Partition string
	Service   string
	Region    string
	Account   string
	Resource  string
}

// String returns the exact ARN without case folding or whitespace cleanup.
func (a AWSARN) String() string {
	return strings.Join([]string{"arn", a.Partition, a.Service, a.Region, a.Account, a.Resource}, ":")
}

// ParseAWSARN accepts complete, printable AWS ARNs, not resource names or
// inferred identities. Region and account may be empty for global resources.
func ParseAWSARN(raw string) (AWSARN, error) {
	parts := strings.SplitN(raw, ":", 6)
	if len(parts) != 6 || len(raw) > 2048 || !utf8.ValidString(raw) || parts[0] != "arn" {
		return AWSARN{}, errors.New("invalid AWS resource ARN")
	}
	a := AWSARN{Partition: parts[1], Service: parts[2], Region: parts[3], Account: parts[4], Resource: parts[5]}
	if !component(a.Partition, false) || (a.Partition != "aws" && !strings.HasPrefix(a.Partition, "aws-")) ||
		!component(a.Service, false) || !component(a.Region, true) || !account(a.Account) || a.Resource == "" {
		return AWSARN{}, errors.New("invalid AWS resource ARN")
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return AWSARN{}, errors.New("invalid AWS resource ARN")
		}
	}
	return a, nil
}

func component(s string, empty bool) bool {
	if s == "" {
		return empty
	}
	for _, c := range s {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func account(s string) bool {
	if s == "" || s == "aws" { // global resources and AWS-managed IAM policies
		return true
	}
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// FromSourceFact validates an inventory source's explicit ARN against any
// accompanying AWS metadata. Missing ARNs never fall back to names or IDs.
func FromSourceFact(attrs map[string]any) (AWSARN, bool) {
	raw, _ := attrs["arn"].(string)
	a, err := ParseAWSARN(raw)
	return a, err == nil && consistent(a, attrs, "aws.partition", "aws.account", "aws.region")
}

// FromProwler accepts the resource key only when it is a full ARN. Both native
// Prowler and Prowler App work: the latter omits provider/account evidence.
// Metadata can reject a contradiction, but can never manufacture an identity.
func FromProwler(key string, evidence map[string]any) (AWSARN, bool) {
	a, err := ParseAWSARN(key)
	if err != nil || !consistent(a, evidence, "partition", "account", "region") {
		return AWSARN{}, false
	}
	if v, present := evidence["provider"]; present {
		provider, ok := v.(string)
		if !ok || provider != "" && !strings.EqualFold(provider, "aws") {
			return AWSARN{}, false
		}
	}
	return a, true
}

func consistent(a AWSARN, metadata map[string]any, partition, acct, region string) bool {
	for _, field := range []struct{ key, expected string }{{partition, a.Partition}, {acct, a.Account}, {region, a.Region}} {
		v, present := metadata[field.key]
		if !present {
			continue
		}
		value, ok := v.(string)
		if !ok || value != "" && field.expected != "" && value != field.expected {
			return false
		}
	}
	// A global ARN's empty region/account stays empty. Scanner context metadata
	// (for example CloudFront's us-east-1 endpoint) is not an identity component.
	return true
}

// Claim attributes an exact identity to one current inventory reporter.
type Claim struct {
	AssetID  int64
	Reporter string
	Identity AWSARN
}

// Claims reads only current source facts on live cloud resources. Conflicting
// ARN assertions on one asset make the entire asset ambiguous. Canonical
// Attrs, legacy missing facts and scanner-provided evidence are not authority.
func Claims(a model.Asset) []Claim {
	claims, usable := sourceClaims(a)
	if !usable {
		return nil
	}
	return claims
}

// sourceClaims keeps syntactically valid assertions even when the asset is
// unusable, so a conflicting claimant cannot disappear from index ambiguity.
func sourceClaims(a model.Asset) ([]Claim, bool) {
	if a.ID <= 0 || a.Kind != model.KindCloudResource || a.RemovedAt != nil {
		return nil, false
	}
	reporters := append([]string(nil), a.Reporters...)
	sort.Strings(reporters)
	var out []Claim
	var known AWSARN
	usable := true
	for i, reporter := range reporters {
		if model.IsIngestSource(reporter) || i > 0 && reporter == reporters[i-1] {
			continue
		}
		fact, exists := a.SourceFacts[reporter]
		if !exists || fact.Attrs["arn"] == nil {
			continue
		}
		raw, _ := fact.Attrs["arn"].(string)
		id, err := ParseAWSARN(raw)
		if err != nil {
			usable = false
			continue
		}
		if !consistent(id, fact.Attrs, "aws.partition", "aws.account", "aws.region") || len(out) > 0 && id != known {
			usable = false
		}
		known = id
		out = append(out, Claim{AssetID: a.ID, Reporter: reporter, Identity: id})
	}
	return out, usable
}

// Index is an immutable derived lookup. Build it from a transaction-consistent
// live inventory view; it must not outlive changes to the source fact ledger.
// Its zero value is an empty index, and concurrent Resolve calls are safe.
type Index struct {
	assets map[string]int64 // zero means two or more distinct asset IDs claimed it
}

// NewIndex never merges assets. Multiple reporters on the same asset are fine;
// multiple distinct live assets claiming one exact ARN are deliberately refused.
func NewIndex(assets []model.Asset) *Index {
	index := &Index{assets: make(map[string]int64)}
	for _, a := range assets {
		claims, usable := sourceClaims(a)
		for _, claim := range claims {
			key := claim.Identity.String()
			if !usable {
				index.assets[key] = 0
				continue
			}
			previous, exists := index.assets[key]
			if exists && previous != claim.AssetID {
				index.assets[key] = 0
			} else if !exists {
				index.assets[key] = claim.AssetID
			}
		}
	}
	return index
}

// Resolve returns an asset only for an exact, unambiguous identity. Missing and
// ambiguous identities both return false; neither permits a guessed match.
func (i *Index) Resolve(id AWSARN) (int64, bool) {
	if i == nil {
		return 0, false
	}
	parsed, err := ParseAWSARN(id.String())
	if err != nil || parsed != id {
		return 0, false
	}
	assetID := i.assets[id.String()]
	return assetID, assetID > 0
}
