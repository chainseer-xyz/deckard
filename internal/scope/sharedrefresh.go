package scope

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// shared_cidrs_snapshot.txt is the generated snapshot of the published
// provider ranges (cmd/refdata-snapshot). shared_cidrs.txt stays hand-curated.
//
//go:embed shared_cidrs_snapshot.txt
var embeddedSharedSnapshot string

// Published sources of shared-infrastructure ranges.
const (
	URLCloudflareV4 = "https://www.cloudflare.com/ips-v4"
	URLCloudflareV6 = "https://www.cloudflare.com/ips-v6"
	URLAWS          = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	URLFastly       = "https://api.fastly.com/public-ip-list"
	URLGitHub       = "https://api.github.com/meta"
)

// SharedSourceURLs lists every URL ParseSharedSources understands.
var SharedSourceURLs = []string{URLCloudflareV4, URLCloudflareV6, URLAWS, URLFastly, URLGitHub}

// awsSharedServices are the ONLY AWS service tags treated as shared edge
// infrastructure. EC2 and AMAZON are deliberately absent: those ranges contain
// customers' own addresses, which must stay ownable.
var awsSharedServices = map[string]string{
	"CLOUDFRONT":        "aws-cloudfront",
	"GLOBALACCELERATOR": "aws-globalaccelerator",
	"S3":                "aws-s3",
}

// maxBadFraction is how many entries of one source may be unusable before the
// whole source is distrusted.
const maxBadFraction = 0.1

// LabeledPrefix is a shared range with the provider that published it.
type LabeledPrefix struct {
	Prefix netip.Prefix
	Label  string
}

// SanitizeSharedPrefix reports whether p is acceptable as a shared range:
// a masked, normalised prefix that is not absurdly broad (shorter than /8 for
// IPv4, /16 for IPv6) and does not overlap loopback, private, link-local,
// metadata, multicast or other never-owned/special space.
func SanitizeSharedPrefix(p netip.Prefix) (netip.Prefix, bool) {
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	p = normPrefix(p)
	min := 8
	if p.Addr().Is6() {
		min = 16
	}
	if p.Bits() < min {
		return netip.Prefix{}, false
	}
	if p.Addr().IsLoopback() || p.Addr().IsPrivate() || p.Addr().IsLinkLocalUnicast() ||
		p.Addr().IsMulticast() || p.Addr().IsUnspecified() {
		return netip.Prefix{}, false
	}
	for _, s := range specialPrefixes {
		if s.Overlaps(p) {
			return netip.Prefix{}, false
		}
	}
	return p, true
}

// SanitizeSharedPrefixes filters ps with SanitizeSharedPrefix and removes
// duplicates, returning the kept prefixes sorted and the number dropped.
func SanitizeSharedPrefixes(ps []netip.Prefix) (kept []netip.Prefix, dropped int) {
	seen := make(map[netip.Prefix]bool, len(ps))
	for _, p := range ps {
		q, ok := SanitizeSharedPrefix(p)
		if !ok {
			dropped++
			continue
		}
		if !seen[q] {
			seen[q] = true
			kept = append(kept, q)
		}
	}
	sortPrefixes(kept)
	return kept, dropped
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
}

// SetSharedRanges replaces the in-memory refreshed shared ranges (as opposed
// to the file ranges of ReloadShared). The embedded list is always kept.
// Entries are sanitised again (see SanitizeSharedPrefix) so no caller can make
// special or absurdly broad space "shared". Classification precedence is
// unchanged: excluded > owned > shared > external. Safe for concurrent use.
func (g *Guard) SetSharedRanges(ps []netip.Prefix) {
	kept, dropped := SanitizeSharedPrefixes(ps)
	if dropped > 0 {
		g.log.Warn("scope: dropped unsafe shared ranges", "dropped", dropped)
	}
	g.mu.Lock()
	g.sharedLive = kept
	g.mu.Unlock()
}

// EmbeddedSharedPrefixes returns the embedded shared ranges: the curated list
// plus the generated snapshot.
func EmbeddedSharedPrefixes() ([]netip.Prefix, error) {
	cur, snap, err := embeddedParts()
	if err != nil {
		return nil, err
	}
	return append(cur, snap...), nil
}

// EmbeddedSnapshotSize is the number of ranges in the generated snapshot (the
// part of the embedded data that a refresh replaces).
func EmbeddedSnapshotSize() (int, error) {
	_, snap, err := embeddedParts()
	return len(snap), err
}

func embeddedParts() (cur, snap []netip.Prefix, err error) {
	if cur, err = parseCIDRList(embeddedShared); err != nil {
		return nil, nil, fmt.Errorf("scope: embedded shared list: %w", err)
	}
	if snap, err = parseCIDRList(embeddedSharedSnapshot); err != nil {
		return nil, nil, fmt.Errorf("scope: embedded shared snapshot: %w", err)
	}
	return cur, snap, nil
}

// MergeShared returns the sanitised, de-duplicated union of base and extra.
func MergeShared(base, extra []netip.Prefix) []netip.Prefix {
	all := make([]netip.Prefix, 0, len(base)+len(extra))
	all = append(all, base...)
	all = append(all, extra...)
	out, _ := SanitizeSharedPrefixes(all)
	return out
}

// ParseSharedSources converts the downloaded provider documents (keyed by
// URL, see SharedSourceURLs) to labelled prefixes. Sources missing from the
// map are skipped; a source that is present but unusable (not parseable, or
// more than 10% bad entries, or no valid entry) fails the whole call so a
// poisoned or truncated document never half-applies. Only AWS CLOUDFRONT,
// GLOBALACCELERATOR and S3 prefixes are taken; EC2/AMAZON never are.
func ParseSharedSources(bodies map[string][]byte) ([]LabeledPrefix, error) {
	var out []LabeledPrefix
	add := func(url string, f func([]byte) ([]LabeledPrefix, error)) error {
		b, ok := bodies[url]
		if !ok {
			return nil
		}
		ps, err := f(b)
		if err != nil {
			return fmt.Errorf("%s: %w", url, err)
		}
		out = append(out, ps...)
		return nil
	}
	for _, s := range []struct {
		url string
		f   func([]byte) ([]LabeledPrefix, error)
	}{
		{URLCloudflareV4, parseTextList("cloudflare")},
		{URLCloudflareV6, parseTextList("cloudflare")},
		{URLAWS, parseAWS},
		{URLFastly, parseFastly},
		{URLGitHub, parseGitHubPages},
	} {
		if err := add(s.url, s.f); err != nil {
			return nil, err
		}
	}
	return dedupeLabeled(out), nil
}

// collect validates raw CIDR strings from one source.
func collect(label string, raw []string) ([]LabeledPrefix, error) {
	var out []LabeledPrefix
	bad := 0
	for _, s := range raw {
		s = strings.TrimSpace(s)
		p, err := parsePrefixOrAddr(s)
		if err != nil {
			bad++
			continue
		}
		q, ok := SanitizeSharedPrefix(p)
		if !ok {
			bad++
			continue
		}
		out = append(out, LabeledPrefix{q, label})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid %s ranges (%d unusable entries)", label, bad)
	}
	if float64(bad) > maxBadFraction*float64(len(raw)) {
		return nil, fmt.Errorf("%s: %d of %d entries unusable", label, bad, len(raw))
	}
	return out, nil
}

func parseTextList(label string) func([]byte) ([]LabeledPrefix, error) {
	return func(b []byte) ([]LabeledPrefix, error) {
		var raw []string
		for _, l := range strings.Split(string(b), "\n") {
			if i := strings.IndexByte(l, '#'); i >= 0 {
				l = l[:i]
			}
			if l = strings.TrimSpace(l); l != "" {
				raw = append(raw, l)
			}
		}
		return collect(label, raw)
	}
}

func parseAWS(b []byte) ([]LabeledPrefix, error) {
	var doc struct {
		Prefixes []struct {
			Prefix  string `json:"ip_prefix"`
			Service string `json:"service"`
		} `json:"prefixes"`
		IPv6 []struct {
			Prefix  string `json:"ipv6_prefix"`
			Service string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("aws ip-ranges: %w", err)
	}
	byLabel := map[string][]string{}
	for _, p := range doc.Prefixes {
		if l, ok := awsSharedServices[p.Service]; ok {
			byLabel[l] = append(byLabel[l], p.Prefix)
		}
	}
	for _, p := range doc.IPv6 {
		if l, ok := awsSharedServices[p.Service]; ok {
			byLabel[l] = append(byLabel[l], p.Prefix)
		}
	}
	if len(byLabel) == 0 {
		return nil, fmt.Errorf("aws ip-ranges: no CLOUDFRONT/GLOBALACCELERATOR/S3 prefixes")
	}
	var out []LabeledPrefix
	for l, raw := range byLabel {
		ps, err := collect(l, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, ps...)
	}
	return out, nil
}

func parseFastly(b []byte) ([]LabeledPrefix, error) {
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("fastly ip list: %w", err)
	}
	return collect("fastly", append(doc.Addresses, doc.IPv6Addresses...))
}

func parseGitHubPages(b []byte) ([]LabeledPrefix, error) {
	var doc struct {
		Pages []string `json:"pages"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("github meta: %w", err)
	}
	return collect("github-pages", doc.Pages)
}

func dedupeLabeled(in []LabeledPrefix) []LabeledPrefix {
	seen := map[netip.Prefix]bool{}
	var out []LabeledPrefix
	for _, l := range in {
		if !seen[l.Prefix] {
			seen[l.Prefix] = true
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Label != out[j].Label {
			return out[i].Label < out[j].Label
		}
		a, b := out[i].Prefix, out[j].Prefix
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	return out
}

// Prefixes strips the labels.
func Prefixes(ls []LabeledPrefix) []netip.Prefix {
	out := make([]netip.Prefix, len(ls))
	for i, l := range ls {
		out[i] = l.Prefix
	}
	return out
}

// FormatSharedSnapshot renders labelled prefixes in the embedded
// shared_cidrs_snapshot.txt format (read back by parseCIDRList).
func FormatSharedSnapshot(ls []LabeledPrefix) []byte {
	var sb strings.Builder
	sb.WriteString("# Generated by cmd/refdata-snapshot from published provider ranges; do not edit.\n# CIDR label\n")
	for _, l := range dedupeLabeled(ls) {
		fmt.Fprintf(&sb, "%s %s\n", l.Prefix, l.Label)
	}
	return []byte(sb.String())
}
