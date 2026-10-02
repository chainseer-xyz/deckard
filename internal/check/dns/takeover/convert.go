package takeover

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// CommunityURL is the can-i-take-over-xyz fingerprint database.
const CommunityURL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"

// minBodyFingerprint is the shortest body substring accepted from the
// community list: shorter strings match too much unrelated content.
const minBodyFingerprint = 8

type communityEntry struct {
	CNAME       []string `json:"cname"`
	Fingerprint string   `json:"fingerprint"`
	NXDomain    bool     `json:"nxdomain"`
	Service     string   `json:"service"`
	Status      string   `json:"status"`
}

var hostSuffixRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// ConvertCommunity converts a can-i-take-over-xyz fingerprints.json document
// to deckard's schema. Only entries with status "Vulnerable" or "Edge case"
// that carry at least one usable CNAME suffix and either an NXDOMAIN flag or a
// plain-text body fingerprint are kept; everything else is skipped (the list
// also holds regex-style, status-code-only and CNAME-less entries that cannot
// be matched safely). Garbage input returns an error or an empty list, never
// a panic.
func ConvertCommunity(data []byte) ([]Fingerprint, error) {
	var in []communityEntry
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, fmt.Errorf("takeover: parse community fingerprints: %w", err)
	}
	var out []Fingerprint
	for _, e := range in {
		f, ok := convertEntry(e)
		if !ok {
			continue
		}
		if err := f.compile(); err != nil {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func convertEntry(e communityEntry) (Fingerprint, bool) {
	var f Fingerprint
	switch strings.ToLower(strings.TrimSpace(e.Status)) {
	case "vulnerable":
		f.Status = "vulnerable"
	case "edge case":
		f.Status = "edge-case"
	default:
		return f, false
	}
	f.Provider = strings.TrimSpace(e.Service)
	if f.Provider == "" {
		return f, false
	}
	seen := map[string]bool{}
	for _, c := range e.CNAME {
		c = strings.ToLower(strings.TrimSpace(c))
		c = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(c, "*."), "."), ".")
		if !hostSuffixRE.MatchString(c) || seen[c] {
			continue // URLs, wildcards mid-name, single labels
		}
		if _, err := netip.ParseAddr(c); err == nil {
			continue // IP addresses are not CNAME targets
		}
		seen[c] = true
		f.CNAME = append(f.CNAME, `(^|\.)`+regexp.QuoteMeta(c)+`$`)
	}
	if len(f.CNAME) == 0 {
		return f, false
	}
	fp := strings.TrimSpace(e.Fingerprint)
	switch {
	case e.NXDomain || strings.EqualFold(fp, "NXDOMAIN"):
		f.NXDomain = true
	default:
		// The list separates alternative strings with "` `".
		for _, s := range strings.Split(fp, "` `") {
			s = strings.Trim(strings.TrimSpace(s), "`")
			if len(s) < minBodyFingerprint || strings.Contains(s, ".*") ||
				strings.Contains(s, `\`) || strings.HasPrefix(s, "HTTP_STATUS=") {
				continue // regex or status-code style, not a body substring
			}
			f.Fingerprint = append(f.Fingerprint, s)
		}
		if len(f.Fingerprint) == 0 {
			return f, false
		}
	}
	return f, true
}
