// Package vulnintel enriches CVE findings with real-world exploit intelligence:
// the CISA Known Exploited Vulnerabilities (KEV) catalog and FIRST EPSS
// exploit-prediction scores. Lookups are non-blocking reads of in-memory
// snapshots; fetching happens in Service.Refresh / RefreshEPSS, which the
// engine calls from a periodic job. With no data every lookup misses, so
// enrichment is a no-op when deckard is offline or air-gapped.
package vulnintel

import (
	"regexp"
	"sort"
	"strings"
)

var (
	cveExact  = regexp.MustCompile(`^CVE-\d{4}-\d{4,19}$`)
	cveSearch = regexp.MustCompile(`(?i)\bcve-\d{4}-\d{4,19}\b`)
)

// NormalizeCVE upper-cases and trims id and reports whether it is a
// well-formed CVE identifier.
func NormalizeCVE(id string) (string, bool) {
	id = strings.ToUpper(strings.TrimSpace(id))
	return id, cveExact.MatchString(id)
}

// ExtractCVEs returns the distinct, upper-cased, sorted CVE ids found in s.
func ExtractCVEs(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range cveSearch.FindAllString(s, -1) {
		m = strings.ToUpper(m)
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// Intel is the read-only lookup surface the finding processor uses. Both
// methods must be fast, non-blocking and safe for concurrent use.
type Intel interface {
	KEV(cve string) (KEVEntry, bool)
	EPSS(cve string) (score, percentile float64, ok bool)
}
