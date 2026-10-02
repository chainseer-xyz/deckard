package finding

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

// Evidence keys and tag set by exploit-intelligence enrichment.
const (
	TagKEV             = "kev"
	EvKEV              = "kev"
	EvKEVDateAdded     = "kev_date_added"
	EvKEVRansomware    = "kev_ransomware"
	EvKEVRequiredAct   = "kev_required_action"
	EvKEVCVEs          = "kev_cves"
	EvEPSS             = "epss"
	EvEPSSPercentile   = "epss_percentile"
	DefaultEPSSHigh    = 0.7
	DefaultEPSSMedium  = 0.3
	DefaultKEVFloor    = model.SeverityCritical
	maxCVEsPerFinding  = 50
	intelDescSeparator = " "
)

// IntelPolicy sets how exploit intelligence raises severity. Severity only
// ever goes up: a finding already at or above a floor is left alone.
type IntelPolicy struct {
	KEVFloor   model.Severity // minimum severity when a CVE is in KEV
	EPSSHigh   float64        // EPSS >= this => at least high
	EPSSMedium float64        // EPSS >= this => at least medium
}

// DefaultIntelPolicy matches the vulnintel config defaults.
func DefaultIntelPolicy() IntelPolicy {
	return IntelPolicy{KEVFloor: DefaultKEVFloor, EPSSHigh: DefaultEPSSHigh, EPSSMedium: DefaultEPSSMedium}
}

// WithIntel enables exploit-intelligence enrichment of check findings in the
// Processor. nil (or never calling it) disables it.
func WithIntel(i vulnintel.Intel) Option { return func(o *options) { o.intel = i } }

// WithIntelPolicy overrides the severity thresholds (default DefaultIntelPolicy).
func WithIntelPolicy(p IntelPolicy) Option {
	return func(o *options) { o.intelPolicy, o.intelPolicySet = p, true }
}

// evidenceCVEKeys are the evidence keys that may carry CVE ids.
var evidenceCVEKeys = []string{"cve", "cve-id", "cve_id", "cves"}

// CVEsOf returns the sorted, distinct CVE ids a finding input references:
// tags, evidence (cve, cve-id, cve_id, cves) and a key that starts with CVE-.
func CVEsOf(in model.FindingInput) []string {
	var parts []string
	if strings.HasPrefix(strings.ToUpper(in.Key), "CVE-") {
		parts = append(parts, in.Key)
	}
	parts = append(parts, in.Tags...)
	for _, k := range evidenceCVEKeys {
		for ek, v := range in.Evidence {
			if strings.EqualFold(ek, k) {
				parts = append(parts, flattenStrings(v)...)
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range parts {
		for _, id := range vulnintel.ExtractCVEs(p) {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	if len(out) > maxCVEsPerFinding {
		out = out[:maxCVEsPerFinding]
	}
	return out
}

func flattenStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []string:
		return x
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, flattenStrings(e)...)
		}
		return out
	}
	return nil
}

func maxSeverity(a, b model.Severity) model.Severity {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// ApplyIntel returns in enriched from intel. It never mutates in (tags and
// evidence are copied), is deterministic for given intel data, never lowers
// severity, and does not touch Check or Key, so the fingerprint is unchanged.
// Inputs without CVE ids, or with no intel hits, are returned as is.
func ApplyIntel(in model.FindingInput, intel vulnintel.Intel, pol IntelPolicy) model.FindingInput {
	if intel == nil {
		return in
	}
	cves := CVEsOf(in)
	if len(cves) == 0 {
		return in
	}
	var kevHits []vulnintel.KEVEntry
	var bestScore, bestPct float64
	haveEPSS := false
	for _, c := range cves {
		if e, ok := intel.KEV(c); ok {
			kevHits = append(kevHits, e)
		}
		if s, p, ok := intel.EPSS(c); ok && (!haveEPSS || s > bestScore) {
			bestScore, bestPct, haveEPSS = s, p, true
		}
	}
	if len(kevHits) == 0 && !haveEPSS {
		return in
	}

	out := in
	out.Tags = slices.Clone(in.Tags)
	out.Evidence = make(map[string]any, len(in.Evidence)+8)
	for k, v := range in.Evidence {
		out.Evidence[k] = v
	}
	var notes []string

	if len(kevHits) > 0 {
		sort.Slice(kevHits, func(i, j int) bool { return kevHits[i].CVE < kevHits[j].CVE })
		first := kevHits[0]
		ransom := false
		ids := make([]string, 0, len(kevHits))
		for _, e := range kevHits {
			ransom = ransom || e.Ransomware
			ids = append(ids, e.CVE)
		}
		out.Severity = maxSeverity(out.Severity, pol.KEVFloor)
		if !slices.Contains(out.Tags, TagKEV) {
			out.Tags = append(out.Tags, TagKEV)
		}
		out.Evidence[EvKEV] = true
		out.Evidence[EvKEVDateAdded] = first.DateAdded
		out.Evidence[EvKEVRansomware] = ransom
		out.Evidence[EvKEVRequiredAct] = first.RequiredAction
		out.Evidence[EvKEVCVEs] = ids
		note := "Known exploited (CISA KEV"
		if first.DateAdded != "" {
			note += ", added " + first.DateAdded
		}
		note += ")"
		if ransom {
			note += "; used in ransomware campaigns"
		}
		notes = append(notes, note)
	}
	if haveEPSS {
		switch {
		case bestScore >= pol.EPSSHigh:
			out.Severity = maxSeverity(out.Severity, model.SeverityHigh)
		case bestScore >= pol.EPSSMedium:
			out.Severity = maxSeverity(out.Severity, model.SeverityMedium)
		}
		out.Evidence[EvEPSS] = bestScore
		out.Evidence[EvEPSSPercentile] = bestPct
		notes = append(notes, fmt.Sprintf("EPSS %.1f%% exploitation probability (%.1fth percentile)", bestScore*100, math.Floor(bestPct*1000)/10))
	}
	for _, n := range notes {
		if !strings.Contains(out.Description, n) {
			if out.Description != "" {
				out.Description += intelDescSeparator
			}
			out.Description += n + "."
		}
	}
	return out
}

// applyIntel enriches the check's own findings (not drift) without mutating
// the caller's slice.
func (p *Processor) applyIntel(in []model.FindingInput) []model.FindingInput {
	if p.opts.intel == nil || len(in) == 0 {
		return in
	}
	pol := DefaultIntelPolicy()
	if p.opts.intelPolicySet {
		pol = p.opts.intelPolicy
	}
	out := make([]model.FindingInput, len(in))
	for i, f := range in {
		out[i] = ApplyIntel(f, p.opts.intel, pol)
	}
	return out
}
