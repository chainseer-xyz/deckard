package prowlerapp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Tool is the ingest tool name: findings pulled from Prowler App are stored
// under the same ext.prowler check as the CLI-output adapter's.
const Tool = "prowler"

// Scope is the ingest scope of a provider: <provider type>:<provider uid>
// (aws:123456789012, gcp:my-project, github:example-org).
func Scope(p Provider) string {
	return ingest.ID(ingest.Line(p.Type, 32)+":"+p.UID, ingest.MaxScopeLen)
}

// MapContext is what a finding is mapped against.
type MapContext struct {
	Provider Provider
	ScanID   string
	// Resource resolves a resource reference of the page being mapped.
	Resource func(Ref) (RawResource, bool)
}

// Mapped is the outcome for one Prowler finding.
type Mapped struct {
	Findings []ingest.Finding
	// Incomplete is the reason the run cannot be called complete because of
	// this finding (an unmappable finding, or one mapped from doubtful data);
	// empty when the finding mapped cleanly.
	Incomplete string
}

// MapFinding converts one Prowler finding into ingest findings, one per
// resource it names (normally exactly one). Evidence is an explicit allow-list;
// raw results and resource tags or details are never read.
func MapFinding(mc MapContext, f RawFinding) Mapped {
	check := f.CheckID
	if check == "" {
		check = mdStr(f.CheckMetadata, "checkid")
	}
	if check == "" {
		return Mapped{Incomplete: fmt.Sprintf("finding %s has no check id", ingest.Line(f.ID, 64))}
	}
	var out Mapped
	title := mdStr(f.CheckMetadata, "checktitle")
	if title == "" {
		title = check
	}
	description := strings.TrimSpace(f.StatusExtended)
	if description == "" {
		description = mdStr(f.CheckMetadata, "description")
	}
	if description == "" {
		description = title
	}
	if risk := mdStr(f.CheckMetadata, "risk"); risk != "" {
		description += "\n\nRisk: " + risk
	}
	remediation := mdStr(f.CheckMetadata, "remediation", "recommendation", "text")
	if u := mdStr(f.CheckMetadata, "remediation", "recommendation", "url"); u != "" {
		if remediation != "" {
			remediation += "\n\n"
		}
		remediation += "Reference: " + ingest.SafeURL(u)
	}
	sev := f.Severity
	if strings.TrimSpace(sev) == "" {
		sev = mdStr(f.CheckMetadata, "severity")
	}

	var resources []RawResource
	switch {
	case !f.Resources.Known:
		// No linkage at all: map it on a synthesized resource so it is not lost,
		// but a run containing it must not resolve anything.
		out.Incomplete = fmt.Sprintf("finding %s has no resources relationship", ingest.Line(f.ID, 64))
		resources = []RawResource{{}}
	case len(f.Resources.Refs) == 0:
		resources = []RawResource{{}} // a finding about no particular resource
	default:
		for _, ref := range f.Resources.Refs {
			res, ok := mc.Resource(ref)
			if !ok || (strings.TrimSpace(res.UID) == "" && strings.TrimSpace(res.Name) == "") {
				out.Incomplete = fmt.Sprintf("resource %s of finding %s is missing from the response", ingest.Line(ref.ID, 64), ingest.Line(f.ID, 64))
				continue
			}
			resources = append(resources, res)
		}
	}
	for _, res := range resources {
		uid := strings.TrimSpace(res.UID)
		if uid == "" {
			uid = strings.TrimSpace(res.Name)
		}
		if uid == "" {
			uid = synthesizedResource(mc.Provider, f, check)
		}
		service := firstNonEmpty(res.Service, mdStr(f.CheckMetadata, "servicename"))
		rtype := firstNonEmpty(res.Type, mdStr(f.CheckMetadata, "resourcetype"))
		out.Findings = append(out.Findings, ingest.Finding{
			Key:         check + ":" + uid,
			Asset:       ingest.Asset{Kind: model.KindCloudResource, Key: uid},
			Title:       title,
			Description: description,
			Severity:    ingest.Severity(sev),
			Remediation: remediation,
			Tags:        ingest.Tags(mc.Provider.Type, service, res.Region, check, Tool),
			Evidence: map[string]any{
				"region": res.Region, "service": service, "resource_type": rtype,
				"scan_id": mc.ScanID, "first_seen_at": f.FirstSeenAt, "delta": f.Delta,
			},
		})
	}
	return out
}

// synthesizedResource names a finding that is about no resource. It is stable
// across scans: Prowler's own finding uid encodes check, account, region and
// resource.
func synthesizedResource(p Provider, f RawFinding, check string) string {
	return "prowler:" + p.Type + ":" + p.UID + ":" + firstNonEmpty(f.UID, check)
}

// Wanted is the client-side re-check of the query's filters: only failing,
// unmuted (unless included) findings at or above the floor are findings. The
// server already filters; this keeps a server that ignored a filter from
// flooding the run.
func Wanted(f RawFinding, floor model.Severity, includeMuted bool) bool {
	switch {
	case f.Status != "" && f.Status != "FAIL":
		return false
	case f.Muted && !includeMuted:
		return false
	}
	sev := f.Severity
	if strings.TrimSpace(sev) == "" {
		sev = mdStr(f.CheckMetadata, "severity")
	}
	return ingest.Severity(sev).AtLeast(floor)
}

// Merge normalizes findings and makes keys unique, deterministically: when a
// key repeats the most severe copy wins (then the lexically first), and the
// result is sorted by key. It returns how many copies were merged away; the
// key set, which is what absence is judged on, is unchanged by merging.
func Merge(in []ingest.Finding) (out []ingest.Finding, merged int) {
	all := make([]ingest.Finding, len(in))
	for i, f := range in {
		all[i] = ingest.Normalize(f)
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		switch {
		case a.Key != b.Key:
			return a.Key < b.Key
		case a.Severity.Rank() != b.Severity.Rank():
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.Title+"\x00"+a.Description < b.Title+"\x00"+b.Description
	})
	for _, f := range all {
		if n := len(out); n > 0 && out[n-1].Key == f.Key {
			merged++
			continue
		}
		out = append(out, f)
	}
	return out, merged
}

// ParseSeverityFloor reads --min-severity.
func ParseSeverityFloor(s string) (model.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "informational":
		return model.SeverityInfo, nil
	case "low":
		return model.SeverityLow, nil
	case "medium":
		return model.SeverityMedium, nil
	case "high":
		return model.SeverityHigh, nil
	case "critical":
		return model.SeverityCritical, nil
	}
	return "", fmt.Errorf("--min-severity must be one of info, low, medium, high, critical (got %q)", s)
}

// ProwlerSeverities lists Prowler's severity words from the floor upwards, for
// filter[severity__in].
func ProwlerSeverities(floor model.Severity) []string {
	var out []string
	for _, p := range []struct {
		word string
		sev  model.Severity
	}{{"critical", model.SeverityCritical}, {"high", model.SeverityHigh}, {"medium", model.SeverityMedium},
		{"low", model.SeverityLow}, {"informational", model.SeverityInfo}} {
		if p.sev.AtLeast(floor) {
			out = append(out, p.word)
		}
	}
	return out
}

// mdStr reads a string at a path of the normalised check metadata; anything
// else (a list, a number, a missing key) reads as "".
func mdStr(md map[string]any, path ...string) string {
	var cur any = md
	for _, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[k]
	}
	s, _ := cur.(string)
	return strings.TrimSpace(s)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}
