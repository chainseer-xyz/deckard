package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// ParseOptions are what a parser knows besides the tool output.
type ParseOptions struct {
	// Scope is the request scope. Parsers use it to qualify asset keys that
	// the tool does not make globally unique (a Kubernetes resource id, a
	// repository-relative path) and as the asset when the output names none.
	Scope string
}

// Parser converts one tool's native output into findings. Parsers are pure:
// no network, no clock, no logging. Their output passed through Normalize is
// always valid for Validate; it never contains secret values.
type Parser func(data []byte, o ParseOptions) ([]Finding, error)

// Line makes s a single clean line of at most max bytes: invalid UTF-8 and
// control characters become spaces, runs of spaces collapse, and the result
// is trimmed and cut at a rune boundary.
func Line(s string, max int) string {
	s = strings.ToValidUTF8(s, " ")
	var b strings.Builder
	space := false
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return cut(b.String(), max)
}

// Text is Line for multi-line text: tabs and newlines are kept (CRLF becomes
// LF), other control characters dropped.
func Text(s string, max int) string {
	s = strings.ToValidUTF8(s, " ")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, s)
	return cut(strings.TrimSpace(s), max)
}

// cut truncates s to at most max bytes at a rune boundary, marking the cut
// with an ellipsis when there is room.
func cut(s string, max int) string {
	if len(s) <= max {
		return s
	}
	const ell = "…"
	limit := max
	if max > 2*len(ell) {
		limit = max - len(ell)
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	out := strings.TrimSpace(s[:limit])
	if limit < max {
		out += ell
	}
	if len(out) > max { // only if max is tiny
		return strings.TrimSpace(s[:limit])
	}
	return out
}

// ID makes s a key-like identifier of at most max bytes. Unlike Line it
// never loses uniqueness: an over-long id keeps a prefix plus a hash of the
// whole.
func ID(s string, max int) string {
	s = Line(s, 1<<20)
	if len(s) <= max {
		return s
	}
	sum := sha256.Sum256([]byte(s))
	h := "#" + hex.EncodeToString(sum[:8])
	n := max - len(h)
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return strings.TrimSpace(s[:n]) + h
}

// SafeURL strips credentials, query and fragment from a URL so that a
// repository or link URL never carries a token into a finding. Anything
// that does not parse as an absolute URL is returned as a clean line with
// any "user:pass@" prefix removed.
func SafeURL(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme == "" || u.Host == "" {
		if at := strings.LastIndex(s, "@"); at >= 0 && strings.Contains(s[:at], ":") && !strings.Contains(s[:at], "/") {
			s = s[at+1:]
		}
		return Line(s, MaxAssetKeyLen)
	}
	u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
	return Line(u.String(), MaxAssetKeyLen)
}

// SecretHash is a short, non-reversible handle for a secret value: the first
// 12 hex digits of its SHA-256. It lets an operator correlate occurrences of
// the same secret without the value ever being stored.
func SecretHash(secret string) string {
	if secret == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:6])
}

// Tags cleans, deduplicates and caps tags, keeping order. An over-long tag
// (a long rule id) is shortened like ID, so distinct rules keep distinct tags.
func Tags(in ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		t = ID(t, MaxTagLen)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) == MaxTags {
			break
		}
	}
	return out
}

// Evidence cleans an evidence map of flat values: strings become clean lines
// (at most 1 KiB each), nil and empty values are dropped, and keys are
// dropped (largest value first) until the encoding fits MaxEvidenceBytes.
func Evidence(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		k = Line(k, 64)
		if k == "" {
			continue
		}
		switch x := v.(type) {
		case nil:
			continue
		case string:
			if x = Line(x, 1024); x == "" {
				continue
			}
			v = x
		case []string:
			var keep []any
			for _, s := range x {
				if s = Line(s, 256); s != "" {
					keep = append(keep, s)
				}
				if len(keep) == 20 {
					break
				}
			}
			if len(keep) == 0 {
				continue
			}
			v = keep
		case float64:
			if math.IsNaN(x) || math.IsInf(x, 0) {
				continue
			}
		case bool, int, int64:
		default:
			continue // only flat, known-safe value types
		}
		out[k] = v
	}
	for {
		b, err := json.Marshal(out)
		if err == nil && len(b) <= MaxEvidenceBytes {
			break
		}
		largest, size := "", -1
		for k, v := range out {
			vb, _ := json.Marshal(v)
			if len(vb) > size || len(vb) == size && k > largest {
				largest, size = k, len(vb)
			}
		}
		delete(out, largest)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Normalize makes a parser's finding valid: every string is cleaned and
// length-capped, missing title, description and asset key get fallbacks, an
// unknown severity becomes medium and the asset is a cloud_resource unless
// it is a ref.
func Normalize(f Finding) Finding {
	f.Key = ID(f.Key, MaxKeyLen)
	if f.Key == "" {
		f.Key = "unkeyed"
	}
	f.Title = Line(f.Title, MaxTitleLen)
	if f.Title == "" {
		f.Title = "Untitled finding"
	}
	f.Description = Text(f.Description, MaxDescriptionLen)
	if f.Description == "" {
		f.Description = f.Title
	}
	f.Remediation = Text(f.Remediation, MaxRemediationLen)
	if !f.Severity.Valid() {
		f.Severity = model.SeverityMedium
	}
	if f.Asset.Ref != nil {
		f.Asset.Ref.Key = ID(f.Asset.Ref.Key, MaxAssetKeyLen)
	} else {
		f.Asset.Kind = model.KindCloudResource
		if f.Asset.Key = ID(f.Asset.Key, MaxAssetKeyLen); f.Asset.Key == "" {
			f.Asset.Key = "unknown-resource"
		}
	}
	f.Tags = Tags(f.Tags...)
	f.Evidence = Evidence(f.Evidence)
	return f
}

// Finalize normalizes every finding and drops later duplicates of a key
// (a tool that reports the same item twice), sorted by key so the output
// (and so the request digest) does not depend on the tool's ordering.
func Finalize(in []Finding) []Finding {
	out := make([]Finding, 0, len(in))
	seen := map[string]bool{}
	for _, f := range in {
		f = Normalize(f)
		if seen[f.Key] {
			continue
		}
		seen[f.Key] = true
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Severity maps common scanner severity words to deckard's scale; anything
// unknown is medium (an unrecognised level is not evidence of low risk).
func Severity(s string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "fatal", "blocker":
		return model.SeverityCritical
	case "high", "error", "major":
		return model.SeverityHigh
	case "medium", "moderate", "warning":
		return model.SeverityMedium
	case "low", "minor", "note":
		return model.SeverityLow
	case "info", "informational", "information", "none", "unknown_severity":
		return model.SeverityInfo
	}
	return model.SeverityMedium
}
