// Package alertmanager delivers deckard findings to Prometheus Alertmanager
// via the v2 API (POST /api/v2/alerts).
package alertmanager

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/chainseer-xyz/deckard/internal/model"
)

const (
	maxLabelRunes = 1000
	maxEvidence   = 2048
	maxContext    = 1024
	truncMarker   = "…truncated"
)

// postableAlert is the Alertmanager v2 PostableAlert schema.
type postableAlert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

// AlertName maps a check id to an Alertmanager alertname: "Deckard" followed by
// the CamelCased alphanumeric words of the check, e.g. dns.dangling ->
// DeckardDnsDangling. Non-ASCII/punctuation act as word separators; an empty
// check yields "Deckard".
func AlertName(check string) string {
	var b strings.Builder
	b.WriteString("Deckard")
	newWord := true
	for _, r := range check {
		if r > unicode.MaxASCII || !(unicode.IsLetter(r) || unicode.IsDigit(r)) {
			newWord = true
			continue
		}
		if newWord {
			b.WriteRune(unicode.ToUpper(r))
			newWord = false
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeValue makes s a safe label value: invalid UTF-8 and control
// characters are replaced, and the result is capped at maxLabelRunes runes.
func sanitizeValue(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > maxLabelRunes {
		s = string([]rune(s)[:maxLabelRunes])
	}
	return s
}

// sanitizeLabelName coerces s to [a-zA-Z_][a-zA-Z0-9_]*.
func sanitizeLabelName(s string) string {
	var b strings.Builder
	for i, r := range s {
		isAlpha := r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		isDigit := r >= '0' && r <= '9'
		switch {
		case isAlpha, isDigit && i > 0:
			b.WriteRune(r)
		case isDigit:
			b.WriteByte('_')
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// evidenceJSON renders evidence compactly, truncated to maxEvidence bytes on
// a rune boundary with a marker appended.
func evidenceJSON(ev map[string]any) string {
	if len(ev) == 0 {
		return ""
	}
	raw, err := json.Marshal(ev) // map keys are sorted: deterministic output
	if err != nil {
		return "unmarshalable evidence"
	}
	s := string(raw)
	if len(s) <= maxEvidence {
		return s
	}
	cut := maxEvidence
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncMarker
}

// truncateRunes caps s at max bytes on a rune boundary, appending the marker.
func truncateRunes(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncMarker
}

// ctxString reads a string from the finding's enrichment context.
func ctxString(f model.Finding, key string) string {
	if v, ok := f.Context[key].(string); ok {
		return v
	}
	return ""
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

func setLabel(m map[string]string, name, value string) {
	// Empty label values are equivalent to absent labels in Alertmanager.
	if v := sanitizeValue(value); v != "" {
		m[sanitizeLabelName(name)] = v
	}
}

func setAnn(m map[string]string, name, value string) {
	if value != "" {
		m[name] = strings.ToValidUTF8(value, "�")
	}
}

// buildAlert converts one finding. endsAt is supplied by the caller.
func buildAlert(f model.Finding, endsAt time.Time, baseURL string) postableAlert {
	l := map[string]string{}
	setLabel(l, "alertname", AlertName(f.Check))
	setLabel(l, "deckard_check", f.Check)
	setLabel(l, "severity", string(f.Severity))
	setLabel(l, "asset", f.AssetKey)
	setLabel(l, "zone", f.Zone)
	setLabel(l, "source", f.Source)
	setLabel(l, "fingerprint", f.Fingerprint)
	setLabel(l, "status", string(f.Status))
	if hasTag(f.Tags, "kev") {
		// Listed in CISA KEV: lets Alertmanager route known-exploited CVEs.
		setLabel(l, "kev", "true")
	}

	a := map[string]string{}
	setAnn(a, "summary", f.Title)
	setAnn(a, "description", f.Description)
	setAnn(a, "remediation", f.Remediation)
	setAnn(a, "evidence", evidenceJSON(f.Evidence))
	if !f.FirstSeen.IsZero() {
		setAnn(a, "first_seen", f.FirstSeen.UTC().Format(time.RFC3339))
	}
	for _, k := range []string{"lineage", "previous_state", "current_state", "owner", "last_changed"} {
		if v := ctxString(f, k); v != "" {
			setAnn(a, k, truncateRunes(v, maxContext))
		}
	}
	if _, ok := a["first_seen"]; !ok {
		setAnn(a, "first_seen", ctxString(f, "first_seen"))
	}
	pa := postableAlert{Labels: l, Annotations: a, StartsAt: f.FirstSeen.UTC(), EndsAt: endsAt.UTC()}
	if baseURL != "" {
		u := strings.TrimRight(baseURL, "/") + "/findings/" + strconv.FormatInt(f.ID, 10)
		setAnn(a, "url", u)
		pa.GeneratorURL = u
	}
	return pa
}

// buildPayload is the pure payload builder.
//
// Open findings (status must be StatusOpen; anything else is dropped even if
// the caller passes it) get endsAt = now + 2*resend. If deckard dies and stops
// re-asserting, Alertmanager auto-resolves them after that window instead of
// leaving stale alerts firing forever; two intervals tolerate one missed push.
//
// Resolved findings get endsAt = ResolvedAt (or now if unset/in the future),
// so Alertmanager marks them resolved immediately. startsAt is FirstSeen.
func buildPayload(open, resolved []model.Finding, now time.Time, resend time.Duration, baseURL string) []postableAlert {
	out := make([]postableAlert, 0, len(open)+len(resolved))
	openEnd := now.Add(2 * resend)
	for _, f := range open {
		if f.Status != model.StatusOpen {
			continue
		}
		out = append(out, buildAlert(f, openEnd, baseURL))
	}
	for _, f := range resolved {
		end := now
		if f.ResolvedAt != nil && !f.ResolvedAt.After(now) {
			end = *f.ResolvedAt
		}
		f.Status = model.StatusResolved
		pa := buildAlert(f, end, baseURL)
		if pa.StartsAt.After(pa.EndsAt) || f.FirstSeen.IsZero() {
			pa.StartsAt = pa.EndsAt
		}
		out = append(out, pa)
	}
	return out
}
