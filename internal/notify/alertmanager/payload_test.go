package alertmanager

import (
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/chainseer-xyz/deckard/internal/model"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func finding(mut func(*model.Finding)) model.Finding {
	f := model.Finding{
		ID: 42, Fingerprint: "abc123", Check: "dns.dangling", AssetKey: "foo.example.com",
		Zone: "example.com", Source: "prod-cf", Severity: model.SeverityHigh,
		Title: "Dangling CNAME", Description: "points nowhere", Remediation: "delete it",
		Status: model.StatusOpen, FirstSeen: t0.Add(-48 * time.Hour),
	}
	if mut != nil {
		mut(&f)
	}
	return f
}

func TestAlertName(t *testing.T) {
	tests := map[string]string{
		"dns.dangling":     "DeckardDnsDangling",
		"tls.cert_expiry":  "DeckardTlsCertExpiry",
		"http-headers":     "DeckardHttpHeaders",
		"":                 "Deckard",
		"...":              "Deckard",
		"a..b":             "DeckardAB",
		"9lives":           "Deckard9lives",
		"ünï.code":         "DeckardNCode",
		"nuclei.CVE-2024":  "DeckardNucleiCVE2024",
		"  spaced out  ":   "DeckardSpacedOut",
		"dns.dangling/../": "DeckardDnsDangling",
	}
	for in, want := range tests {
		if got := AlertName(in); got != want {
			t.Errorf("AlertName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildPayloadLabelsAnnotations(t *testing.T) {
	f := finding(func(f *model.Finding) { f.Evidence = map[string]any{"target": "x.example.net", "n": 1} })
	got := buildPayload([]model.Finding{f}, nil, t0, 5*time.Minute, "https://deckard.example.com/")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	a := got[0]
	wantL := map[string]string{
		"alertname": "DeckardDnsDangling", "deckard_check": "dns.dangling", "severity": "high",
		"asset": "foo.example.com", "zone": "example.com", "source": "prod-cf",
		"fingerprint": "abc123", "status": "open",
	}
	if len(a.Labels) != len(wantL) {
		t.Errorf("labels = %v", a.Labels)
	}
	for k, v := range wantL {
		if a.Labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, a.Labels[k], v)
		}
	}
	wantA := map[string]string{
		"summary": "Dangling CNAME", "description": "points nowhere", "remediation": "delete it",
		"evidence": `{"n":1,"target":"x.example.net"}`, "first_seen": "2026-09-30T12:00:00Z",
		"url": "https://deckard.example.com/findings/42",
	}
	for k, v := range wantA {
		if a.Annotations[k] != v {
			t.Errorf("annotation %s = %q, want %q", k, a.Annotations[k], v)
		}
	}
	if !a.StartsAt.Equal(f.FirstSeen) {
		t.Errorf("startsAt = %v", a.StartsAt)
	}
}

func TestOptionalLabelsAndURLOmitted(t *testing.T) {
	f := finding(func(f *model.Finding) { f.Zone, f.Source, f.Remediation = "", "", ""; f.Evidence = nil })
	a := buildPayload([]model.Finding{f}, nil, t0, time.Minute, "")[0]
	for _, k := range []string{"zone", "source"} {
		if _, ok := a.Labels[k]; ok {
			t.Errorf("label %s should be omitted", k)
		}
	}
	for _, k := range []string{"url", "remediation", "evidence"} {
		if _, ok := a.Annotations[k]; ok {
			t.Errorf("annotation %s should be omitted", k)
		}
	}
	if a.GeneratorURL != "" {
		t.Errorf("generatorURL = %q", a.GeneratorURL)
	}
}

func TestEndsAtRules(t *testing.T) {
	resend := 5 * time.Minute
	rt := t0.Add(-time.Hour)
	future := t0.Add(time.Hour)
	tests := []struct {
		name     string
		open     []model.Finding
		resolved []model.Finding
		wantEnd  time.Time
	}{
		{"open: now+2*resend", []model.Finding{finding(nil)}, nil, t0.Add(10 * time.Minute)},
		{"resolved with ResolvedAt", nil, []model.Finding{finding(func(f *model.Finding) { f.Status = model.StatusResolved; f.ResolvedAt = &rt })}, rt},
		{"resolved without ResolvedAt => now", nil, []model.Finding{finding(nil)}, t0},
		{"resolved future ResolvedAt => now", nil, []model.Finding{finding(func(f *model.Finding) { f.ResolvedAt = &future })}, t0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildPayload(tc.open, tc.resolved, t0, resend, "")
			if len(got) != 1 {
				t.Fatalf("len=%d", len(got))
			}
			if !got[0].EndsAt.Equal(tc.wantEnd) {
				t.Errorf("endsAt = %v, want %v", got[0].EndsAt, tc.wantEnd)
			}
			if tc.resolved != nil && got[0].Labels["status"] != "resolved" {
				t.Errorf("status label = %q", got[0].Labels["status"])
			}
		})
	}
}

func TestResolvedStartsAtNeverAfterEndsAt(t *testing.T) {
	rt := t0.Add(-time.Hour)
	f := finding(func(f *model.Finding) { f.FirstSeen = t0; f.ResolvedAt = &rt })
	a := buildPayload(nil, []model.Finding{f}, t0, time.Minute, "")[0]
	if a.StartsAt.After(a.EndsAt) {
		t.Errorf("startsAt %v after endsAt %v", a.StartsAt, a.EndsAt)
	}
}

func TestFiltersNonOpenStatuses(t *testing.T) {
	var open []model.Finding
	for _, s := range []model.FindingStatus{
		model.StatusOpen, model.StatusAcknowledged, model.StatusSuppressed,
		model.StatusFalsePositive, model.StatusResolved, "",
	} {
		open = append(open, finding(func(f *model.Finding) { f.Status = s; f.Fingerprint = "fp-" + string(s) }))
	}
	got := buildPayload(open, nil, t0, time.Minute, "")
	if len(got) != 1 || got[0].Labels["fingerprint"] != "fp-open" {
		t.Fatalf("got %+v", got)
	}
}

var labelNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func TestSanitizeLabelName(t *testing.T) {
	tests := map[string]string{
		"ok_name": "ok_name", "with-dash": "with_dash", "9start": "_9start",
		"dots.and space": "dots_and_space", "": "_", "é": "_",
	}
	for in, want := range tests {
		got := sanitizeLabelName(in)
		if got != want || !labelNameRe.MatchString(got) {
			t.Errorf("sanitizeLabelName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeValue(t *testing.T) {
	if got := sanitizeValue("a\x00b\nc\xffd"); got != "a b c�d" {
		t.Errorf("got %q", got)
	}
	long := strings.Repeat("é", 1500)
	got := sanitizeValue(long)
	if utf8.RuneCountInString(got) != 1000 || !utf8.ValidString(got) {
		t.Errorf("runes=%d valid=%v", utf8.RuneCountInString(got), utf8.ValidString(got))
	}
	if sanitizeValue("日本語") != "日本語" {
		t.Error("unicode mangled")
	}
}

func TestLabelValuesSanitisedInPayload(t *testing.T) {
	f := finding(func(f *model.Finding) { f.AssetKey = strings.Repeat("a", 2000) + "\n" })
	a := buildPayload([]model.Finding{f}, nil, t0, time.Minute, "")[0]
	if n := utf8.RuneCountInString(a.Labels["asset"]); n != 1000 {
		t.Errorf("asset runes = %d", n)
	}
}

func TestEvidenceTruncation(t *testing.T) {
	small := evidenceJSON(map[string]any{"a": "b"})
	if small != `{"a":"b"}` {
		t.Errorf("small = %q", small)
	}
	if evidenceJSON(nil) != "" {
		t.Error("nil evidence should be empty")
	}
	big := evidenceJSON(map[string]any{"blob": strings.Repeat("é", 5000)})
	if !strings.HasSuffix(big, truncMarker) {
		t.Fatalf("missing marker")
	}
	if len(big) > maxEvidence+len(truncMarker) {
		t.Errorf("len = %d", len(big))
	}
	if !utf8.ValidString(big) {
		t.Error("truncation split a rune")
	}
	exact := map[string]any{"k": strings.Repeat("x", maxEvidence-8)} // {"k":"..."} = len+8
	if s := evidenceJSON(exact); strings.HasSuffix(s, truncMarker) || len(s) != maxEvidence {
		t.Errorf("exact-size evidence mishandled: len=%d", len(s))
	}
	if s := evidenceJSON(map[string]any{"bad": make(chan int)}); s == "" {
		t.Error("unmarshalable should yield a placeholder")
	}
}

func TestKEVLabelAndUpgradedSeverity(t *testing.T) {
	plain := buildPayload([]model.Finding{finding(nil)}, nil, t0, time.Minute, "")[0]
	if _, ok := plain.Labels["kev"]; ok {
		t.Error("kev label on a finding without the kev tag")
	}
	// An already-open finding upgraded by KEV enrichment: the next payload
	// carries the new severity, the kev label and the KEV evidence.
	up := finding(func(f *model.Finding) {
		f.Severity = model.SeverityCritical
		f.Tags = []string{"cve", "KEV"}
		f.Evidence = map[string]any{"kev": true, "kev_date_added": "2021-12-10"}
	})
	a := buildPayload([]model.Finding{up}, nil, t0, time.Minute, "")[0]
	if a.Labels["kev"] != "true" || a.Labels["severity"] != "critical" {
		t.Errorf("labels = %v", a.Labels)
	}
	if a.Labels["fingerprint"] != "abc123" {
		t.Errorf("fingerprint label changed: %v", a.Labels)
	}
	if !strings.Contains(a.Annotations["evidence"], `"kev":true`) {
		t.Errorf("evidence = %q", a.Annotations["evidence"])
	}
}
