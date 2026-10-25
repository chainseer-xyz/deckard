package finding

import (
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

var sample = model.Finding{
	Check: "http.headers", AssetKey: "blog.example.com", Zone: "example.com", Source: "cf",
	Severity: model.SeverityLow, Title: "Missing HSTS header", Fingerprint: "abc123",
}

func TestGlob(t *testing.T) {
	tests := []struct {
		p, s string
		want bool
	}{
		{"a", "a", true}, {"a", "b", false}, {"*", "", true}, {"*", "a.b/c", true},
		{"*.example.com", "a.b.example.com", true}, {"*.example.com", "example.com", false},
		{"http.*", "http.headers", true}, {"a?c", "abc", true}, {"a?c", "ac", false},
		{"a*b*c", "aXXbYYc", true}, {"a*b*c", "aXXbYY", false}, {"**", "x", true},
		{"https://*/x", "https://a.b/x", true}, {"", "", true}, {"", "a", false},
		{"é*", "éa", true},
	}
	for _, tc := range tests {
		if got := glob(tc.p, tc.s); got != tc.want {
			t.Errorf("glob(%q,%q)=%v want %v", tc.p, tc.s, got, tc.want)
		}
	}
}

func TestMatchGrammar(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		match string
		want  bool
	}{
		{"check+asset", "check=http.headers asset=blog.example.com", true},
		{"asset glob", "asset=*.example.com", true},
		{"zone", "zone=example.com", true},
		{"source", "source=cf", true},
		{"severity", "severity=low", true},
		{"severity glob", "severity=l*", true},
		{"fingerprint", "fingerprint=abc123", true},
		{"title quoted", `title="Missing HSTS*"`, true},
		{"title glob no quotes", "title=Missing*", true},
		{"case-insensitive", "CHECK=HTTP.Headers asset=BLOG.example.com", true},
		{"tabs/newlines", "check=http.headers\tzone=example.com\nsource=cf", true},
		{"repeated key", "asset=*.example.com asset=blog.*", true},
		{"AND fails", "check=http.headers asset=other.example.com", false},
		{"check glob mismatch", "check=tls.*", false},
		{"asset not apex", "asset=*.blog.example.com", false},
		{"severity mismatch", "severity=high", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSuppressor([]config.Suppression{{Match: tc.match, Reason: "r"}})
			if err != nil {
				t.Fatal(err)
			}
			_, _, ok := s.Match(sample, now)
			if ok != tc.want {
				t.Fatalf("Match=%v want %v", ok, tc.want)
			}
		})
	}
}

func TestControlIDMatchesStructuredKubescapeEvidence(t *testing.T) {
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	until := now.Add(24 * time.Hour)
	s, err := NewSuppressor([]config.Suppression{{
		Match: "check=ext.kubescape control_id=C-0270", Reason: "CPU limits intentionally omitted", Until: &until,
	}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		check    string
		title    string
		evidence map[string]any
		want     bool
	}{
		{"exact control without title hint", "ext.kubescape", "Unrelated wording", map[string]any{"control_id": "C-0270"}, true},
		{"case insensitive", "EXT.KUBESCAPE", "", map[string]any{"control_id": "c-0270"}, true},
		{"wrong control despite title", "ext.kubescape", "CPU limits (C-0270)", map[string]any{"control_id": "C-0012"}, false},
		{"title only", "ext.kubescape", "CPU limits (C-0270)", nil, false},
		{"other evidence key", "ext.kubescape", "CPU limits (C-0270)", map[string]any{"rule_id": "C-0270"}, false},
		{"empty control", "ext.kubescape", "", map[string]any{"control_id": ""}, false},
		{"substring", "ext.kubescape", "", map[string]any{"control_id": "prefix C-0270 suffix"}, false},
		{"longer control", "ext.kubescape", "", map[string]any{"control_id": "C-02700"}, false},
		{"whitespace", "ext.kubescape", "", map[string]any{"control_id": " C-0270 "}, false},
		{"number", "ext.kubescape", "", map[string]any{"control_id": 270}, false},
		{"array", "ext.kubescape", "", map[string]any{"control_id": []string{"C-0270"}}, false},
		{"object", "ext.kubescape", "", map[string]any{"control_id": map[string]string{"id": "C-0270"}}, false},
		{"other check", "ext.prowler", "CPU limits (C-0270)", map[string]any{"control_id": "C-0270"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := model.Finding{Check: tc.check, Title: tc.title, Evidence: tc.evidence, Tags: []string{"C-0270"}}
			reason, gotUntil, ok := s.Match(f, now)
			if ok != tc.want {
				t.Fatalf("Match = %v, want %v", ok, tc.want)
			}
			if ok && (reason != "CPU limits intentionally omitted" || gotUntil == nil || !gotUntil.Equal(until)) {
				t.Fatalf("suppression reason or expiry changed: %q %v", reason, gotUntil)
			}
		})
	}
}

func TestControlIDRequiresExactKubescapeScope(t *testing.T) {
	for _, match := range []string{
		"check=ext.kubescape control_id=C-0270",
		"CONTROL_ID=c-0270 CHECK=EXT.KUBESCAPE asset=k8s://*",
	} {
		if err := ValidateSuppressions([]config.Suppression{{Match: match}}); err != nil {
			t.Errorf("valid control selector %q: %v", match, err)
		}
	}
	for _, match := range []string{
		"control_id=C-0270",
		"check=ext.prowler control_id=C-0270",
		"check=ext.* control_id=C-0270",
	} {
		if err := ValidateSuppressions([]config.Suppression{{Match: match}}); err == nil || !strings.Contains(err.Error(), "requires check=ext.kubescape") {
			t.Errorf("unscoped selector %q: %v", match, err)
		}
	}
	for _, id := range []string{"*", "C-*", "C-027?", "C0270", "C-02700", "C-027", "C-02x0", "C-0270 "} {
		match := `check=ext.kubescape control_id="` + id + `"`
		if err := ValidateSuppressions([]config.Suppression{{Match: match}}); err == nil || !strings.Contains(err.Error(), "exact Kubescape control ID") {
			t.Errorf("invalid control selector %q: %v", match, err)
		}
	}
}

func TestMatchErrors(t *testing.T) {
	tests := []struct{ match, errSub string }{
		{"", "empty match"},
		{"   \t ", "empty match"},
		{"check", "not key=value"},
		{"bogus=1", "unknown match key"},
		{"check=", "empty value"},
		{"severity=extreme", "unknown severity"},
		{`title="unterminated`, "unterminated"},
		{"=x", "unknown match key"},
		{`""`, "not key=value"},
	}
	for _, tc := range tests {
		err := ValidateSuppressions([]config.Suppression{{Match: tc.match}})
		if err == nil || !strings.Contains(err.Error(), tc.errSub) {
			t.Errorf("%q: err=%v want containing %q", tc.match, err, tc.errSub)
		}
		if _, err := NewSuppressor([]config.Suppression{{Match: tc.match}}); err == nil {
			t.Errorf("%q: NewSuppressor must fail", tc.match)
		}
	}
	// All problems reported with index.
	err := ValidateSuppressions([]config.Suppression{{Match: "check=a"}, {Match: ""}, {Match: "x=1"}})
	if err == nil || !strings.Contains(err.Error(), "suppressions[1]") || !strings.Contains(err.Error(), "suppressions[2]") {
		t.Fatalf("%v", err)
	}
	if err := ValidateSuppressions(nil); err != nil {
		t.Fatal(err)
	}
}

func TestSuppressorUntilAndOrder(t *testing.T) {
	until := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	s, err := NewSuppressor([]config.Suppression{
		{Match: "check=http.headers", Reason: "first", Until: &until},
		{Match: "asset=blog.example.com", Reason: "second"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r, u, ok := s.Match(sample, until.Add(-time.Hour))
	if !ok || r != "first" || u == nil || !u.Equal(until) {
		t.Fatalf("%v %v %v", r, u, ok)
	}
	// at/after until the first lapses and the second takes over.
	r, u, ok = s.Match(sample, until)
	if !ok || r != "second" || u != nil {
		t.Fatalf("%v %v %v", r, u, ok)
	}
	var nilS *Suppressor
	if _, _, ok := nilS.Match(sample, until); ok {
		t.Fatal("nil suppressor must not match")
	}
}

func TestOwnedByConfig(t *testing.T) {
	if !ownedByConfig(model.Finding{Status: model.StatusSuppressed, SuppressionNote: ConfigNotePrefix + "x"}) {
		t.Fatal()
	}
	if ownedByConfig(model.Finding{Status: model.StatusSuppressed, SuppressionNote: "operator note"}) ||
		ownedByConfig(model.Finding{Status: model.StatusOpen, SuppressionNote: ConfigNotePrefix}) {
		t.Fatal()
	}
}
