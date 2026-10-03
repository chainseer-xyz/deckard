package ingest

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestLineAndText(t *testing.T) {
	if got := Line("  a\tb\n\x00c\x7f  d  ", 100); got != "a b c d" {
		t.Errorf("Line = %q", got)
	}
	if got := Line("\xffok", 100); got != "ok" {
		t.Errorf("invalid utf8 = %q", got)
	}
	if got := Line(strings.Repeat("é", 200), 11); len(got) > 11 || !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
		t.Errorf("cut = %q (%d bytes)", got, len(got))
	}
	if got := Text("a\r\nb\tc\x00\x1b", 100); got != "a\nb\tc" {
		t.Errorf("Text = %q", got)
	}
}

func TestIDKeepsUniqueness(t *testing.T) {
	a, b := strings.Repeat("x", 600)+"a", strings.Repeat("x", 600)+"b"
	ia, ib := ID(a, MaxKeyLen), ID(b, MaxKeyLen)
	if len(ia) > MaxKeyLen || ia == ib || ID(a, MaxKeyLen) != ia {
		t.Fatalf("ID not unique/stable/bounded: %d %v", len(ia), ia == ib)
	}
	if ID("short", 10) != "short" {
		t.Fatal("short id changed")
	}
}

func TestSafeURLStripsCredentials(t *testing.T) {
	cases := map[string]string{
		"https://user:ghp_secret@github.com/example/app.git?token=x#frag": "https://github.com/example/app.git",
		"https://github.com/example/app":                                  "https://github.com/example/app",
		"git@github.com:example/app.git":                                  "git@github.com:example/app.git",
		"oauth2:glpat-secret@gitlab.example.com":                          "gitlab.example.com",
	}
	for in, want := range cases {
		if got := SafeURL(in); got != want {
			t.Errorf("SafeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSecretHash(t *testing.T) {
	h := SecretHash("hunter2")
	if !strings.HasPrefix(h, "sha256:") || len(h) != len("sha256:")+12 || strings.Contains(h, "hunter2") || SecretHash("") != "" {
		t.Fatalf("SecretHash = %q", h)
	}
}

func TestEvidenceBounds(t *testing.T) {
	ev := Evidence(map[string]any{
		"ok": "v", "nil": nil, "empty": "", "nested": map[string]any{"x": 1}, "list": []string{"a", "", "b"},
		"big": strings.Repeat("y", 5000), "num": 3.5, "nan": nan(), "n": 2,
	})
	if ev["ok"] != "v" || ev["num"] != 3.5 || ev["n"] != 2 || len(ev["big"].(string)) > 1024 {
		t.Fatalf("evidence %v", ev)
	}
	for _, k := range []string{"nil", "empty", "nested", "nan"} {
		if _, ok := ev[k]; ok {
			t.Errorf("%s kept", k)
		}
	}
	huge := map[string]any{}
	for i := 0; i < 100; i++ {
		huge[strings.Repeat("k", i+1)] = strings.Repeat("v", 1000)
	}
	if p := evidenceProblem(Evidence(huge)); p != "" {
		t.Fatalf("Evidence output invalid: %s", p)
	}
}

func nan() float64 { var z float64; return z / z }

func TestSeverityWords(t *testing.T) {
	for in, want := range map[string]model.Severity{"CRITICAL": "critical", "Error": "high", "warning": "medium", "note": "low", "Informational": "info", "weird": "medium"} {
		if got := Severity(in); got != want {
			t.Errorf("Severity(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestFinalizeDedupesAndSorts(t *testing.T) {
	fs := Finalize([]Finding{{Key: "b", Title: "first b"}, {Key: "a"}, {Key: "b", Title: "second b"}})
	if len(fs) != 2 || fs[0].Key != "a" || fs[1].Title != "first b" {
		t.Fatalf("finalize = %+v", fs)
	}
}

// Whatever a parser puts in a Finding, Normalize makes it valid.
func FuzzNormalize(f *testing.F) {
	f.Add("k", "title", "desc", "high", "rem", "tag", "arn:aws:s3:::x", "ev")
	f.Add("", "", "", "", "", "", "", "")
	f.Add(strings.Repeat("\x00", 600), "\n\t", "\xff\xfe", "CRITICAL", strings.Repeat("r", 5000), strings.Repeat("t", 100), "\x01", strings.Repeat("e", 20000))
	f.Fuzz(func(t *testing.T, key, title, desc, sev, rem, tag, asset, ev string) {
		fd := Normalize(Finding{
			Key: key, Title: title, Description: desc, Severity: model.Severity(sev), Remediation: rem,
			Tags: []string{tag, tag + "2"}, Asset: Asset{Key: asset}, Evidence: map[string]any{ev: ev, "x": []string{ev}},
		})
		obs := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
		r := &Request{Tool: "fuzz", Scope: "s", ObservedAt: &obs, Findings: []Finding{fd}}
		if p := Validate(r, Options{}); len(p) > 0 {
			t.Fatalf("normalized finding invalid: %s\n%+v", Summary(p), fd)
		}
	})
}
