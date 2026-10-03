package gitleaks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/ingesttest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// fakeSecrets are planted in the fixture's Secret, Match, Line, Message,
// Email and Link fields; none may appear in the generated request.
var fakeSecrets = []string{
	"fakefakefake-gl-secret-0001", "fakefakefake-gl-match-0001", "fakefakefake-gl-line-0001",
	"fakefakefake-gl-secret-0002", "fakefakefake-gl-match-0002", "fakefakefake-gl-line-0002",
	"fakefakefake-gl-message-0001", "fakefakefake-gl-urltoken", "dev@example.com",
}

func TestReport(t *testing.T) {
	fs := ingesttest.Golden(t, Tool, Parse, "report.json")
	// The first and third leak are the same secret at the same place: one finding.
	if len(fs) != 2 {
		t.Fatalf("findings = %d, want 2", len(fs))
	}
	for _, f := range fs {
		if f.Severity != model.SeverityMedium || !strings.HasPrefix(f.Evidence["secret_hash"].(string), "sha256:") {
			t.Errorf("%s: %s %v", f.Key, f.Severity, f.Evidence["secret_hash"])
		}
	}
	if fs[0].Asset.Key != "https://github.com/example/billing" || fs[1].Asset.Key != ingesttest.Scope {
		t.Fatalf("assets %q %q", fs[0].Asset.Key, fs[1].Asset.Key)
	}
}

func TestNoSecretInRequest(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("testdata", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Parse(in, ingest.ParseOptions{Scope: ingesttest.Scope})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ingesttest.Request(Tool, fs))
	for _, s := range fakeSecrets {
		if !strings.Contains(string(in), s) {
			t.Errorf("fixture lost %q: the test would prove nothing", s)
		}
		if strings.Contains(string(b), s) {
			t.Errorf("request contains %q", s)
		}
	}
	// A type error must not quote the secret either.
	_, err = Parse([]byte(`[{"Secret": 5, "Match": "fakefakefake-gl-secret-0001"}]`), ingest.ParseOptions{})
	if err == nil || strings.Contains(err.Error(), "fakefake") {
		t.Fatalf("error = %v", err)
	}
}

func TestCleanAndErrors(t *testing.T) {
	if fs := ingesttest.Golden(t, Tool, Parse, "clean.json"); len(fs) != 0 {
		t.Fatalf("clean = %d", len(fs))
	}
	for _, bad := range []string{"", "  ", "{}", "null x", "not json"} {
		if _, err := Parse([]byte(bad), ingest.ParseOptions{}); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func FuzzParse(f *testing.F) {
	ingesttest.Seeds(f)
	f.Add([]byte(`[{"StartLine":-5,"Link":"https://u:p@h/x/blob/y"}]`))
	f.Fuzz(func(t *testing.T, data []byte) { ingesttest.Fuzz(t, Tool, Parse, data) })
}

// A value planted in Secret, Match, Line, Message or Email never reaches the
// request, whatever the other fields say.
func FuzzRedaction(f *testing.F) {
	f.Add("generic-api-key", "a/b.py", "desc", "x", 3)
	f.Fuzz(func(t *testing.T, rule, file, desc, suffix string, line int) {
		const mark = "SECRETMARK"
		for _, s := range []string{rule, file, desc} {
			if strings.Contains(strings.ToUpper(s), mark) {
				return
			}
		}
		secret := mark + suffix
		in, _ := json.Marshal([]map[string]any{{"RuleID": rule, "File": file, "Description": desc, "StartLine": line,
			"Secret": secret, "Match": "k=" + secret, "Line": "k=" + secret, "Message": secret, "Email": secret}})
		fs, err := Parse(in, ingest.ParseOptions{Scope: ingesttest.Scope})
		if err != nil {
			return
		}
		ingesttest.Valid(t, Tool, fs)
		b, _ := json.Marshal(ingesttest.Request(Tool, fs))
		if strings.Contains(strings.ToUpper(string(b)), mark) {
			t.Fatalf("secret marker in request: %s", b)
		}
	})
}
