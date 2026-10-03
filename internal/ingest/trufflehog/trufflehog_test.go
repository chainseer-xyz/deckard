package trufflehog

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

// fakeSecrets are the values planted in testdata: secrets, partial secrets,
// detector extra data and a credential inside a repository URL. None may
// appear anywhere in the generated request.
var fakeSecrets = []string{
	"deckard-fixture-FAKE-aws-id-0001",
	"deckard-fixture-FAKE-aws-secret-0001",
	"deckard-fixture-FAKE-leak-in-extradata",
	"deckard-fixture-FAKE-url-token",
	"deckard-fixture-FAKE-slack-webhook-0002",
	"deckard-fixture-FAKE-slack-redacted",
	"private-key-0003",
	"deckard-fixture-FAKE-key-redacted",
	"deckard-fixture-FAKE-structured",
	"dev@example.com",
}

func TestGit(t *testing.T) {
	fs := ingesttest.Golden(t, Tool, Parse, "git.jsonl")
	if len(fs) != 3 {
		t.Fatalf("findings = %d, want 3 (the repeated result is deduplicated)", len(fs))
	}
	sev := map[string]model.Severity{}
	for _, f := range fs {
		sev[strings.SplitN(f.Key, ":", 2)[0]] = f.Severity
		if f.Evidence["secret_hash"] == nil || !strings.HasPrefix(f.Evidence["secret_hash"].(string), "sha256:") {
			t.Errorf("%s: no secret hash", f.Key)
		}
	}
	if sev["AWS"] != model.SeverityHigh || sev["SlackWebhook"] != model.SeverityMedium || sev["PrivateKey"] != model.SeverityMedium {
		t.Fatalf("severities %v", sev)
	}
}

// The redaction rule: the request built from the fixtures carries none of
// the fake secrets, in any field.
func TestNoSecretInRequest(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("testdata", "git.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Parse(in, ingest.ParseOptions{Scope: ingesttest.Scope})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(ingesttest.Request(Tool, fs))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range fakeSecrets {
		if strings.Contains(string(b), s) {
			t.Errorf("request contains %q", s)
		}
		if !strings.Contains(string(in), s) {
			t.Errorf("fixture lost %q: the test would prove nothing", s)
		}
	}
	// The same holds for the error a malformed line produces.
	_, err = Parse(append(in, []byte(`{"DetectorName":"AWS","Raw":"deckard-fixture-FAKE-aws-secret-0001`)...), ingest.ParseOptions{})
	if err == nil || strings.Contains(err.Error(), "FAKE") {
		t.Fatalf("malformed line error = %v", err)
	}
}

func TestEmptyAndErrors(t *testing.T) {
	if fs := ingesttest.Golden(t, Tool, Parse, "empty.jsonl"); len(fs) != 0 {
		t.Fatalf("empty = %d", len(fs))
	}
	for _, bad := range []string{`{"Raw":"x"}`, `[1]`, `nope`} {
		if _, err := Parse([]byte(bad), ingest.ParseOptions{}); err == nil {
			t.Errorf("Parse(%s) accepted", bad)
		}
	}
}

func FuzzParse(f *testing.F) {
	ingesttest.Seeds(f)
	f.Add([]byte(`{"DetectorName":"X","SourceMetadata":{"Data":{"Git":{"line":-1,"repository":"https://u:p@h/x"}}}}`))
	f.Fuzz(func(t *testing.T, data []byte) { ingesttest.Fuzz(t, Tool, Parse, data) })
}

// Whatever the rest of a result says, a value planted in Raw, RawV2,
// Redacted or ExtraData never reaches the request.
func FuzzRedaction(f *testing.F) {
	f.Add("AWS", "config/app.yaml", "https://github.com/example/app.git", "AKIA-ish", 12, true)
	f.Add("", "", "", "", 0, false)
	f.Fuzz(func(t *testing.T, detector, file, repo, suffix string, line int, verified bool) {
		const mark = "SECRETMARK"
		for _, s := range []string{detector, file, repo} {
			if strings.Contains(strings.ToUpper(s), mark) {
				return // the marker came in through a location field
			}
		}
		if detector == "" {
			detector = "X"
		}
		secret := mark + suffix
		in, _ := json.Marshal(map[string]any{
			"SourceMetadata": map[string]any{"Data": map[string]any{"Git": map[string]any{"file": file, "repository": repo, "line": line}}},
			"DetectorName":   detector, "Verified": verified, "Raw": secret, "RawV2": "id:" + secret, "Redacted": secret,
			"ExtraData": map[string]any{"token": secret},
		})
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
