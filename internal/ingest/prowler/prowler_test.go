package prowler

import (
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/ingesttest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestOCSF(t *testing.T) {
	fs := ingesttest.Golden(t, Tool, Parse, "ocsf.json")
	// PASS and MANUAL are skipped: three FAIL results remain.
	if len(fs) != 3 {
		t.Fatalf("findings = %d, want 3", len(fs))
	}
	byKey := map[string]ingest.Finding{}
	for _, f := range fs {
		byKey[f.Key] = f
	}
	s3 := byKey["s3_bucket_public_access:arn:aws:s3:::example-public-assets"]
	if s3.Severity != model.SeverityHigh || s3.Asset.Key != "arn:aws:s3:::example-public-assets" || s3.Remediation == "" {
		t.Fatalf("s3 finding = %+v", s3)
	}
	if byKey["iam_root_mfa_enabled:arn:aws:iam::123456789012:root"].Severity != model.SeverityCritical {
		t.Fatal("critical severity lost")
	}
	// No resource uid or name: an account/region-level key; severity from severity_id.
	gd, ok := byKey["guardduty_is_enabled:prowler:aws:123456789012:eu-west-1:guardduty_is_enabled"]
	if !ok || gd.Severity != model.SeverityMedium {
		t.Fatalf("account-level finding = %+v (keys %v)", gd, keys(byKey))
	}
}

func TestLegacy(t *testing.T) {
	fs := ingesttest.Golden(t, Tool, Parse, "legacy.json")
	if len(fs) != 2 {
		t.Fatalf("findings = %d, want 2 (PASS skipped)", len(fs))
	}
}

func TestEmptyAndLines(t *testing.T) {
	fs := ingesttest.Golden(t, Tool, Parse, "empty.json")
	if len(fs) != 0 {
		t.Fatalf("empty run = %d findings", len(fs))
	}
	lines := []byte(`{"CheckID":"a_check","Status":"FAIL","StatusExtended":"x","Severity":"low","ResourceArn":"arn:aws:s3:::a"}` + "\n\n" +
		`{"status_code":"FAIL","metadata":{"event_code":"b_check"},"severity":"High","status_detail":"y","resources":[{"uid":"arn:aws:s3:::b"}]}` + "\n")
	fs, err := Parse(lines, ingest.ParseOptions{})
	if err != nil || len(fs) != 2 {
		t.Fatalf("NDJSON: %d %v", len(fs), err)
	}
	for _, bad := range []string{"", " \n", `{"foo":1}`, `[1,2]`, `{"CheckID":`, `not json`} {
		if _, err := Parse([]byte(bad), ingest.ParseOptions{}); err == nil {
			t.Errorf("Parse(%s) accepted", bad)
		}
	}
}

func keys(m map[string]ingest.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func FuzzParse(f *testing.F) {
	ingesttest.Seeds(f)
	f.Add([]byte(`[{"status_code":"FAIL","resources":[{},{}]}]`))
	f.Fuzz(func(t *testing.T, data []byte) { ingesttest.Fuzz(t, Tool, Parse, data) })
}
