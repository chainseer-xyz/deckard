package sarif

import (
	"fmt"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/ingesttest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestScan(t *testing.T) {
	fs := ingesttest.Golden(t, Tool, Parse, "scan.sarif")
	// Two Semgrep results remain (suppressed, absent and pass are dropped)
	// plus the two Trivy results.
	if len(fs) != 4 {
		t.Fatalf("findings = %d, want 4", len(fs))
	}
	by := map[string]ingest.Finding{}
	for _, f := range fs {
		by[strings.SplitN(f.Key, ":", 2)[0]] = f
	}
	if f := by["python.lang.security.audit.eval-detected.eval-detected"]; f.Severity != model.SeverityHigh ||
		f.Asset.Key != "https://github.com/example/app" || !strings.Contains(f.Key, "primaryLocationLineHash=") {
		t.Errorf("semgrep eval = %+v", f)
	}
	if f := by["yaml.github-actions.security.run-shell-injection.run-shell-injection"]; f.Severity != model.SeverityHigh ||
		!strings.Contains(f.Description, "github.event.pull_request.title") || !strings.HasPrefix(f.Title, "Possible shell injection") {
		t.Errorf("message string arguments not applied: %+v", f)
	}
	if f := by["CVE-2024-24790"]; f.Severity != model.SeverityCritical || f.Asset.Key != ingesttest.Scope || f.Remediation == "" {
		t.Errorf("trivy cve (extension rule, numeric security-severity) = %+v", f)
	}
	if f := by["no-rule-defined"]; f.Severity != model.SeverityLow {
		t.Errorf("note level = %s", f.Severity)
	}
	for _, f := range fs {
		if strings.Contains(f.Asset.Key, "fake-token") || strings.Contains(fmt.Sprint(f.Evidence["repository"]), "fake-token") {
			t.Errorf("repository credentials kept: %s", f.Asset.Key)
		}
	}
}

func TestCleanAndErrors(t *testing.T) {
	if fs := ingesttest.Golden(t, Tool, Parse, "clean.sarif"); len(fs) != 0 {
		t.Fatalf("clean = %d", len(fs))
	}
	for _, bad := range []string{"", `{}`, `{"version":"1.0.0","runs":[]}`, `{"version":"2.1.0"}`, `[]`, `{"version":"2.1.0","runs":[{"results":[{"level":7}]}]}`} {
		if _, err := Parse([]byte(bad), ingest.ParseOptions{}); err == nil {
			t.Errorf("Parse(%s) accepted", bad)
		}
	}
}

func FuzzParse(f *testing.F) {
	ingesttest.Seeds(f)
	f.Add([]byte(`{"version":"2.1.0","runs":[{"results":[{"ruleIndex":-1,"locations":[{"physicalLocation":{"region":{"startLine":-3}}}],"properties":{"security-severity":"NaN"}}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) { ingesttest.Fuzz(t, Tool, Parse, data) })
}
