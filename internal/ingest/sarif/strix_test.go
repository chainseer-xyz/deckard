package sarif

import (
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Minimal compatibility fixture shaped by Strix v1.7.0's report/sarif.py.
// Coverage rows are not findings, and interrupted runs are not clean scans.
func TestStrixSARIFCompatibility(t *testing.T) {
	data := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Strix","version":"1.7.0","rules":[{"id":"CWE-306","shortDescription":{"text":"Authentication required"},"properties":{"security-severity":"9.5"}}]}},"invocations":[{"executionSuccessful":true}],"results":[{"ruleId":"CWE-306","kind":"fail","level":"error","message":{"text":"Administrative route lacks authentication"},"locations":[{"logicalLocations":[{"fullyQualifiedName":"https://app.example.com/admin"}]}],"partialFingerprints":{"primaryLocationLineHash":"stable-route-identity"}},{"ruleId":"coverage:sql","kind":"pass","level":"none","message":{"text":"No issue identified"}},{"ruleId":"coverage:auth","kind":"open","level":"none","message":{"text":"Needs follow-up"}}]}]}`
	findings, err := Parse([]byte(data), ingest.ParseOptions{Scope: "app:example:staging"})
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings: %+v %v", findings, err)
	}
	if findings[0].Severity != model.SeverityCritical || !strings.Contains(findings[0].Key, "stable-route-identity") {
		t.Fatalf("lost severity or stable identity: %+v", findings[0])
	}
	failed := strings.Replace(data, `"executionSuccessful":true`, `"executionSuccessful":false`, 1)
	if _, err := Parse([]byte(failed), ingest.ParseOptions{}); err == nil {
		t.Fatal("failed agentic scan accepted")
	}
}
