package tetragon

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
)

func TestEventAndIncidentCountsAreBounded(t *testing.T) {
	many := "[" + strings.Repeat(`{"process_exec":{"process":{}}}`+",", maxEvents) + `{"process_exec":{"process":{}}}` + "]"
	if out, err := Parse([]byte(many), ingest.ParseOptions{Scope: "marina-staging"}); err == nil || len(out) != 0 || !strings.Contains(err.Error(), "event count") {
		t.Fatalf("event limit not enforced: %v", err)
	}
	var batch strings.Builder
	for i := 0; i <= ingest.MaxFindings; i++ {
		input := strings.ReplaceAll(policyEvent, `sensitive-file-write`, fmt.Sprintf("rule-%d", i))
		batch.WriteString(input)
		batch.WriteByte('\n')
	}
	if out, err := Parse([]byte(batch.String()), ingest.ParseOptions{Scope: "marina-staging"}); err == nil || len(out) != 0 || !strings.Contains(err.Error(), "incident count") {
		t.Fatalf("incident limit not enforced: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	for _, input := range []string{policyEvent, "null", "[]", "{}", ""} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		out, err := Parse(data, ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
		if err != nil {
			return
		}
		at := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
		req := ingest.Request{Tool: Tool, Scope: "k8s:uid:cluster-123", ObservedAt: &at, Findings: out, Complete: false}
		if problems := ingest.Validate(&req, ingest.Options{}); len(problems) != 0 {
			t.Fatalf("parser emitted invalid wire data: %+v", problems)
		}
		encoded, _ := json.Marshal(out)
		if len(encoded) > ingest.MaxBodyBytes {
			t.Fatal("parser exceeded wire body limit")
		}
	})
}
