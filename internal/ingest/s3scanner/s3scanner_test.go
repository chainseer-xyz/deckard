package s3scanner

import (
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/ingesttest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestScan(t *testing.T) {
	fs := ingesttest.Golden(t, Tool, Parse, "scan.jsonl")
	want := map[string]model.Severity{
		"aws:example-public-site:all-users-read":     model.SeverityHigh,
		"aws:example-public-site:auth-users-read":    model.SeverityMedium,
		"aws:example-uploads:all-users-write":        model.SeverityCritical,
		"aws:example-uploads:auth-users-write":       model.SeverityHigh,
		"digitalocean:example-assets:all-users-read": model.SeverityHigh,
	}
	if len(fs) != len(want) {
		t.Fatalf("findings = %d, want %d (unknown permissions, private and missing buckets are not findings)", len(fs), len(want))
	}
	for _, f := range fs {
		if sev, ok := want[f.Key]; !ok || sev != f.Severity {
			t.Errorf("%s: %s (expected %v)", f.Key, f.Severity, ok)
		}
	}
	if fs[0].Asset.Key != "arn:aws:s3:::example-public-site" {
		t.Errorf("aws asset = %s", fs[0].Asset.Key)
	}
}

func TestEmptyAndErrors(t *testing.T) {
	if fs := ingesttest.Golden(t, Tool, Parse, "empty.jsonl"); len(fs) != 0 {
		t.Fatalf("empty = %d", len(fs))
	}
	for _, bad := range []string{"nope", `{"level":"fatal","msg":"no credentials"}`, `{"level":"error","msg":"throttled"}`} {
		if _, err := Parse([]byte(bad), ingest.ParseOptions{}); err == nil {
			t.Errorf("Parse(%s) accepted", bad)
		}
	}
}

func FuzzParse(f *testing.F) {
	ingesttest.Seeds(f)
	f.Add([]byte(`{"bucket":{"name":" ","exists":1,"perm_all_users_read":1}}`))
	f.Fuzz(func(t *testing.T, data []byte) { ingesttest.Fuzz(t, Tool, Parse, data) })
}
