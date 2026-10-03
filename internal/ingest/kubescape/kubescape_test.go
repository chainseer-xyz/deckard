package kubescape

import (
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/ingesttest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestResults(t *testing.T) {
	fs := ingesttest.Golden(t, Tool, Parse, "results.json")
	if len(fs) != 3 {
		t.Fatalf("findings = %d, want 3 (passed and skipped controls dropped)", len(fs))
	}
	want := map[string]model.Severity{
		"C-0017:path=1/api=apps/v1/payments/Deployment/api":                   model.SeverityLow,
		"C-0057:path=2/api=apps/v1/kube-system/DaemonSet/node-agent":          model.SeverityHigh,
		"C-0035:rbac.authorization.k8s.io/v1//ClusterRoleBinding/ci-deployer": model.SeverityMedium,
	}
	for _, f := range fs {
		if sev, ok := want[f.Key]; !ok || f.Severity != sev {
			t.Errorf("%s severity %s (known %v)", f.Key, f.Severity, ok)
		}
		if f.Asset.Key[:len("k8s://prod-example/")] != "k8s://prod-example/" {
			t.Errorf("asset %s not qualified by the cluster", f.Asset.Key)
		}
	}
}

func TestCleanClusterAndErrors(t *testing.T) {
	if fs := ingesttest.Golden(t, Tool, Parse, "clean.json"); len(fs) != 0 {
		t.Fatalf("clean cluster = %d findings", len(fs))
	}
	for _, bad := range []string{`[]`, `{}`, `not json`, `{"results":[{"controls":[{"status":7}]}]`} {
		if _, err := Parse([]byte(bad), ingest.ParseOptions{}); err == nil {
			t.Errorf("Parse(%s) accepted", bad)
		}
	}
}

func FuzzParse(f *testing.F) {
	ingesttest.Seeds(f)
	f.Add([]byte(`{"results":[{"resourceID":"","controls":[{"status":"failed"}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) { ingesttest.Fuzz(t, Tool, Parse, data) })
}
