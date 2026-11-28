package finding

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/kubescape"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestKubescapeSecretReferenceException(t *testing.T) {
	const scope = "k8s://fixture-cluster/*"
	suppressor, err := NewSuppressor([]config.Suppression{{Match: "check=ext.kubescape control_id=C-0012 asset=" + scope + " credential_source=secretKeyRef", Reason: "Secret references are not inline credentials"}})
	if err != nil {
		t.Fatal(err)
	}
	const safe = `{"name":"DATABASE_PASSWORD","valueFrom":{"secretKeyRef":{"name":"db","key":"password"}}}`
	for _, tc := range []struct {
		name, env, control, path, cluster string
		want                              bool
	}{
		{"reference", safe, "C-0012", "spec.template.spec.containers[0].env[0].name", "fixture-cluster", true},
		{"reported value path", safe, "C-0012", "spec.template.spec.containers[0].env[0].value", "fixture-cluster", true},
		{"reference key path", safe, "C-0012", "spec.template.spec.containers[0].env[0].valueFrom.secretKeyRef.key", "fixture-cluster", true},
		{"inline", `{"name":"PASSWORD","value":"fictional-inline-value"}`, "C-0012", "spec.template.spec.containers[0].env[0].value", "fixture-cluster", false},
		{"mixed inline and reference", strings.TrimSuffix(safe, "}") + `,"value":"fictional-inline-value"}`, "C-0012", "spec.template.spec.containers[0].env[0].name", "fixture-cluster", false},
		{"missing object", `null`, "C-0012", "spec.template.spec.containers[0].env[0].name", "fixture-cluster", false},
		{"unknown path", safe, "C-0012", "spec.template.spec.containers[0].envFrom[0].secretRef.name", "fixture-cluster", false},
		{"missing path", safe, "C-0012", "", "fixture-cluster", false},
		{"wrong index", safe, "C-0012", "spec.template.spec.containers[0].env[1].name", "fixture-cluster", false},
		{"wrong control", safe, "C-0271", "spec.template.spec.containers[0].env[0].name", "fixture-cluster", false},
		{"wrong scope", safe, "C-0012", "spec.template.spec.containers[0].env[0].name", "another-cluster", false},
		{"config reference", `{"name":"PASSWORD","valueFrom":{"configMapKeyRef":{"name":"config","key":"password"}}}`, "C-0012", "spec.template.spec.containers[0].env[0].name", "fixture-cluster", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var env any
			if err := json.Unmarshal([]byte(tc.env), &env); err != nil {
				t.Fatal(err)
			}
			report := map[string]any{"clusterName": tc.cluster, "resources": []any{map[string]any{"resourceID": "apps/v1/example/Deployment/api", "object": map[string]any{"kind": "Deployment", "metadata": map[string]any{"name": "api", "namespace": "example"}, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"env": []any{env}}}}}}}}}, "results": []any{map[string]any{"resourceID": "apps/v1/example/Deployment/api", "controls": []any{map[string]any{"controlID": tc.control, "status": "failed", "rules": []any{map[string]any{"paths": []any{map[string]any{"failedPath": tc.path}}}}}}}}}
			data, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			findings, err := kubescape.Parse(data, ingest.ParseOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 {
				t.Fatalf("findings=%d", len(findings))
			}
			f := findings[0]
			_, _, got := suppressor.Match(model.Finding{Check: "ext.kubescape", AssetKey: f.Asset.Key, Evidence: f.Evidence}, time.Now())
			if got != tc.want {
				t.Fatalf("suppressed=%v want %v; evidence=%v", got, tc.want, f.Evidence)
			}
			encoded, _ := json.Marshal(f.Evidence)
			if strings.Contains(string(encoded), "fictional-inline-value") {
				t.Fatal("credential value retained in evidence")
			}
		})
	}
	for _, match := range []string{"credential_source=secretKeyRef", "check=ext.kubescape control_id=C-0271 credential_source=secretKeyRef", "check=ext.kubescape control_id=C-0012 credential_source=*"} {
		if _, err := NewSuppressor([]config.Suppression{{Match: match}}); err == nil {
			t.Fatalf("accepted invalid exception %s", match)
		}
	}
	// Historical evidence without a report-derived source marker must stay active.
	_, _, matched := suppressor.Match(model.Finding{Check: "ext.kubescape", AssetKey: "k8s://fixture-cluster/resource", Evidence: map[string]any{"control_id": "C-0012", "failed_paths": []string{"spec.template.spec.containers[0].env[0].name"}}}, time.Now())
	if matched {
		t.Fatal("historical evidence accepted without source proof")
	}
}
