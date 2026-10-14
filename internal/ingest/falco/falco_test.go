package falco

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const ruleEvent = `{"time":"2026-10-14T12:00:00Z","rule":"Terminal shell in container","priority":"Warning","source":"syscall","hostname":"worker-1","output":"SECRET-OUTPUT","output_fields":{"k8s.ns.name":"apps","k8s.pod.name":"web-abc","k8s.pod.uid":"pod-123","container.id":"container-123","proc.cmdline":"SECRET-COMMAND","evt.args":"SECRET-REQUEST"}}`

func TestRuleEventBecomesNonprobeableIncident(t *testing.T) {
	got, err := Parse([]byte(ruleEvent), ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d incidents, want 1", len(got))
	}
	f := got[0]
	if f.Asset.Kind != model.KindCloudResource || f.Asset.Ref != nil || f.Severity != model.SeverityMedium {
		t.Fatalf("incident must remain nonprobeable: %+v", f)
	}
	if f.Evidence["runtime_cluster_id"] != "uid:cluster-123" || f.Evidence["runtime_namespace"] != "apps" || f.Evidence["runtime_pod_uid"] != "pod-123" || f.Evidence["runtime_rule"] != "Terminal shell in container" {
		t.Fatalf("missing exact workload evidence: %#v", f.Evidence)
	}
}

func TestHostAlertsAcceptNativeMissingKubernetesPlaceholders(t *testing.T) {
	input := strings.NewReplacer("apps", "<NA>", "pod-123", "<NA>", "web-abc", "<NA>", "container-123", "<NA>").Replace(ruleEvent)
	got, err := Parse([]byte(input), ingest.ParseOptions{Scope: "marina-staging"})
	if err != nil || len(got) != 1 {
		t.Fatalf("host alert rejected: %+v %v", got, err)
	}
	if _, ok := got[0].Evidence["runtime_pod_uid"]; ok {
		t.Fatal("placeholder became a PodUID")
	}
	if _, ok := got[0].Evidence["runtime_namespace"]; ok {
		t.Fatal("placeholder became a namespace")
	}
}

func TestInputBoundsAndScopeAreEnforced(t *testing.T) {
	if out, err := Parse(bytes.Repeat([]byte(" "), MaxInputBytes+1), ingest.ParseOptions{Scope: "marina-staging"}); err == nil || len(out) != 0 {
		t.Fatal("oversized input accepted")
	}
	if out, err := Parse([]byte(ruleEvent), ingest.ParseOptions{}); err == nil || len(out) != 0 {
		t.Fatal("missing operator scope accepted")
	}
	bad := strings.ReplaceAll(ruleEvent, "2026-10-14T12:00:00Z", "0001-01-01T00:00:00Z")
	if out, err := Parse([]byte(bad), ingest.ParseOptions{Scope: "marina-staging"}); err == nil || len(out) != 0 {
		t.Fatal("zero event timestamp accepted")
	}
}

func TestMissingIdentityTupleCannotAliasAnotherWorkload(t *testing.T) {
	base := strings.ReplaceAll(ruleEvent, `"k8s.pod.uid":"pod-123",`, "")
	a := strings.NewReplacer("web-abc", "a|b", "container-123", "c").Replace(base)
	b := strings.NewReplacer("web-abc", "a", "container-123", "b|c").Replace(base)
	first, err := Parse([]byte(a), ingest.ParseOptions{Scope: "marina-staging"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Parse([]byte(b), ingest.ParseOptions{Scope: "marina-staging"})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Key == second[0].Key || first[0].Asset.Key == second[0].Asset.Key {
		t.Fatal("distinct unproven workload identities aliased")
	}
}

func TestMalformedOrLossMarkedBatchIsRejectedWhole(t *testing.T) {
	for name, invalid := range map[string]string{
		"empty object":          `{}`,
		"null":                  `null`,
		"missing rule":          strings.ReplaceAll(ruleEvent, `"Terminal shell in container"`, `""`),
		"missing priority":      strings.ReplaceAll(ruleEvent, `"Warning"`, `""`),
		"invalid namespace":     strings.ReplaceAll(ruleEvent, `"apps"`, `"apps/token=SECRET"`),
		"invalid timestamp":     strings.ReplaceAll(ruleEvent, "2026-10-14T12:00:00Z", "SECRET-TIMESTAMP"),
		"invalid pod UID":       strings.ReplaceAll(ruleEvent, `"pod-123"`, `"token=SECRET"`),
		"invalid identity type": strings.ReplaceAll(ruleEvent, `"pod-123"`, `123`),
		"dropped events":        `{"rule":"Falco internal: syscall event drop","source":"internal","priority":"Critical","time":"2026-10-14T12:00:00Z"}`,
		"truncated":             `{"rule":`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Parse([]byte(ruleEvent+"\n"+invalid), ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
			if err == nil || len(got) != 0 {
				t.Fatalf("malformed/loss batch must reject whole: %d findings, %v", len(got), err)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("error echoed sensitive input")
			}
		})
	}
}

func TestFalcoPriorityUsesItsNativeScale(t *testing.T) {
	for priority, want := range map[string]model.Severity{"Emergency": model.SeverityCritical, "Alert": model.SeverityCritical, "Critical": model.SeverityCritical, "Error": model.SeverityHigh, "Warning": model.SeverityMedium, "Notice": model.SeverityLow, "Informational": model.SeverityInfo, "Debug": model.SeverityInfo} {
		t.Run(priority, func(t *testing.T) {
			got, err := Parse([]byte(strings.ReplaceAll(ruleEvent, "Warning", priority)), ingest.ParseOptions{Scope: "marina-staging"})
			if err != nil || len(got) != 1 || got[0].Severity != want {
				t.Fatalf("priority %s: %+v %v", priority, got, err)
			}
			if _, ok := got[0].Evidence["runtime_cluster_id"]; ok {
				t.Fatal("opaque scope invented immutable cluster identity")
			}
			encoded, _ := json.Marshal(got)
			if strings.Contains(string(encoded), "SECRET") {
				t.Fatalf("raw data retained: %s", encoded)
			}
		})
	}
}

func TestIncidentBatchIsOrderIndependentAndDeduplicated(t *testing.T) {
	later := strings.ReplaceAll(ruleEvent, "12:00:00Z", "12:01:00Z")
	later = strings.ReplaceAll(later, "Warning", "Critical")
	o := ingest.ParseOptions{Scope: "k8s:uid:cluster-123"}
	a, err := Parse([]byte("["+later+","+ruleEvent+","+later+"]"), o)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(ruleEvent+"\n"+later+"\n"+later), o)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || len(a) != 1 {
		t.Fatalf("reordered batch differs: %+v versus %+v", a, b)
	}
	one, _ := Parse([]byte(ruleEvent), o)
	if a[0].Key != one[0].Key || a[0].Severity != model.SeverityCritical || a[0].Evidence["runtime_batch_count"] != int64(2) ||
		a[0].Evidence["runtime_first_seen"] != "2026-10-14T12:00:00Z" || a[0].Evidence["runtime_last_seen"] != "2026-10-14T12:01:00Z" {
		t.Fatalf("wrong incident aggregation: %+v", a[0])
	}
}
