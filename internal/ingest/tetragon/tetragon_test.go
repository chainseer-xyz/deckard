package tetragon

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const policyEvent = `{"process_kprobe":{"process":{"exec_id":"event-process-1","arguments":"--password SECRET-COMMAND","environment_variables":[{"Key":"TOKEN","Value":"SECRET-ENV"}],"pod":{"namespace":"apps","name":"web-abc","uid":"pod-123","pod_annotations":{"token":"SECRET-ANNOTATION"}}},"policy_name":"sensitive-file-write","function_name":"security_file_permission","action":"KPROBE_ACTION_POST","args":[{"string_arg":"SECRET-REQUEST"}],"message":"SECRET-MESSAGE"},"node_name":"worker-1","cluster_name":"untrusted-display-name","time":"2026-10-14T12:00:00Z"}`

func TestPolicyEventBecomesNonprobeableIncident(t *testing.T) {
	got, err := Parse([]byte(policyEvent), ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
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
	if f.Evidence["runtime_cluster_id"] != "uid:cluster-123" || f.Evidence["runtime_namespace"] != "apps" || f.Evidence["runtime_pod_uid"] != "pod-123" || f.Evidence["runtime_rule"] != "sensitive-file-write" {
		t.Fatalf("missing exact workload evidence: %#v", f.Evidence)
	}
}

func TestNativeAggregationAndSimultaneousHooksCountEvents(t *testing.T) {
	first := strings.Replace(policyEvent, `"node_name"`, `"aggregation_info":{"count":"3"},"node_name"`, 1)
	second := strings.ReplaceAll(policyEvent, "security_file_permission", "security_inode_permission")
	got, err := Parse([]byte(first+"\n"+second+"\n"+first), ingest.ParseOptions{Scope: "marina-staging"})
	if err != nil || len(got) != 1 || got[0].Evidence["runtime_batch_count"] != int64(4) {
		t.Fatalf("native aggregation lost: %+v %v", got, err)
	}
	for _, count := range []string{`"0"`, `"1000000001"`, `"SECRET"`, `-1`, `1.5`} {
		bad := strings.Replace(first, `"count":"3"`, `"count":`+count, 1)
		if out, err := Parse([]byte(bad), ingest.ParseOptions{Scope: "marina-staging"}); err == nil || len(out) != 0 {
			t.Fatalf("invalid aggregate count accepted: %+v %v", out, err)
		}
	}
}

func TestProtobufJSONFieldNamesAndEnforcementActions(t *testing.T) {
	camel := strings.NewReplacer("process_kprobe", "processKprobe", "policy_name", "policyName", "node_name", "nodeName", "exec_id", "execId", "function_name", "functionName").Replace(policyEvent)
	for _, input := range []string{camel, strings.ReplaceAll(policyEvent, `"KPROBE_ACTION_POST"`, `3`), strings.ReplaceAll(policyEvent, "KPROBE_ACTION_POST", "KPROBE_ACTION_SIGNAL"), strings.ReplaceAll(policyEvent, "KPROBE_ACTION_POST", "KPROBE_ACTION_OVERRIDE")} {
		got, err := Parse([]byte(input), ingest.ParseOptions{Scope: "marina-staging"})
		if err != nil || len(got) != 1 {
			t.Fatalf("valid protobuf event rejected: %+v %v", got, err)
		}
		if input != camel && got[0].Severity != model.SeverityHigh {
			t.Fatalf("enforcement severity lost: %+v", got[0])
		}
	}
}

func TestInputBoundsAndScopeAreEnforced(t *testing.T) {
	if out, err := Parse(bytes.Repeat([]byte(" "), MaxInputBytes+1), ingest.ParseOptions{Scope: "marina-staging"}); err == nil || len(out) != 0 {
		t.Fatal("oversized input accepted")
	}
	if out, err := Parse([]byte(policyEvent), ingest.ParseOptions{}); err == nil || len(out) != 0 {
		t.Fatal("missing operator scope accepted")
	}
	bad := strings.ReplaceAll(policyEvent, "2026-10-14T12:00:00Z", "0001-01-01T00:00:00Z")
	if out, err := Parse([]byte(bad), ingest.ParseOptions{Scope: "marina-staging"}); err == nil || len(out) != 0 {
		t.Fatal("zero event timestamp accepted")
	}
}

func TestMissingIdentityTupleCannotAliasAnotherWorkload(t *testing.T) {
	base := strings.ReplaceAll(policyEvent, `"uid":"pod-123",`, "")
	a := strings.NewReplacer("web-abc", "a|b", "worker-1", "c").Replace(base)
	b := strings.NewReplacer("web-abc", "a", "worker-1", "b|c").Replace(base)
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
		"empty object":      `{}`,
		"null":              `null`,
		"unknown event":     `{"process_future":{},"time":"2026-10-14T12:00:00Z"}`,
		"multiple events":   `{"process_exec":{"process":{}},"process_exit":{"process":{}}}`,
		"missing process":   `{"process_kprobe":{"policy_name":"detect"},"time":"2026-10-14T12:00:00Z"}`,
		"invalid namespace": strings.ReplaceAll(policyEvent, `"apps"`, `"apps/token=SECRET"`),
		"invalid timestamp": strings.ReplaceAll(policyEvent, "2026-10-14T12:00:00Z", "SECRET-TIMESTAMP"),
		"dropped events":    `{"rate_limit_info":{"number_of_dropped_process_events":"2"}}`,
		"throttle":          `{"process_throttle":{"type":"THROTTLE_START"}}`,
		"truncated":         `{"process_kprobe":`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Parse([]byte(policyEvent+"\n"+invalid), ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
			if err == nil || len(got) != 0 {
				t.Fatalf("malformed/loss batch must reject whole: %d findings, %v", len(got), err)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("error echoed sensitive input")
			}
		})
	}
}

func TestRoutineTelemetryAndUnnamedTracingAreNotSecurityFindings(t *testing.T) {
	for _, input := range []string{"", "[]", `{"process_exec":{"process":{"binary":"/usr/bin/curl","arguments":"SECRET"}}}`, `{"process_exit":{"process":{"pid":12},"status":0}}`, strings.ReplaceAll(policyEvent, `"sensitive-file-write"`, `""`)} {
		got, err := Parse([]byte(input), ingest.ParseOptions{Scope: "marina-staging"})
		if err != nil || len(got) != 0 {
			t.Fatalf("ordinary telemetry became an incident: %+v, %v", got, err)
		}
	}
}

func TestNamedPolicyEventKindsAreSupported(t *testing.T) {
	for _, kind := range []string{"process_kprobe", "process_tracepoint", "process_uprobe", "process_lsm", "process_usdt"} {
		t.Run(kind, func(t *testing.T) {
			got, err := Parse([]byte(strings.ReplaceAll(policyEvent, "process_kprobe", kind)), ingest.ParseOptions{Scope: "marina-staging"})
			if err != nil || len(got) != 1 {
				t.Fatalf("named policy event lost: %+v %v", got, err)
			}
			if _, ok := got[0].Evidence["runtime_cluster_id"]; ok {
				t.Fatal("native cluster_name invented immutable cluster identity")
			}
			encoded, _ := json.Marshal(got)
			if strings.Contains(string(encoded), "SECRET") || strings.Contains(string(encoded), "untrusted-display-name") {
				t.Fatalf("raw data retained: %s", encoded)
			}
		})
	}
}

func TestIncidentBatchIsOrderIndependentAndDeduplicated(t *testing.T) {
	later := strings.ReplaceAll(policyEvent, "12:00:00Z", "12:01:00Z")
	later = strings.ReplaceAll(later, "KPROBE_ACTION_POST", "KPROBE_ACTION_SIGKILL")
	o := ingest.ParseOptions{Scope: "k8s:uid:cluster-123"}
	a, err := Parse([]byte("["+later+","+policyEvent+","+later+"]"), o)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(policyEvent+"\n"+later+"\n"+later), o)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || len(a) != 1 {
		t.Fatalf("reordered batch differs: %+v versus %+v", a, b)
	}
	one, _ := Parse([]byte(policyEvent), o)
	if a[0].Key != one[0].Key || a[0].Severity != model.SeverityHigh || a[0].Evidence["runtime_batch_count"] != int64(2) ||
		a[0].Evidence["runtime_first_seen"] != "2026-10-14T12:00:00Z" || a[0].Evidence["runtime_last_seen"] != "2026-10-14T12:01:00Z" {
		t.Fatalf("wrong incident aggregation: %+v", a[0])
	}
}
