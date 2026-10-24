// Package tetragon imports named tracing-policy events, not routine process telemetry.
package tetragon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const Tool = "tetragon"
const MaxInputBytes = 64 << 20

// Parse returns incidents only. Callers must always submit Complete=false:
// silence in an event stream is never a clean observation.
func Parse(data []byte, o ingest.ParseOptions) ([]ingest.Finding, error) {
	return parseBatch(data, o)
}

func parseEvent(data []byte, o ingest.ParseOptions) (observation, error) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil || raw == nil {
		return observation{}, fmt.Errorf("tetragon event is not valid JSON")
	}
	if err := canonicalize(raw, [][2]string{{"processKprobe", "process_kprobe"}, {"processTracepoint", "process_tracepoint"}, {"processUprobe", "process_uprobe"}, {"processLsm", "process_lsm"}, {"processUsdt", "process_usdt"}, {"processExec", "process_exec"}, {"processExit", "process_exit"}, {"processLoader", "process_loader"}, {"processThrottle", "process_throttle"}, {"rateLimitInfo", "rate_limit_info"}, {"nodeName", "node_name"}, {"aggregationInfo", "aggregation_info"}}); err != nil {
		return observation{}, err
	}
	kind, payload, err := eventPayload(raw)
	if err != nil {
		return observation{}, err
	}
	if kind == "rate_limit_info" || kind == "process_throttle" {
		return observation{}, fmt.Errorf("runtime sensor reports dropped or throttled events")
	}
	if kind == "process_exec" || kind == "process_exit" || kind == "process_loader" || kind == "test" {
		return observation{}, nil
	}
	var e envelope
	var hit policyHit
	encoded, _ := json.Marshal(raw)
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil {
		return observation{}, fmt.Errorf("runtime policy event is invalid")
	}
	if err := canonicalize(fields, [][2]string{{"policyName", "policy_name"}, {"functionName", "function_name"}}); err != nil {
		return observation{}, err
	}
	if process, exists := fields["process"]; exists && string(process) != "null" {
		var object map[string]json.RawMessage
		if json.Unmarshal(process, &object) != nil {
			return observation{}, fmt.Errorf("runtime process is invalid")
		}
		if err := canonicalize(object, [][2]string{{"execId", "exec_id"}}); err != nil {
			return observation{}, err
		}
		fields["process"], _ = json.Marshal(object)
	}
	payload, _ = json.Marshal(fields)
	if json.Unmarshal(encoded, &e) != nil || json.Unmarshal(payload, &hit) != nil {
		return observation{}, fmt.Errorf("runtime policy event has invalid field types")
	}
	if hit.PolicyName == "" {
		return observation{}, nil // Tracing telemetry is not itself a security alert.
	}
	if hit.Process == nil || ingest.Line(hit.PolicyName, 256) != hit.PolicyName {
		return observation{}, fmt.Errorf("runtime policy event requires a bounded policy name and process")
	}
	pod := hit.Process.Pod
	if !identityPart(pod.Namespace, 253) || !identityPart(pod.UID, 128) {
		return observation{}, fmt.Errorf("runtime workload identity is invalid")
	}
	subject := eventID(pod.Namespace, pod.UID, pod.Name, e.Node)
	if pod.UID != "" {
		subject = "pod:" + pod.Namespace + "/" + pod.UID
	}
	at, err := time.Parse(time.RFC3339Nano, e.Time)
	if err != nil || at.IsZero() {
		return observation{}, fmt.Errorf("runtime event requires an RFC3339 timestamp")
	}
	severity := model.SeverityMedium
	action := string(hit.Action)
	if action == `"KPROBE_ACTION_SIGKILL"` || action == `"KPROBE_ACTION_SIGNAL"` || action == `"KPROBE_ACTION_OVERRIDE"` || action == "3" || action == "5" || action == "10" {
		severity = model.SeverityHigh
	}
	f := incident(o.Scope, subject, pod.Namespace, pod.UID, hit.PolicyName, at.UTC().Format(time.RFC3339Nano), severity)
	// Display metadata is optional and never participates in UID-based identity.
	// Omit malformed names without rejecting an otherwise valid policy event.
	if pod.Name != "" && identityPart(pod.Name, 253) {
		f.Evidence["runtime_pod_name"] = pod.Name
	}
	count := int64(1)
	if e.Aggregation != nil {
		count, err = aggregateCount(e.Aggregation.Count)
		if err != nil {
			return observation{}, err
		}
	}
	return observation{finding: f, at: at, count: count, id: eventID(subject, e.Node, at.UTC().Format(time.RFC3339Nano), hit.PolicyName, hit.Process.ExecID, kind, hit.FunctionName, hit.Subsys, hit.Event, hit.Symbol)}, nil
}

type envelope struct {
	Node        string                           `json:"node_name"`
	Time        string                           `json:"time"`
	Aggregation *struct{ Count json.RawMessage } `json:"aggregation_info"`
}

type policyHit struct {
	PolicyName            string `json:"policy_name"`
	Action                json.RawMessage
	FunctionName          string `json:"function_name"`
	Subsys, Event, Symbol string
	Process               *struct {
		ExecID string `json:"exec_id"`
		Pod    struct{ Namespace, Name, UID string }
	}
}

func canonicalize(object map[string]json.RawMessage, aliases [][2]string) error {
	for _, pair := range aliases {
		if value, exists := object[pair[0]]; exists {
			if _, conflict := object[pair[1]]; conflict {
				return fmt.Errorf("runtime event has conflicting protobuf field aliases")
			}
			object[pair[1]] = value
			delete(object, pair[0])
		}
	}
	return nil
}

func aggregateCount(raw json.RawMessage) (int64, error) {
	value := string(raw)
	var text string
	if json.Unmarshal(raw, &text) == nil {
		value = text
	}
	count, err := strconv.ParseInt(value, 10, 64)
	if err != nil || count <= 0 || count > 1000000000 {
		return 0, fmt.Errorf("runtime aggregated event count is invalid or exceeds the limit")
	}
	return count, nil
}

func eventPayload(raw map[string]json.RawMessage) (string, json.RawMessage, error) {
	var kind string
	var payload json.RawMessage
	for key, value := range raw {
		switch key {
		case "process_kprobe", "process_tracepoint", "process_uprobe", "process_lsm", "process_usdt", "process_exec", "process_exit", "process_loader", "process_throttle", "rate_limit_info", "test":
			if kind != "" || len(value) == 0 || value[0] != '{' {
				return "", nil, fmt.Errorf("runtime envelope must contain exactly one event object")
			}
			kind, payload = key, value
		default:
			if strings.HasPrefix(key, "process_") {
				return "", nil, fmt.Errorf("unsupported runtime event kind")
			}
		}
	}
	if kind == "" {
		return "", nil, fmt.Errorf("runtime envelope has no recognized event")
	}
	return kind, payload, nil
}

func incident(scope, subject, namespace, uid, rule, at string, severity model.Severity) ingest.Finding {
	assetHash := sha256.Sum256([]byte(subject))
	identity, _ := json.Marshal([]string{scope, subject, rule})
	key := sha256.Sum256(identity)
	evidence := map[string]any{"runtime_namespace": namespace, "runtime_pod_uid": uid, "runtime_rule": rule,
		"runtime_first_seen": at, "runtime_last_seen": at, "runtime_batch_count": int64(1)}
	if strings.HasPrefix(scope, "k8s:uid:") && len(scope) > len("k8s:uid:") && identityPart(strings.TrimPrefix(scope, "k8s:uid:"), 128) {
		evidence["runtime_cluster_id"] = strings.TrimPrefix(scope, "k8s:")
	}
	return ingest.Normalize(ingest.Finding{Key: "runtime:" + Tool + ":" + hex.EncodeToString(key[:]),
		Asset: ingest.Asset{Kind: model.KindCloudResource, Key: "runtime:" + scope + ":" + Tool + ":" + hex.EncodeToString(assetHash[:])},
		Title: "Tetragon runtime policy: " + rule, Severity: severity,
		Description: "A named Tetragon tracing policy reported a runtime event. This event is not a complete security assessment.",
		Remediation: "Investigate the policy event in the runtime sensor. Event silence does not establish remediation.",
		Tags:        []string{Tool, "runtime"}, Evidence: evidence})
}
