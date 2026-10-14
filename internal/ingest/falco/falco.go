// Package falco imports runtime rule alerts with allowlisted incident evidence.
package falco

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const Tool = "falco"
const MaxInputBytes = 64 << 20

// Parse returns incidents only. Callers must always submit Complete=false:
// silence in an event stream is never a clean observation.
func Parse(data []byte, o ingest.ParseOptions) ([]ingest.Finding, error) {
	return parseBatch(data, o, parseEvent)
}

func parseEvent(data []byte, o ingest.ParseOptions) (observation, error) {
	var e event
	if json.Unmarshal(data, &e) != nil {
		return observation{}, fmt.Errorf("falco event is not valid JSON")
	}
	if e.Source == "internal" {
		return observation{}, fmt.Errorf("runtime sensor reports an internal health or event loss signal")
	}
	if e.Rule == "" || ingest.Line(e.Rule, 256) != e.Rule || e.Priority == "" || ingest.Line(e.Priority, 32) != e.Priority {
		return observation{}, fmt.Errorf("runtime rule and priority must be bounded nonempty strings")
	}
	for _, name := range []string{"k8s.ns.name", "k8s.pod.uid", "k8s.pod.name", "container.id"} {
		if value, exists := e.Fields[name]; exists && string(value) != "null" {
			var text string
			if json.Unmarshal(value, &text) != nil {
				return observation{}, fmt.Errorf("runtime identity fields must be strings")
			}
		}
	}
	namespace, uid := field(e.Fields, "k8s.ns.name"), field(e.Fields, "k8s.pod.uid")
	if !identityPart(namespace, 253) || !identityPart(uid, 128) {
		return observation{}, fmt.Errorf("runtime workload identity is invalid")
	}
	subject := eventID(namespace, field(e.Fields, "k8s.pod.name"), field(e.Fields, "container.id"), e.Hostname)
	if uid != "" {
		subject = "pod:" + namespace + "/" + uid
	}
	at, err := time.Parse(time.RFC3339Nano, e.Time)
	if err != nil || at.IsZero() {
		return observation{}, fmt.Errorf("runtime event requires an RFC3339 timestamp")
	}
	f := incident(o.Scope, subject, namespace, uid, e.Rule, at.UTC().Format(time.RFC3339Nano), priority(e.Priority))
	return observation{finding: f, at: at, count: 1, id: eventID(subject, e.Hostname, at.UTC().Format(time.RFC3339Nano), e.Rule, string(e.Fields["evt.num"]), string(e.Fields["proc.pid"]))}, nil
}

type event struct {
	Time, Rule, Priority, Hostname, Source string
	Fields                                 map[string]json.RawMessage `json:"output_fields"`
}

func priority(value string) model.Severity {
	switch strings.ToLower(value) {
	case "emergency", "alert", "critical":
		return model.SeverityCritical
	case "notice":
		return model.SeverityLow
	case "debug":
		return model.SeverityInfo
	default:
		return ingest.Severity(value)
	}
}

func field(fields map[string]json.RawMessage, name string) string {
	var value string
	_ = json.Unmarshal(fields[name], &value)
	if value == "<NA>" || value == "<nil>" || value == "N/A" || value == "(none)" {
		return ""
	}
	return value
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
		Title: "Falco runtime rule: " + rule, Severity: severity,
		Description: "Falco reported a runtime rule alert. This event is not a complete security assessment.",
		Remediation: "Investigate the rule alert in the runtime sensor. Event silence does not establish remediation.",
		Tags:        []string{Tool, "runtime"}, Evidence: evidence})
}
