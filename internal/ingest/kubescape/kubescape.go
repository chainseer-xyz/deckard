// Package kubescape converts Kubescape results (kubescape scan --format json)
// into ingest findings: one per failed control per resource. Passed, skipped
// and excluded controls are not findings.
package kubescape

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Tool is the default tool name.
const Tool = "kubescape"

type report struct {
	ClusterName    string `json:"clusterName"`
	SummaryDetails struct {
		Controls map[string]summaryControl `json:"controls"`
	} `json:"summaryDetails"`
	Resources []struct {
		ResourceID string `json:"resourceID"`
		Object     struct {
			Spec     map[string]any `json:"spec"`
			Kind     string         `json:"kind"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		} `json:"object"`
	} `json:"resources"`
	Results []struct {
		ResourceID string    `json:"resourceID"`
		Controls   []control `json:"controls"`
	} `json:"results"`
}

type summaryControl struct {
	Name        string  `json:"name"`
	ScoreFactor float64 `json:"scoreFactor"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Remediation string  `json:"remediation"`
	Category    struct {
		Name string `json:"name"`
	} `json:"category"`
}

type control struct {
	ControlID string          `json:"controlID"`
	Name      string          `json:"name"`
	Status    json.RawMessage `json:"status"`
	Rules     []struct {
		Name  string `json:"name"`
		Paths []struct {
			FailedPath string `json:"failedPath"`
			FixPath    struct {
				Path  string `json:"path"`
				Value string `json:"value"`
			} `json:"fixPath"`
			ReviewPath string `json:"reviewPath"`
			DeletePath string `json:"deletePath"`
		} `json:"paths"`
	} `json:"rules"`
}

// status reads {"status":"failed"} (v2, v3) or a bare "failed".
func (c control) status() string {
	var s string
	if json.Unmarshal(c.Status, &s) == nil {
		return s
	}
	var o struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(c.Status, &o)
	return o.Status
}

// Parse implements ingest.Parser.
func Parse(data []byte, o ingest.ParseOptions) ([]ingest.Finding, error) {
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("kubescape output: %w", err)
	}
	if r.Results == nil && r.SummaryDetails.Controls == nil {
		return nil, fmt.Errorf("kubescape output has neither results nor summaryDetails (want --format json)")
	}
	cluster := r.ClusterName
	if strings.TrimSpace(cluster) == "" {
		cluster = o.Scope
	}
	type obj struct {
		kind, ns, name string
		spec           map[string]any
	}
	objects := map[string]obj{}
	for _, res := range r.Resources {
		objects[res.ResourceID] = obj{res.Object.Kind, res.Object.Metadata.Namespace, res.Object.Metadata.Name, res.Object.Spec}
	}

	var out []ingest.Finding
	for _, res := range r.Results {
		ob := objects[res.ResourceID]
		label := res.ResourceID
		if ob.name != "" {
			label = strings.TrimPrefix(ob.kind+" "+strings.Trim(ob.ns+"/"+ob.name, "/"), " ")
		}
		for _, c := range res.Controls {
			if !strings.EqualFold(c.status(), "failed") {
				continue
			}
			sum := r.SummaryDetails.Controls[c.ControlID]
			name := c.Name
			if name == "" {
				name = sum.Name
			}
			var failed, fixes []string
			completePaths := len(c.Rules) > 0
			for _, rule := range c.Rules {
				if len(rule.Paths) == 0 {
					completePaths = false
				}
				for _, p := range rule.Paths {
					if p.FailedPath == "" && p.ReviewPath == "" && p.DeletePath == "" {
						completePaths = false
					}
					for _, fp := range []string{p.FailedPath, p.ReviewPath, p.DeletePath} {
						if fp != "" {
							failed = append(failed, fp)
						}
					}
					if p.FixPath.Path != "" {
						fixes = append(fixes, fmt.Sprintf("set %s to %s", p.FixPath.Path, p.FixPath.Value))
					}
				}
			}
			failed, fixes = uniq(failed), uniq(fixes)
			description := sum.Description
			if description == "" {
				description = fmt.Sprintf("Kubescape control %s (%s) failed for %s in cluster %s.", c.ControlID, name, label, cluster)
			}
			if len(failed) > 0 {
				description += "\n\nFailed paths: " + strings.Join(failed, ", ")
			}
			remediation := sum.Remediation
			if len(fixes) > 0 {
				remediation = strings.TrimSpace(remediation + "\n\nFix: " + strings.Join(fixes, "; "))
			}
			remediation = strings.TrimSpace(remediation + "\n\nSee https://hub.armosec.io/docs/" + strings.ToLower(c.ControlID))
			evidence := map[string]any{
				"control_id": c.ControlID, "cluster": cluster, "resource_id": res.ResourceID,
				"kind": ob.kind, "namespace": ob.ns, "name": ob.name, "failed_paths": failed,
			}
			if strings.EqualFold(c.ControlID, "C-0012") && completePaths && secretRefsOnly(ob.spec, failed) {
				evidence["credential_source"] = "secretKeyRef"
			}
			out = append(out, ingest.Finding{
				Key:         c.ControlID + ":" + res.ResourceID,
				Asset:       ingest.Asset{Kind: model.KindCloudResource, Key: "k8s://" + cluster + "/" + res.ResourceID},
				Title:       fmt.Sprintf("%s: %s (%s)", label, name, c.ControlID),
				Description: description,
				Severity:    severity(sum),
				Remediation: remediation,
				Tags:        ingest.Tags(Tool, c.ControlID, sum.Category.Name),
				Evidence:    evidence,
			})
		}
	}
	return ingest.Finalize(out), nil
}

// severity uses the control's severity word when present, else Kubescape's
// scoreFactor scale (9+ critical, 7+ high, 4+ medium, 1+ low).
func severity(c summaryControl) model.Severity {
	if strings.TrimSpace(c.Severity) != "" {
		return ingest.Severity(c.Severity)
	}
	switch f := c.ScoreFactor; {
	case f >= 9:
		return model.SeverityCritical
	case f >= 7:
		return model.SeverityHigh
	case f >= 4:
		return model.SeverityMedium
	case f >= 1:
		return model.SeverityLow
	}
	return model.SeverityMedium
}

func uniq(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// A source classification is proof from the same report, never from a name or
// historical path alone. Refuse unknown paths and mixed inline/reference data.
var envPath = regexp.MustCompile(`^spec\.(?:(?:template\.spec\.)|(?:jobTemplate\.spec\.template\.spec\.))?(?:initContainers|containers|ephemeralContainers)\[[0-9]+\]\.env\[[0-9]+\]\.(?:name|value|valueFrom\.secretKeyRef\.(?:name|key))$`)
var pathPart = regexp.MustCompile(`^([A-Za-z]+)(?:\[([0-9]+)\])?$`)

func secretRefsOnly(spec map[string]any, paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	for _, path := range paths {
		if !envPath.MatchString(path) {
			return false
		}
		end := strings.Index(path, "].env[")
		if end < 0 {
			return false
		}
		envEnd := strings.Index(path[end+6:], "]") + end + 6
		var node any = map[string]any{"spec": spec}
		for _, part := range strings.Split(path[:envEnd+1], ".") {
			match := pathPart.FindStringSubmatch(part)
			object, ok := node.(map[string]any)
			if !ok || match == nil {
				return false
			}
			node = object[match[1]]
			if match[2] != "" {
				index, err := strconv.Atoi(match[2])
				list, ok := node.([]any)
				if err != nil || !ok || index >= len(list) {
					return false
				}
				node = list[index]
			}
		}
		env, ok := node.(map[string]any)
		if !ok {
			return false
		}
		if _, inline := env["value"]; inline {
			return false
		}
		from, ok := env["valueFrom"].(map[string]any)
		if !ok || len(from) != 1 {
			return false
		}
		ref, ok := from["secretKeyRef"].(map[string]any)
		if !ok {
			return false
		}
		for _, key := range []string{"name", "key"} {
			value, ok := ref[key].(string)
			if !ok || strings.TrimSpace(value) == "" {
				return false
			}
		}
	}
	return true
}
