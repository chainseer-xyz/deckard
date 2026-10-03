// Package kubescape converts Kubescape results (kubescape scan --format json)
// into ingest findings: one per failed control per resource. Passed, skipped
// and excluded controls are not findings.
package kubescape

import (
	"encoding/json"
	"fmt"
	"sort"
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
			Kind     string `json:"kind"`
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
	type obj struct{ kind, ns, name string }
	objects := map[string]obj{}
	for _, res := range r.Resources {
		objects[res.ResourceID] = obj{res.Object.Kind, res.Object.Metadata.Namespace, res.Object.Metadata.Name}
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
			for _, rule := range c.Rules {
				for _, p := range rule.Paths {
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
			out = append(out, ingest.Finding{
				Key:         c.ControlID + ":" + res.ResourceID,
				Asset:       ingest.Asset{Kind: model.KindCloudResource, Key: "k8s://" + cluster + "/" + res.ResourceID},
				Title:       fmt.Sprintf("%s: %s (%s)", label, name, c.ControlID),
				Description: description,
				Severity:    severity(sum),
				Remediation: remediation,
				Tags:        ingest.Tags(Tool, c.ControlID, sum.Category.Name),
				Evidence: map[string]any{
					"control_id": c.ControlID, "cluster": cluster, "resource_id": res.ResourceID,
					"kind": ob.kind, "namespace": ob.ns, "name": ob.name, "failed_paths": failed,
				},
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
