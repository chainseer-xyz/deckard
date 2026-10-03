// Package prowler converts Prowler output into ingest findings. It reads the
// JSON-OCSF format (prowler --output-formats json-ocsf, v4 and later) and the
// legacy JSON format (prowler -M json, v3), as an array or as one object per
// line. Only FAIL results become findings: PASS, MANUAL and anything else is
// skipped, so a complete run with no FAIL resolves what was fixed.
package prowler

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Tool is the default tool name.
const Tool = "prowler"

type ocsf struct {
	StatusCode   string `json:"status_code"`
	StatusDetail string `json:"status_detail"`
	Message      string `json:"message"`
	Severity     string `json:"severity"`
	SeverityID   int    `json:"severity_id"`
	Metadata     struct {
		EventCode string `json:"event_code"`
	} `json:"metadata"`
	FindingInfo struct {
		UID   string `json:"uid"`
		Title string `json:"title"`
		Desc  string `json:"desc"`
	} `json:"finding_info"`
	Resources []ocsfResource `json:"resources"`
	Cloud     struct {
		Provider string `json:"provider"`
		Region   string `json:"region"`
		Account  struct {
			UID string `json:"uid"`
		} `json:"account"`
	} `json:"cloud"`
	Remediation struct {
		Desc       string   `json:"desc"`
		References []string `json:"references"`
	} `json:"remediation"`
	RiskDetails string `json:"risk_details"`
}

type ocsfResource struct {
	UID    string `json:"uid"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Region string `json:"region"`
	Group  struct {
		Name string `json:"name"`
	} `json:"group"`
}

type legacy struct {
	Status          string `json:"Status"`
	StatusExtended  string `json:"StatusExtended"`
	Severity        string `json:"Severity"`
	Provider        string `json:"Provider"`
	CheckID         string `json:"CheckID"`
	CheckTitle      string `json:"CheckTitle"`
	ServiceName     string `json:"ServiceName"`
	Description     string `json:"Description"`
	Risk            string `json:"Risk"`
	RelatedURL      string `json:"RelatedUrl"`
	AccountID       string `json:"AccountId"`
	Region          string `json:"Region"`
	ResourceID      string `json:"ResourceId"`
	ResourceArn     string `json:"ResourceArn"`
	ResourceType    string `json:"ResourceType"`
	FindingUniqueID string `json:"FindingUniqueId"`
	Remediation     struct {
		Recommendation struct {
			Text string `json:"Text"`
			URL  string `json:"Url"`
		} `json:"Recommendation"`
		Code struct {
			CLI string `json:"CLI"`
		} `json:"Code"`
	} `json:"Remediation"`
}

// Parse implements ingest.Parser.
func Parse(data []byte, _ ingest.ParseOptions) ([]ingest.Finding, error) {
	items, err := split(data)
	if err != nil {
		return nil, err
	}
	var out []ingest.Finding
	for i, raw := range items {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, fmt.Errorf("prowler result %d: %w", i, err)
		}
		_, isOCSF := probe["status_code"]
		if _, ok := probe["finding_info"]; ok {
			isOCSF = true
		}
		_, isLegacy := probe["CheckID"]
		var fs []ingest.Finding
		switch {
		case isOCSF:
			var r ocsf
			if err := json.Unmarshal(raw, &r); err != nil {
				return nil, fmt.Errorf("prowler OCSF result %d: %w", i, err)
			}
			fs = fromOCSF(r)
		case isLegacy:
			var r legacy
			if err := json.Unmarshal(raw, &r); err != nil {
				return nil, fmt.Errorf("prowler result %d: %w", i, err)
			}
			fs = fromLegacy(r)
		default:
			return nil, fmt.Errorf("prowler result %d: neither JSON-OCSF (status_code) nor legacy JSON (CheckID)", i)
		}
		out = append(out, fs...)
	}
	return ingest.Finalize(out), nil
}

// split accepts a JSON array or one JSON object per line.
func split(data []byte) ([]json.RawMessage, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}
	if data[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, fmt.Errorf("prowler output: %w", err)
		}
		return items, nil
	}
	var items []json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), ingest.MaxBodyBytes)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return nil, fmt.Errorf("prowler output line %d is not JSON", n)
		}
		items = append(items, append(json.RawMessage(nil), line...))
	}
	return items, sc.Err()
}

func fromOCSF(r ocsf) []ingest.Finding {
	if !strings.EqualFold(strings.TrimSpace(r.StatusCode), "FAIL") {
		return nil
	}
	check := r.Metadata.EventCode
	sev := ingest.Severity(r.Severity)
	if strings.TrimSpace(r.Severity) == "" {
		sev = bySeverityID(r.SeverityID)
	}
	remediation := r.Remediation.Desc
	if len(r.Remediation.References) > 0 {
		remediation += "\n\nReferences: " + strings.Join(r.Remediation.References, " ")
	}
	description := r.FindingInfo.Desc
	if r.RiskDetails != "" {
		description += "\n\nRisk: " + r.RiskDetails
	}
	title := r.StatusDetail
	if strings.TrimSpace(title) == "" {
		title = r.Message
	}
	if strings.TrimSpace(title) == "" {
		title = r.FindingInfo.Title
	}
	resources := r.Resources
	if len(resources) == 0 {
		resources = []ocsfResource{{}} // an account-level result
	}
	var out []ingest.Finding
	for _, res := range resources {
		region := res.Region
		if region == "" {
			region = r.Cloud.Region
		}
		uid := resourceKey(res.UID, res.Name, r.Cloud.Provider, r.Cloud.Account.UID, region, check)
		out = append(out, ingest.Finding{
			Key:         check + ":" + uid,
			Asset:       ingest.Asset{Kind: model.KindCloudResource, Key: uid},
			Title:       title,
			Description: description,
			Severity:    sev,
			Remediation: remediation,
			Tags:        ingest.Tags(Tool, check, res.Group.Name, r.Cloud.Provider),
			Evidence: map[string]any{
				"check_id": check, "provider": r.Cloud.Provider, "account": r.Cloud.Account.UID, "region": region,
				"service": res.Group.Name, "resource_type": res.Type, "resource_name": res.Name, "finding_uid": r.FindingInfo.UID,
			},
		})
	}
	return out
}

func fromLegacy(r legacy) []ingest.Finding {
	if !strings.EqualFold(strings.TrimSpace(r.Status), "FAIL") {
		return nil
	}
	uid := resourceKey(r.ResourceArn, r.ResourceID, r.Provider, r.AccountID, r.Region, r.CheckID)
	description := r.Description
	if description == "" {
		description = r.CheckTitle
	}
	if r.Risk != "" {
		description += "\n\nRisk: " + r.Risk
	}
	remediation := r.Remediation.Recommendation.Text
	if u := r.Remediation.Recommendation.URL; u != "" {
		remediation += "\n\nReference: " + u
	}
	if c := r.Remediation.Code.CLI; c != "" {
		remediation += "\n\nCLI: " + c
	}
	title := r.StatusExtended
	if strings.TrimSpace(title) == "" {
		title = r.CheckTitle
	}
	return []ingest.Finding{{
		Key:         r.CheckID + ":" + uid,
		Asset:       ingest.Asset{Kind: model.KindCloudResource, Key: uid},
		Title:       title,
		Description: description,
		Severity:    ingest.Severity(r.Severity),
		Remediation: remediation,
		Tags:        ingest.Tags(Tool, r.CheckID, r.ServiceName, r.Provider),
		Evidence: map[string]any{
			"check_id": r.CheckID, "provider": r.Provider, "account": r.AccountID, "region": r.Region,
			"service": r.ServiceName, "resource_type": r.ResourceType, "resource_name": r.ResourceID, "finding_uid": r.FindingUniqueID,
		},
	}}
}

// resourceKey is the resource's unique id (an ARN for AWS), else its name,
// else an account-level key for checks that name no resource.
func resourceKey(uid, name, provider, account, region, check string) string {
	switch {
	case strings.TrimSpace(uid) != "":
		return uid
	case strings.TrimSpace(name) != "":
		return name
	}
	return strings.Join([]string{"prowler", provider, account, region, check}, ":")
}

func bySeverityID(id int) model.Severity {
	switch id {
	case 1:
		return model.SeverityInfo
	case 2:
		return model.SeverityLow
	case 3:
		return model.SeverityMedium
	case 4:
		return model.SeverityHigh
	case 5, 6:
		return model.SeverityCritical
	}
	return model.SeverityMedium
}
