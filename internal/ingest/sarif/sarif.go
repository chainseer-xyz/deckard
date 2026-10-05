// Package sarif converts SARIF 2.1.0 logs into ingest findings, so almost
// any scanner (Semgrep, CodeQL, Trivy, Checkov, tfsec, KICS, ...) can feed
// deckard. Every result of kind "fail" (the default) becomes a finding,
// unless it is suppressed (accepted or unreviewed-status suppressions) or
// its baselineState is "absent".
package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Tool is the default tool name (use --tool to name the actual scanner).
const Tool = "sarif"

type log struct {
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type component struct {
	Name           string                     `json:"name"`
	Version        string                     `json:"version"`
	SemanticVer    string                     `json:"semanticVersion"`
	Rules          []rule                     `json:"rules"`
	MessageStrings map[string]json.RawMessage `json:"globalMessageStrings"`
}

type run struct {
	Tool struct {
		Driver     component   `json:"driver"`
		Extensions []component `json:"extensions"`
	} `json:"tool"`
	VersionControlProvenance []struct {
		RepositoryURI string `json:"repositoryUri"`
		RevisionID    string `json:"revisionId"`
	} `json:"versionControlProvenance"`
	Invocations []struct {
		ExecutionSuccessful *bool `json:"executionSuccessful"`
	} `json:"invocations"`
	Results []result `json:"results"`
}

type text struct {
	Text string `json:"text"`
}

type rule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     text            `json:"shortDescription"`
	FullDescription      text            `json:"fullDescription"`
	Help                 text            `json:"help"`
	HelpURI              string          `json:"helpUri"`
	MessageStrings       map[string]text `json:"messageStrings"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties props `json:"properties"`
}

type props struct {
	SecuritySeverity json.RawMessage `json:"security-severity"`
	Tags             []string        `json:"tags"`
}

type result struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Rule      struct {
		ID    string `json:"id"`
		Index *int   `json:"index"`
	} `json:"rule"`
	Kind    string `json:"kind"`
	Level   string `json:"level"`
	Message struct {
		Text      string   `json:"text"`
		ID        string   `json:"id"`
		Arguments []string `json:"arguments"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
			} `json:"region"`
		} `json:"physicalLocation"`
		LogicalLocations []struct {
			FullyQualifiedName string `json:"fullyQualifiedName"`
		} `json:"logicalLocations"`
	} `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Fingerprints        map[string]string `json:"fingerprints"`
	BaselineState       string            `json:"baselineState"`
	Suppressions        []struct {
		Status string `json:"status"`
	} `json:"suppressions"`
	Properties props `json:"properties"`
}

// Parse implements ingest.Parser.
func Parse(data []byte, o ingest.ParseOptions) ([]ingest.Finding, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("SARIF log is empty")
	}
	var l log
	if err := json.Unmarshal(data, &l); err != nil {
		// Not wrapped: decoder errors can quote input, and a SARIF log from
		// a secret scanner may carry the secret in its snippets.
		return nil, fmt.Errorf("SARIF log is not a valid SARIF 2.1.0 JSON document")
	}
	if !strings.HasPrefix(l.Version, "2.1") {
		return nil, fmt.Errorf("SARIF version %q is not 2.1.0", ingest.Line(l.Version, 32))
	}
	if l.Runs == nil {
		return nil, fmt.Errorf("SARIF log has no runs")
	}
	var out []ingest.Finding
	for i, r := range l.Runs {
		for _, invocation := range r.Invocations {
			if invocation.ExecutionSuccessful != nil && !*invocation.ExecutionSuccessful {
				return nil, fmt.Errorf("SARIF run %d did not complete successfully; no findings were ingested", i)
			}
		}
		for _, res := range r.Results {
			if f, ok := finding(r, res, o); ok {
				out = append(out, f)
			}
		}
	}
	return ingest.Finalize(out), nil
}

func finding(r run, res result, o ingest.ParseOptions) (ingest.Finding, bool) {
	if k := strings.ToLower(res.Kind); k != "" && k != "fail" {
		return ingest.Finding{}, false
	}
	if strings.EqualFold(res.BaselineState, "absent") {
		return ingest.Finding{}, false
	}
	for _, s := range res.Suppressions {
		if !strings.EqualFold(s.Status, "rejected") {
			return ingest.Finding{}, false
		}
	}
	ru := lookupRule(r, res)
	id := res.RuleID
	if id == "" {
		id = res.Rule.ID
	}
	if id == "" {
		id = ru.ID
	}
	if id == "" {
		id = "unknown-rule"
	}
	level := res.Level
	if level == "" {
		level = ru.DefaultConfiguration.Level
	}
	if level == "" {
		level = "warning" // the SARIF default
	}
	secSev, hasSecSev := securitySeverity(res.Properties.SecuritySeverity)
	if !hasSecSev {
		secSev, hasSecSev = securitySeverity(ru.Properties.SecuritySeverity)
	}
	sev := levelSeverity(level)
	if hasSecSev {
		sev = scoreSeverity(secSev)
	}

	var uri, logical string
	var line, col int
	if len(res.Locations) > 0 {
		pl := res.Locations[0].PhysicalLocation
		uri, line, col = pl.ArtifactLocation.URI, pl.Region.StartLine, pl.Region.StartColumn
		if ll := res.Locations[0].LogicalLocations; len(ll) > 0 {
			logical = ll[0].FullyQualifiedName
		}
	}
	if line < 0 {
		line = 0
	}
	if col < 0 {
		col = 0
	}
	where := uri
	if where == "" {
		where = logical
	}
	place := where
	if place != "" && line > 0 {
		place += ":" + strconv.Itoa(line)
	}
	fp := fingerprint(res)
	if fp == "" {
		fp = strconv.Itoa(line)
	}

	msg := message(r, ru, res)
	// The rule's short description names the problem (CodeQL, Trivy) unless
	// it merely repeats the rule id (Semgrep); then the message does.
	title := ru.ShortDescription.Text
	if strings.TrimSpace(title) == "" || strings.Contains(title, id) {
		title = strings.SplitN(msg, "\n", 2)[0]
	}
	if strings.TrimSpace(title) == "" {
		title = id
	}
	if place != "" {
		title += " (" + place + ")"
	}
	description := msg
	if d := ru.FullDescription.Text; d != "" && d != msg {
		description = strings.TrimSpace(d + "\n\n" + msg)
	}
	remediation := ru.Help.Text
	if ru.HelpURI != "" {
		remediation = strings.TrimSpace(remediation + "\n\nSee " + ru.HelpURI)
	}

	var repo, revision string
	if len(r.VersionControlProvenance) > 0 {
		repo = strings.TrimSuffix(ingest.SafeURL(r.VersionControlProvenance[0].RepositoryURI), ".git")
		revision = r.VersionControlProvenance[0].RevisionID
	}
	asset := repo
	if asset == "" {
		asset = o.Scope
	}
	driver := r.Tool.Driver
	version := driver.Version
	if version == "" {
		version = driver.SemanticVer
	}
	tags := append([]string{Tool, strings.ToLower(driver.Name), id}, ru.Properties.Tags...)
	ev := map[string]any{
		"tool": driver.Name, "tool_version": version, "rule_id": id, "level": level, "file": uri, "line": line,
		"column": col, "logical_location": logical, "fingerprint": fp, "repository": repo, "revision": revision,
		"help_uri": ru.HelpURI,
	}
	if hasSecSev {
		ev["security_severity"] = secSev
	}
	return ingest.Finding{
		Key:         strings.Join([]string{id, where, fp}, ":"),
		Asset:       ingest.Asset{Kind: model.KindCloudResource, Key: asset},
		Title:       title,
		Description: description,
		Severity:    sev,
		Remediation: remediation,
		Tags:        ingest.Tags(tags...),
		Evidence:    ev,
	}, true
}

// lookupRule finds the result's rule by index, else by id, in the driver
// and then the extensions.
func lookupRule(r run, res result) rule {
	idx := res.RuleIndex
	if idx == nil {
		idx = res.Rule.Index
	}
	rules := r.Tool.Driver.Rules
	if idx != nil && *idx >= 0 && *idx < len(rules) {
		return rules[*idx]
	}
	id := res.RuleID
	if id == "" {
		id = res.Rule.ID
	}
	if id == "" {
		return rule{}
	}
	for _, c := range append([]component{r.Tool.Driver}, r.Tool.Extensions...) {
		for _, ru := range c.Rules {
			if ru.ID == id {
				return ru
			}
		}
	}
	return rule{}
}

// message is the result text, or the rule's message string with
// {0}-style arguments filled in.
func message(r run, ru rule, res result) string {
	if res.Message.Text != "" {
		return res.Message.Text
	}
	tmpl := ru.MessageStrings[res.Message.ID].Text
	if tmpl == "" {
		var t text
		if raw, ok := r.Tool.Driver.MessageStrings[res.Message.ID]; ok && json.Unmarshal(raw, &t) == nil {
			tmpl = t.Text
		}
	}
	for i, a := range res.Message.Arguments {
		if i >= 20 {
			break
		}
		tmpl = strings.ReplaceAll(tmpl, "{"+strconv.Itoa(i)+"}", a)
	}
	if tmpl == "" {
		return ru.ShortDescription.Text
	}
	return tmpl
}

// fingerprint is a stable identity for the result from fingerprints or
// partialFingerprints (sorted by name), so a finding survives line shifts.
func fingerprint(res result) string {
	for _, m := range []map[string]string{res.Fingerprints, res.PartialFingerprints} {
		if len(m) == 0 {
			continue
		}
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		return names[0] + "=" + m[names[0]]
	}
	return ""
}

// securitySeverity reads the GitHub convention "security-severity" (a CVSS
// score, as a string or a number).
func securitySeverity(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		return f, f >= 0 && f <= 10
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f, err == nil && f >= 0 && f <= 10
}

func scoreSeverity(f float64) model.Severity {
	switch {
	case f >= 9:
		return model.SeverityCritical
	case f >= 7:
		return model.SeverityHigh
	case f >= 4:
		return model.SeverityMedium
	case f > 0:
		return model.SeverityLow
	}
	return model.SeverityInfo
}

func levelSeverity(level string) model.Severity {
	switch strings.ToLower(level) {
	case "error":
		return model.SeverityHigh
	case "warning":
		return model.SeverityMedium
	case "note":
		return model.SeverityLow
	case "none":
		return model.SeverityInfo
	}
	return model.SeverityMedium
}
