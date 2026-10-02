// Package nuclei wraps the nuclei binary as deckard checks. nuclei opens its own
// network connections, so it bypasses the scope-guarded Dialer: this package
// therefore re-verifies every target through an injected ScopeVerifier and
// never builds a command line from unvalidated input.
package nuclei

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
)

const (
	maxLine         = 1 << 20
	maxExtracted    = 10
	maxExtractedLen = 64
	maxMatchedAt    = 20
)

// flexList decodes either a JSON string (comma separated) or a list of strings.
type flexList []string

func (f *flexList) UnmarshalJSON(b []byte) error {
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		*f = list
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return nil // tolerate odd shapes: treat as empty
	}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*f = append(*f, p)
		}
	}
	return nil
}

// flexStr decodes a JSON string or number into a string (nuclei prints ports
// as strings today; be lenient).
type flexStr string

func (f *flexStr) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexStr(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err == nil {
		*f = flexStr(n.String())
	}
	return nil
}

type nucleiEvent struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Severity       string   `json:"severity"`
		Remediation    string   `json:"remediation"`
		Tags           flexList `json:"tags"`
		Reference      flexList `json:"reference"`
		Classification struct {
			CVE flexList `json:"cve-id"`
			CWE flexList `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	Port             flexStr  `json:"port"`
	Scheme           string   `json:"scheme"`
	URL              string   `json:"url"`
	MatchedAt        string   `json:"matched-at"`
	MatcherName      string   `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
}

// ParseJSONL converts nuclei -jsonl output into findings. Blank lines and
// garbage (log noise, truncated JSON, events without a template-id) are
// skipped. Multiple matches of one template (and matcher) are merged into one
// finding; the check name is left empty for the caller to set.
func ParseJSONL(r io.Reader) ([]model.FindingInput, error) {
	var out []model.FindingInput
	index := map[string]int{}
	err := eachEvent(r, func(m Match) {
		f := m.FindingInput
		if i, dup := index[f.Key]; dup {
			mergeMatch(&out[i], f)
		} else {
			index[f.Key] = len(out)
			out = append(out, f)
		}
	})
	return out, err
}

// Match is one nuclei result event: the finding plus where it was seen, so a
// multi-target run can be attributed back to the target that matched.
type Match struct {
	model.FindingInput
	Host   string // hostname or IP, no port
	Port   string
	Scheme string // http/https for web matches, empty otherwise
	URL    string // the target origin nuclei reports, e.g. http://127.0.0.1:8080
}

// Origin is the normalised "scheme://host:port" of the matched target (default
// ports filled in, host lowercased, IPv6 bracketed); without a scheme it is
// "host" or "host:port". Targets are keyed the same way (see OriginOfURL), so
// a Match is attributed by comparing origins.
func (m Match) Origin() string {
	if m.URL != "" {
		if o := OriginOfURL(m.URL); o != "" {
			return o
		}
	}
	host := strings.ToLower(m.Host)
	if m.Scheme != "" && host != "" {
		return m.Scheme + "://" + net.JoinHostPort(host, portOrDefault(m.Port, m.Scheme))
	}
	if host != "" && m.Port != "" {
		return net.JoinHostPort(host, m.Port)
	}
	return host
}

// OriginOfURL normalises an http(s) URL to "scheme://host:port"; "" when raw
// is not an absolute http(s) URL.
func OriginOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return ""
	}
	return u.Scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), portOrDefault(u.Port(), u.Scheme))
}

func portOrDefault(port, scheme string) string {
	if port != "" {
		return port
	}
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// ParseMatches converts nuclei -jsonl output into one Match per event, without
// merging events of different targets. Blank lines and garbage are skipped.
func ParseMatches(r io.Reader) ([]Match, error) {
	var out []Match
	err := eachEvent(r, func(m Match) { out = append(out, m) })
	return out, err
}

func eachEvent(r io.Reader, fn func(Match)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br)
		if len(line) > 0 {
			if m, ok := parseLine(line); ok {
				fn(m)
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("nuclei: reading output: %w", err)
		}
	}
}

// readLine returns the next line, discarding the excess of overlong lines.
func readLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		if len(line) < maxLine {
			line = append(line, chunk...)
		}
		if err != nil || !isPrefix {
			return line, err
		}
	}
}

func parseLine(line []byte) (Match, bool) {
	line = []byte(strings.TrimSpace(string(line)))
	if len(line) == 0 || line[0] != '{' {
		return Match{}, false
	}
	var ev nucleiEvent
	if err := json.Unmarshal(line, &ev); err != nil || ev.TemplateID == "" {
		return Match{}, false
	}
	key := ev.TemplateID
	if ev.MatcherName != "" {
		key += ":" + ev.MatcherName
	}
	title := ev.Info.Name
	if title == "" {
		title = ev.TemplateID
	}
	desc := ev.Info.Description
	if desc == "" {
		desc = "nuclei template " + ev.TemplateID + " matched " + ev.MatchedAt + "."
	}
	fix := ev.Info.Remediation
	if fix == "" {
		fix = "Review the template references and apply the vendor fix or mitigation."
	}
	ev2 := map[string]any{
		"template_id": ev.TemplateID, "matched_at": ev.MatchedAt, "host": ev.Host, "type": ev.Type,
		"matched_at_all": []string{ev.MatchedAt},
	}
	if ev.MatcherName != "" {
		ev2["matcher"] = ev.MatcherName
	}
	if len(ev.Info.Reference) > 0 {
		ev2["references"] = []string(ev.Info.Reference)
	}
	if ex := truncateAll(ev.ExtractedResults); len(ex) > 0 {
		ev2["extracted_results"] = ex
	}
	return Match{
		FindingInput: model.FindingInput{
			Key: key, Severity: toSeverity(ev.Info.Severity), Title: title, Description: desc,
			Evidence: ev2, Remediation: fix, Tags: buildTags(ev),
		},
		Host: ev.Host, Port: string(ev.Port), Scheme: ev.Scheme, URL: ev.URL,
	}, true
}

func toSeverity(s string) model.Severity {
	if sev := model.Severity(strings.ToLower(strings.TrimSpace(s))); sev.Valid() {
		return sev
	}
	return model.SeverityInfo
}

func truncateAll(in []string) []string {
	var out []string
	for _, s := range in {
		if len(out) == maxExtracted {
			break
		}
		if len(s) > maxExtractedLen {
			s = s[:maxExtractedLen] + "..."
		}
		out = append(out, s)
	}
	return out
}

func buildTags(ev nucleiEvent) []string {
	seen := map[string]bool{}
	var tags []string
	add := func(t string) {
		if t = strings.TrimSpace(t); t != "" && !seen[strings.ToLower(t)] {
			seen[strings.ToLower(t)] = true
			tags = append(tags, t)
		}
	}
	add("nuclei")
	for _, t := range ev.Info.Tags {
		add(strings.ToLower(t))
	}
	for _, c := range ev.Info.Classification.CVE {
		add(strings.ToUpper(c))
	}
	for _, c := range ev.Info.Classification.CWE {
		add(strings.ToUpper(c))
	}
	return tags
}

func mergeMatch(dst *model.FindingInput, src model.FindingInput) {
	all, _ := dst.Evidence["matched_at_all"].([]string)
	at, _ := src.Evidence["matched_at"].(string)
	if len(all) >= maxMatchedAt || at == "" {
		return
	}
	for _, a := range all {
		if a == at {
			return
		}
	}
	dst.Evidence["matched_at_all"] = append(all, at)
}
