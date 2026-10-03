// Package gitleaks converts a gitleaks report (gitleaks detect|git|dir
// --report-format json) into ingest findings. gitleaks matches patterns and
// does not verify them, so every finding is medium.
//
// The secret never leaves this package: Secret is only hashed
// (ingest.SecretHash), and Match, Line (both contain the secret), Author,
// Email and Message are not even decoded.
package gitleaks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Tool is the default tool name.
const Tool = "gitleaks"

// leak decodes only what a finding may carry. Do not add Match, Line,
// Author, Email or Message.
type leak struct {
	Description string   `json:"Description"`
	RuleID      string   `json:"RuleID"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Link        string   `json:"Link"`
	Entropy     float64  `json:"Entropy"`
	Date        string   `json:"Date"`
	Tags        []string `json:"Tags"`
	Fingerprint string   `json:"Fingerprint"`
	Secret      string   `json:"Secret"` // hashed, never copied
}

// Parse implements ingest.Parser.
func Parse(data []byte, o ingest.ParseOptions) ([]ingest.Finding, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		// gitleaks writes [] when it finds nothing; an empty file is a
		// failed run and must not resolve everything.
		return nil, fmt.Errorf("gitleaks report is empty (a clean scan is [])")
	}
	var leaks []leak
	if err := json.Unmarshal(data, &leaks); err != nil {
		// Never wrap the decoder error: a type error can quote input.
		return nil, fmt.Errorf("gitleaks report is not a JSON array of findings (want --report-format json)")
	}
	out := make([]ingest.Finding, 0, len(leaks))
	for _, l := range leaks {
		out = append(out, finding(l, o))
	}
	return ingest.Finalize(out), nil
}

func finding(l leak, o ingest.ParseOptions) ingest.Finding {
	hash := ingest.SecretHash(l.Secret)
	link := ingest.SafeURL(l.Link)
	asset := repoFromLink(link)
	if asset == "" {
		asset = o.Scope
	}
	rule := l.RuleID
	if strings.TrimSpace(rule) == "" {
		rule = "unknown-rule"
	}
	place := l.File
	if place == "" {
		place = "an unnamed file"
	}
	if l.StartLine > 0 {
		place += ":" + strconv.Itoa(l.StartLine)
	}
	description := fmt.Sprintf("gitleaks rule %s matched in %s", rule, place)
	if d := strings.TrimSpace(l.Description); d != "" {
		description = d + "\n\n" + description
	}
	if l.Commit != "" {
		description += " (commit " + l.Commit + ")"
	}
	if asset != "" {
		description += " of " + asset
	}
	description += ". This is an unverified pattern match. The secret value is not stored"
	if hash != "" {
		description += "; its hash prefix is " + hash
	}
	description += "."
	line := l.StartLine
	if line < 0 {
		line = 0
	}
	return ingest.Finding{
		Key:         strings.Join([]string{rule, l.File, strconv.Itoa(line), l.Commit, hash}, ":"),
		Asset:       ingest.Asset{Kind: model.KindCloudResource, Key: asset},
		Title:       fmt.Sprintf("Possible %s secret in %s", rule, place),
		Description: description,
		Severity:    model.SeverityMedium,
		Remediation: "Check whether the match is a real credential. If it is, rotate it (removing it from the history alone " +
			"does not reach existing clones), remove it from the repository and load it from a secret manager; if not, " +
			"mark this finding as a false positive or add a gitleaks allowlist entry.",
		Tags: ingest.Tags(append([]string{Tool, rule, "secret"}, l.Tags...)...),
		Evidence: map[string]any{
			"rule_id": rule, "file": l.File, "symlink_file": l.SymlinkFile, "line": line, "end_line": l.EndLine,
			"commit": l.Commit, "link": link, "entropy": l.Entropy, "date": l.Date, "fingerprint": l.Fingerprint,
			"secret_hash": hash,
		},
	}
}

// repoFromLink turns a GitHub/GitLab/Bitbucket file link into the
// repository URL.
func repoFromLink(link string) string {
	for _, sep := range []string{"/-/blob/", "/blob/", "/src/", "/commit/", "/-/commit/"} {
		if i := strings.Index(link, sep); i > 0 {
			return link[:i]
		}
	}
	return ""
}
