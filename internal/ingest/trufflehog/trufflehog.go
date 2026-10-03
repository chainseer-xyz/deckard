// Package trufflehog converts trufflehog results (trufflehog <source> --json,
// one JSON object per line) into ingest findings. Verified secrets are high,
// unverified ones medium.
//
// The secret value never leaves this package: Raw and RawV2 are only hashed
// (ingest.SecretHash), and Redacted, ExtraData and StructuredData, which can
// hold parts of the secret or account details, are not even decoded. A
// finding records the detector, where the secret is (repository, file, line,
// commit, link) and the hash prefix.
package trufflehog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Tool is the default tool name.
const Tool = "trufflehog"

// result decodes only what a finding may carry. Do not add Redacted,
// ExtraData or StructuredData.
type result struct {
	SourceMetadata struct {
		Data map[string]map[string]any `json:"Data"`
	} `json:"SourceMetadata"`
	SourceName   string `json:"SourceName"`
	DetectorName string `json:"DetectorName"`
	DecoderName  string `json:"DecoderName"`
	Verified     bool   `json:"Verified"`
	Raw          string `json:"Raw"`
	RawV2        string `json:"RawV2"`
}

// location fields read from SourceMetadata.Data.<source>; anything else
// there (email, username, visibility) is ignored.
type location struct {
	repository, file, commit, link, image, bucket string
	line                                          int
}

func locate(data map[string]map[string]any) location {
	var l location
	str := func(m map[string]any, k string) string {
		s, _ := m[k].(string)
		return s
	}
	for _, m := range data { // one entry: Git, Github, Gitlab, Filesystem, Docker, S3, ...
		l.repository = ingest.SafeURL(str(m, "repository"))
		l.file = str(m, "file")
		l.commit = str(m, "commit")
		l.link = ingest.SafeURL(str(m, "link"))
		l.image = str(m, "image")
		l.bucket = str(m, "bucket")
		if n, ok := m["line"].(float64); ok && n > 0 && n < 1e9 {
			l.line = int(n)
		}
	}
	return l
}

// Parse implements ingest.Parser.
func Parse(data []byte, o ingest.ParseOptions) ([]ingest.Finding, error) {
	var out []ingest.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), ingest.MaxBodyBytes)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r result
		if err := json.Unmarshal(line, &r); err != nil {
			// The error never quotes input, so no secret reaches a log.
			return nil, fmt.Errorf("trufflehog output line %d is not a JSON result", n)
		}
		if strings.TrimSpace(r.DetectorName) == "" {
			return nil, fmt.Errorf("trufflehog output line %d has no DetectorName (want trufflehog --json output)", n)
		}
		out = append(out, finding(r, o))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("trufflehog output: %w", err)
	}
	return ingest.Finalize(out), nil
}

func finding(r result, o ingest.ParseOptions) ingest.Finding {
	l := locate(r.SourceMetadata.Data)
	secret := r.Raw
	if secret == "" {
		secret = r.RawV2
	}
	hash := ingest.SecretHash(secret)
	where := l.file
	switch {
	case where == "" && l.image != "":
		where = l.image
	case where == "" && l.bucket != "":
		where = l.bucket
	}
	place := where
	if place != "" && l.line > 0 {
		place += ":" + strconv.Itoa(l.line)
	}
	if place == "" {
		place = r.SourceName
	}

	asset := strings.TrimSuffix(l.repository, ".git")
	if asset == "" {
		asset = repoFromLink(l.link)
	}
	if asset == "" {
		asset = o.Scope
	}

	verified, sev := "Unverified", model.SeverityMedium
	remediation := fmt.Sprintf("Check whether the value is a real %s credential. If it is, rotate it, remove it from the history "+
		"and load it from a secret manager; if not, mark this finding as a false positive.", r.DetectorName)
	if r.Verified {
		verified, sev = "Verified", model.SeverityHigh
		remediation = fmt.Sprintf("Revoke or rotate the %s credential now: trufflehog confirmed it is live. Then remove it from the "+
			"history (rotation is what makes it safe; history rewrites do not reach clones) and load it from a secret manager.", r.DetectorName)
	}
	title := fmt.Sprintf("%s %s secret in %s", verified, r.DetectorName, place)
	article := "an"
	if r.Verified {
		article = "a"
	}
	description := fmt.Sprintf("trufflehog found %s %s %s credential in %s", article, strings.ToLower(verified), r.DetectorName, place)
	if l.commit != "" {
		description += " (commit " + l.commit + ")"
	}
	if asset != "" {
		description += " of " + asset
	}
	description += ". The secret value is not stored"
	if hash != "" {
		description += "; its hash prefix is " + hash
	}
	description += "."

	return ingest.Finding{
		Key:         strings.Join([]string{r.DetectorName, where, strconv.Itoa(l.line), l.commit, hash}, ":"),
		Asset:       ingest.Asset{Kind: model.KindCloudResource, Key: asset},
		Title:       title,
		Description: description,
		Severity:    sev,
		Remediation: remediation,
		Tags:        ingest.Tags(Tool, strings.ToLower(r.DetectorName), "secret"),
		Evidence: map[string]any{
			"detector": r.DetectorName, "decoder": r.DecoderName, "verified": r.Verified, "source": r.SourceName,
			"repository": l.repository, "file": l.file, "line": l.line, "commit": l.commit, "link": l.link,
			"image": l.image, "bucket": l.bucket, "secret_hash": hash,
		},
	}
}

// repoFromLink turns a GitHub/GitLab blob link into the repository URL.
func repoFromLink(link string) string {
	for _, sep := range []string{"/blob/", "/-/blob/", "/commit/", "/-/commit/"} {
		if i := strings.Index(link, sep); i > 0 {
			return strings.TrimSuffix(link[:i], "/-")
		}
	}
	return ""
}
