// Package s3scanner converts S3Scanner results (s3scanner --json, one JSON
// log entry per line with a "bucket" object) into ingest findings: one per
// permission a bucket grants to everyone (AllUsers) or to any authenticated
// cloud user (AuthenticatedUsers). Buckets that do not exist or grant
// nothing public are not findings.
package s3scanner

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
const Tool = "s3scanner"

// S3Scanner's tri-state values.
const (
	exists  = 1 // bucket.BucketExists
	allowed = 1 // bucket.PermissionAllowed
)

type bucket struct {
	Name              string `json:"name"`
	Region            string `json:"region"`
	Exists            uint8  `json:"exists"`
	Provider          string `json:"provider"`
	DateScanned       string `json:"date_scanned"`
	ObjectsEnumerated bool   `json:"objects_enumerated"`
	NumObjects        int64  `json:"num_objects"`
	OwnerID           string `json:"owner_id"`

	AuthRead        uint8 `json:"perm_auth_users_read"`
	AuthWrite       uint8 `json:"perm_auth_users_write"`
	AuthReadACL     uint8 `json:"perm_auth_users_read_acl"`
	AuthWriteACL    uint8 `json:"perm_auth_users_write_acl"`
	AuthFullControl uint8 `json:"perm_auth_users_full_control"`
	AllRead         uint8 `json:"perm_all_users_read"`
	AllWrite        uint8 `json:"perm_all_users_write"`
	AllReadACL      uint8 `json:"perm_all_users_read_acl"`
	AllWriteACL     uint8 `json:"perm_all_users_write_acl"`
	AllFullControl  uint8 `json:"perm_all_users_full_control"`
}

type entry struct {
	Bucket *bucket `json:"bucket"`
	Level  string  `json:"level"`
}

// grant is one public permission and what it means.
type grant struct {
	id       string // rule id, used in keys and tags
	grantee  string
	perm     string
	severity model.Severity
	means    string
	set      func(b bucket) uint8
}

var grants = []grant{
	{"all-users-full-control", "everyone", "FULL_CONTROL", model.SeverityCritical, "anyone on the internet can read, write and change the permissions of", func(b bucket) uint8 { return b.AllFullControl }},
	{"all-users-write", "everyone", "WRITE", model.SeverityCritical, "anyone on the internet can write objects to", func(b bucket) uint8 { return b.AllWrite }},
	{"all-users-write-acl", "everyone", "WRITE_ACP", model.SeverityCritical, "anyone on the internet can change the permissions of", func(b bucket) uint8 { return b.AllWriteACL }},
	{"all-users-read", "everyone", "READ", model.SeverityHigh, "anyone on the internet can list the objects of", func(b bucket) uint8 { return b.AllRead }},
	{"all-users-read-acl", "everyone", "READ_ACP", model.SeverityMedium, "anyone on the internet can read the permissions of", func(b bucket) uint8 { return b.AllReadACL }},
	{"auth-users-full-control", "any authenticated user", "FULL_CONTROL", model.SeverityHigh, "any authenticated cloud account can read, write and change the permissions of", func(b bucket) uint8 { return b.AuthFullControl }},
	{"auth-users-write", "any authenticated user", "WRITE", model.SeverityHigh, "any authenticated cloud account can write objects to", func(b bucket) uint8 { return b.AuthWrite }},
	{"auth-users-write-acl", "any authenticated user", "WRITE_ACP", model.SeverityHigh, "any authenticated cloud account can change the permissions of", func(b bucket) uint8 { return b.AuthWriteACL }},
	{"auth-users-read", "any authenticated user", "READ", model.SeverityMedium, "any authenticated cloud account can list the objects of", func(b bucket) uint8 { return b.AuthRead }},
	{"auth-users-read-acl", "any authenticated user", "READ_ACP", model.SeverityLow, "any authenticated cloud account can read the permissions of", func(b bucket) uint8 { return b.AuthReadACL }},
}

// Parse implements ingest.Parser. No output is a valid empty run (nothing
// was scanned); an error or fatal log entry fails the parse so a broken run
// never resolves findings.
func Parse(data []byte, _ ingest.ParseOptions) ([]ingest.Finding, error) {
	var out []ingest.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), ingest.MaxBodyBytes)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("s3scanner output line %d is not a JSON entry (want s3scanner --json)", n)
		}
		switch strings.ToLower(e.Level) {
		case "error", "fatal", "panic":
			return nil, fmt.Errorf("s3scanner output line %d is an %s log entry: the scan did not complete", n, strings.ToLower(e.Level))
		}
		if e.Bucket == nil || strings.TrimSpace(e.Bucket.Name) == "" || e.Bucket.Exists != exists {
			continue // a log line, or a bucket that does not exist
		}
		out = append(out, findings(*e.Bucket)...)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("s3scanner output: %w", err)
	}
	return ingest.Finalize(out), nil
}

func findings(b bucket) []ingest.Finding {
	provider := strings.ToLower(strings.TrimSpace(b.Provider))
	if provider == "" {
		provider = "aws"
	}
	asset := provider + "://" + b.Name
	remediation := "Remove the public grant from the bucket ACL (and any bucket policy that grants the same), then confirm with s3scanner."
	if provider == "aws" {
		asset = "arn:aws:s3:::" + b.Name
		remediation = "Remove the AllUsers/AuthenticatedUsers grant from the bucket ACL, enable S3 Block Public Access on the bucket " +
			"and the account, and set Object Ownership to BucketOwnerEnforced so ACLs no longer apply."
	}
	var out []ingest.Finding
	for _, g := range grants {
		if g.set(b) != allowed {
			continue
		}
		out = append(out, ingest.Finding{
			Key:   strings.Join([]string{provider, b.Name, g.id}, ":"),
			Asset: ingest.Asset{Kind: model.KindCloudResource, Key: asset},
			Title: fmt.Sprintf("Bucket %s grants %s to %s", b.Name, g.perm, g.grantee),
			Description: fmt.Sprintf("s3scanner found that %s the %s bucket %s (region %s): its ACL grants %s to %s.",
				g.means, provider, b.Name, orUnknown(b.Region), g.perm, g.grantee),
			Severity:    g.severity,
			Remediation: remediation,
			Tags:        ingest.Tags(Tool, g.id, provider),
			Evidence: map[string]any{
				"bucket": b.Name, "provider": provider, "region": b.Region, "permission": g.perm, "grantee": g.grantee,
				"objects_enumerated": b.ObjectsEnumerated, "num_objects": b.NumObjects, "date_scanned": b.DateScanned,
			},
		})
	}
	return out
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}
