// Package ingest is the wire contract of POST /api/v1/ingest, through which
// external scanners (Prowler, Kubescape, trufflehog, gitleaks, s3scanner, any
// SARIF producer) feed findings into deckard's lifecycle. It is pure: the API
// validates requests with it and the `deckard ingest` CLI builds and checks
// them locally with the same code. The per-tool parsers live in
// subpackages and produce a Request.
//
// The reconciliation semantics (what resolves, when) are store.IngestInput's;
// docs/ingest.md explains them for producers.
package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// Limits of one request. The API enforces them; parsers stay within them.
const (
	MaxBodyBytes      = 10 << 20
	MaxFindings       = 5000
	MaxScopeLen       = 200
	MaxKeyLen         = 512
	MaxAssetKeyLen    = 512
	MaxTitleLen       = 300
	MaxDescriptionLen = 8000
	MaxRemediationLen = 4000
	MaxTags           = 20
	MaxTagLen         = 64
	MaxEvidenceBytes  = 16 << 10
	MaxEvidenceDepth  = 8
	// MaxFutureSkew is how far observed_at may be ahead of the server clock.
	MaxFutureSkew = 5 * time.Minute
	// MaxProblems caps how many problems one validation reports.
	MaxProblems = 100
)

// Request is the body of POST /api/v1/ingest: one run of one tool over one
// scope.
type Request struct {
	// Tool names the producer, ^[a-z0-9][a-z0-9-]{1,31}$. Findings are stored
	// under check ext.<tool>.
	Tool string `json:"tool"`
	// Scope identifies what was scanned (aws:<account>:<region>, a cluster, a
	// GitHub org). Findings reconcile per (tool, scope).
	Scope string `json:"scope"`
	// Complete asserts that Findings is everything the tool found in Scope,
	// so previously reported findings that are absent may resolve. Omitted
	// means false: absence proves nothing unless the producer says so.
	Complete bool `json:"complete"`
	// ObservedAt is when the run happened. It identifies the run: a request
	// equal to the last accepted one is a no-op retry, and a run not newer
	// than the newest accepted one never resolves anything.
	ObservedAt *time.Time `json:"observed_at"`
	// Findings must be present; [] is a valid (empty) run.
	Findings []Finding `json:"findings"`
}

// Finding is one item of a Request.
type Finding struct {
	// Key is the producer's stable id for the item, unique within the
	// request. The finding's fingerprint is derived from (tool, scope, key).
	Key         string         `json:"key"`
	Asset       Asset          `json:"asset"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    model.Severity `json:"severity"`
	Remediation string         `json:"remediation,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
}

// Asset is what a finding attaches to: either a non-probable asset by
// (Kind, Key), created when missing, or Ref, an existing owned asset.
type Asset struct {
	Kind model.AssetKind `json:"kind,omitempty"`
	Key  string          `json:"key,omitempty"`
	Ref  *AssetRef       `json:"ref,omitempty"`
}

// AssetRef names an existing asset of any kind by (Kind, Key).
type AssetRef struct {
	Kind model.AssetKind `json:"kind"`
	Key  string          `json:"key"`
}

// CreatableKinds are the asset kinds an ingest may create: kinds no check is
// ever allowed to probe.
var CreatableKinds = map[model.AssetKind]bool{model.KindCloudResource: true}

var refKinds = map[model.AssetKind]bool{
	model.KindZone: true, model.KindHostname: true, model.KindIP: true, model.KindService: true,
	model.KindURL: true, model.KindCertificate: true, model.KindCloudResource: true,
}

// Rejection is one problem with a request; Index is the finding's position,
// or -1 for the request itself.
type Rejection struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

func (r Rejection) String() string {
	if r.Index < 0 {
		return r.Reason
	}
	return fmt.Sprintf("findings[%d]: %s", r.Index, r.Reason)
}

// Response is the 200 body.
type Response struct {
	// Accepted counts findings applied (not rejected); 0 for a replay.
	Accepted int `json:"accepted"`
	// Opened, Reopened and Refreshed count findings newly opened, reopened
	// after resolution, and already known and seen again.
	Opened    int `json:"opened"`
	Reopened  int `json:"reopened"`
	Refreshed int `json:"refreshed"`
	// ResolvedPending counts absent findings that accrued a miss and will
	// resolve after findings.resolve_after consecutive complete misses;
	// Resolved counts findings this request resolved.
	ResolvedPending int `json:"resolved_pending"`
	Resolved        int `json:"resolved"`
	// Complete reports whether absence was applied. A request with
	// complete: true is downgraded (and says why in Note) when an item was
	// rejected or the run is not newer than the newest accepted one.
	Complete bool   `json:"complete"`
	Note     string `json:"note,omitempty"`
	// Replay is set when the request repeated the last accepted one for its
	// (tool, scope); nothing changed.
	Replay   bool        `json:"replay"`
	Rejected []Rejection `json:"rejected"`
}

// ErrorResponse is the 422 body: the usual error envelope plus every problem
// found (up to MaxProblems).
type ErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Rejected []Rejection `json:"rejected,omitempty"`
}

// Options tune Validate.
type Options struct {
	// MaxFindings caps len(Findings); 0 or more than MaxFindings means
	// MaxFindings.
	MaxFindings int
	// Now is the server clock (observed_at may not be beyond Now +
	// MaxFutureSkew); zero skips that check (local validation).
	Now time.Time
}

// Validate checks r against the contract and returns every problem found (up
// to MaxProblems). A request with any problem must be rejected whole.
func Validate(r *Request, o Options) []Rejection {
	v := &validator{}
	if !model.ValidIngestTool(r.Tool) {
		v.req("tool must match ^[a-z0-9][a-z0-9-]{1,31}$")
	}
	switch {
	case r.Scope == "":
		v.req("scope is required")
	case len(r.Scope) > MaxScopeLen:
		v.req(fmt.Sprintf("scope longer than %d bytes", MaxScopeLen))
	case strings.TrimSpace(r.Scope) != r.Scope:
		v.req("scope has leading or trailing whitespace")
	case !cleanLine(r.Scope):
		v.req("scope must be valid UTF-8 without control characters")
	}
	switch {
	case r.ObservedAt == nil || r.ObservedAt.IsZero():
		v.req("observed_at is required (RFC 3339): it identifies the run")
	case !o.Now.IsZero() && r.ObservedAt.After(o.Now.Add(MaxFutureSkew)):
		v.req(fmt.Sprintf("observed_at is more than %s in the future", MaxFutureSkew))
	}
	limit := o.MaxFindings
	if limit <= 0 || limit > MaxFindings {
		limit = MaxFindings
	}
	switch {
	case r.Findings == nil:
		v.req("findings is required (use [] for a run that found nothing)")
	case len(r.Findings) > limit:
		v.req(fmt.Sprintf("%d findings exceed the limit of %d per request", len(r.Findings), limit))
		return v.out // do not walk an oversized list
	}
	keys := make(map[string]int, len(r.Findings))
	for i := range r.Findings {
		f := &r.Findings[i]
		if prev, dup := keys[f.Key]; dup && f.Key != "" {
			v.item(i, fmt.Sprintf("key duplicates findings[%d]", prev))
		} else {
			keys[f.Key] = i
		}
		validateFinding(v, i, f)
		if v.full() {
			break
		}
	}
	return v.out
}

func validateFinding(v *validator, i int, f *Finding) {
	switch {
	case f.Key == "":
		v.item(i, "key is required")
	case len(f.Key) > MaxKeyLen:
		v.item(i, fmt.Sprintf("key longer than %d bytes", MaxKeyLen))
	case !cleanLine(f.Key):
		v.item(i, "key must be valid UTF-8 without control characters")
	}
	a := f.Asset
	switch {
	case a.Ref != nil && (a.Kind != "" || a.Key != ""):
		v.item(i, "asset: give either kind and key, or ref, not both")
	case a.Ref != nil:
		switch {
		case !refKinds[a.Ref.Kind]:
			v.item(i, fmt.Sprintf("asset.ref.kind %q is not an asset kind", a.Ref.Kind))
		case a.Ref.Key == "" || len(a.Ref.Key) > MaxAssetKeyLen || !cleanLine(a.Ref.Key):
			v.item(i, fmt.Sprintf("asset.ref.key must be 1 to %d bytes of UTF-8 without control characters", MaxAssetKeyLen))
		}
	case !CreatableKinds[a.Kind]:
		v.item(i, fmt.Sprintf("asset.kind %q cannot be created by ingest (allowed: cloud_resource; use asset.ref for an existing owned asset)", a.Kind))
	case a.Key == "" || len(a.Key) > MaxAssetKeyLen || !cleanLine(a.Key):
		v.item(i, fmt.Sprintf("asset.key must be 1 to %d bytes of UTF-8 without control characters", MaxAssetKeyLen))
	}
	switch {
	case strings.TrimSpace(f.Title) == "":
		v.item(i, "title is required")
	case utf8.RuneCountInString(f.Title) > MaxTitleLen:
		v.item(i, fmt.Sprintf("title longer than %d characters", MaxTitleLen))
	case !cleanLine(f.Title):
		v.item(i, "title must be valid UTF-8 without control characters")
	}
	if !f.Severity.Valid() {
		v.item(i, fmt.Sprintf("severity %q must be info|low|medium|high|critical", f.Severity))
	}
	switch {
	case strings.TrimSpace(f.Description) == "":
		v.item(i, "description is required (it becomes the alert description)")
	case len(f.Description) > MaxDescriptionLen || !cleanText(f.Description):
		v.item(i, fmt.Sprintf("description must be at most %d bytes of UTF-8 text", MaxDescriptionLen))
	}
	if len(f.Remediation) > MaxRemediationLen || !cleanText(f.Remediation) {
		v.item(i, fmt.Sprintf("remediation must be at most %d bytes of UTF-8 text", MaxRemediationLen))
	}
	if len(f.Tags) > MaxTags {
		v.item(i, fmt.Sprintf("more than %d tags", MaxTags))
	}
	for _, t := range f.Tags {
		if t == "" || len(t) > MaxTagLen || !cleanLine(t) {
			v.item(i, fmt.Sprintf("tags must be 1 to %d bytes of UTF-8 without control characters", MaxTagLen))
			break
		}
	}
	if f.Evidence != nil {
		if reason := evidenceProblem(f.Evidence); reason != "" {
			v.item(i, reason)
		}
	}
}

// evidenceProblem bounds evidence size and depth and refuses NUL characters,
// which Postgres cannot store in jsonb.
func evidenceProblem(ev map[string]any) string {
	b, err := json.Marshal(ev)
	if err != nil {
		return "evidence is not serialisable"
	}
	if len(b) > MaxEvidenceBytes {
		return fmt.Sprintf("evidence larger than %d bytes", MaxEvidenceBytes)
	}
	var walk func(v any, depth int) string
	walk = func(v any, depth int) string {
		if depth > MaxEvidenceDepth {
			return fmt.Sprintf("evidence nested deeper than %d levels", MaxEvidenceDepth)
		}
		switch x := v.(type) {
		case string:
			if strings.ContainsRune(x, 0) || !utf8.ValidString(x) {
				return "evidence strings must be valid UTF-8 without NUL"
			}
		case map[string]any:
			for k, e := range x {
				if strings.ContainsRune(k, 0) || !utf8.ValidString(k) {
					return "evidence keys must be valid UTF-8 without NUL"
				}
				if p := walk(e, depth+1); p != "" {
					return p
				}
			}
		case []any:
			for _, e := range x {
				if p := walk(e, depth+1); p != "" {
					return p
				}
			}
		}
		return ""
	}
	return walk(ev, 1)
}

// cleanLine: valid UTF-8, no control characters at all.
func cleanLine(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// cleanText: valid UTF-8; tabs and newlines allowed, other controls not.
func cleanText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

type validator struct{ out []Rejection }

func (v *validator) full() bool { return len(v.out) >= MaxProblems }

func (v *validator) req(reason string) {
	if !v.full() {
		v.out = append(v.out, Rejection{Index: -1, Reason: reason})
	}
}

func (v *validator) item(i int, reason string) {
	if !v.full() {
		v.out = append(v.out, Rejection{Index: i, Reason: reason})
	}
}

// Digest identifies a request's content: equal digests mean the same run
// delivered again. It is the SHA-256 of the request's canonical JSON
// encoding (encoding/json sorts map keys).
func Digest(r *Request) string {
	b, err := json.Marshal(r)
	if err != nil {
		return "" // unreachable for a decoded request; "" disables replay detection
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Decode parses a request body strictly: unknown fields and trailing data are
// errors.
func Decode(b []byte) (*Request, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Request
	if err := dec.Decode(&r); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("unexpected trailing data")
	}
	return &r, nil
}

// Summary joins the first few problems into one line for error messages.
func Summary(problems []Rejection) string {
	const show = 5
	parts := make([]string, 0, show+1)
	for i, p := range problems {
		if i == show {
			parts = append(parts, fmt.Sprintf("and %d more", len(problems)-show))
			break
		}
		parts = append(parts, p.String())
	}
	return strings.Join(parts, "; ")
}
