// Package bucket implements cloud.bucket: owned hostnames whose CNAME chain ends
// at an object-storage endpoint (S3, Google Cloud Storage, Azure Blob, R2) and
// that answer GET / with a public bucket listing.
//
// Safety: only the OWNED hostname is ever requested, once or twice (https,
// then http), with a plain GET / and no query string, through the scope-guarded
// client, exactly like dns.takeover. The provider's endpoint is only resolved
// via DNS. Nothing is written, no key is ever requested, only the first page of
// a listing is read, and at most 20 key names are kept as evidence.
//
// Classification of the response body:
//
//	ListBucketResult / EnumerationResults (2xx)   listable: high, critical when
//	                                              a key looks sensitive
//	AccessDenied, AllAccessDisabled, 403, ...     private: no finding
//	NoSuchBucket                                  left to dns.takeover and
//	                                              dns.dangling: no finding
//	any other 2xx page                            static website: recorded in
//	                                              the observation only
//	5xx, 429, redirects, no answer                inconclusive: run is partial
//
// Config keys (checks.cloud.bucket):
//
//	timeout_seconds    int       per-request timeout (default 10)
//	sensitive_keywords []string  extra substrings that make a listing critical
//	                             (on top of .env, backup, .sql, id_rsa,
//	                             credentials, tfstate, .pem)
//
// The check does not use Target.Intel: it asks no third-party service, so
// intel.enabled does not affect it.
package bucket

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "cloud.bucket"

// DefaultInterval is the check's cadence: a bucket policy change is worth
// noticing within the day.
const DefaultInterval = 12 * time.Hour

const (
	maxRecordedKeys = 20  // key names kept as evidence
	maxKeyLen       = 120 // characters kept per key name
	maxCountedKeys  = 10000
)

// State is the classification of one endpoint response.
type State string

const (
	StateListable     State = "listable"
	StatePrivate      State = "private"
	StateNoSuchBucket State = "no_such_bucket"
	StateWebsite      State = "website"
	StateOtherError   State = "error"
	StateNotFound     State = "not_found"
	StateInconclusive State = "inconclusive"
	StateNoAnswer     State = "no_answer"
)

// provider recognises one object-storage endpoint by the end of a CNAME chain.
type provider struct {
	name string
	re   *regexp.Regexp
	// website marks endpoints that serve a static website, not the REST API.
	website bool
}

// providers is the endpoint table; patterns match the lower-cased CNAME target
// without a trailing dot. Order matters: the website forms come first.
var providers = []provider{
	{"aws-s3-website", regexp.MustCompile(`(^|\.)s3-website([.-][a-z0-9-]+)*\.amazonaws\.com(\.cn)?$`), true},
	{"aws-s3", regexp.MustCompile(`(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com(\.cn)?$`), false},
	{"gcs", regexp.MustCompile(`(^|\.)storage\.googleapis\.com$`), false},
	{"azure-blob", regexp.MustCompile(`\.blob\.core\.windows\.net$`), false},
	{"azure-static-website", regexp.MustCompile(`\.web\.core\.windows\.net$`), true},
	{"cloudflare-r2", regexp.MustCompile(`\.(r2\.dev|r2\.cloudflarestorage\.com)$`), false},
}

// MatchProvider returns the provider whose endpoint pattern matches target.
func MatchProvider(target string) *provider {
	target = checkutil.Norm(target)
	for i := range providers {
		if providers[i].re.MatchString(target) {
			return &providers[i]
		}
	}
	return nil
}

// defaultSensitive are the substrings that make a listing critical.
var defaultSensitive = []string{".env", "backup", ".sql", "id_rsa", "credentials", "tfstate", ".pem"}

// Check is the cloud.bucket check.
type Check struct{ base map[string]any }

// New builds the check.
func New(cfg map[string]any) *Check { return &Check{base: cfg} }

// Checks is the wiring constructor.
func Checks(cfg map[string]map[string]any) []check.Check { return []check.Check{New(cfg[Name])} }

func (*Check) Name() string                   { return Name }
func (*Check) Tier() model.Tier               { return model.TierPassive }
func (*Check) DefaultInterval() time.Duration { return DefaultInterval }

// SlowLookups: the requests go to the object-storage provider's endpoint
// (up to two, each with its own timeout), not to local infrastructure, so the
// check runs in the intel queue.
func (*Check) SlowLookups() bool { return true }

// Applies matches owned hostnames; whether the CNAME ends at object storage is
// only known after resolving, so Run filters further.
func (*Check) Applies(a model.Asset) bool {
	return a.Kind == model.KindHostname && a.Scope == model.ScopeOwned
}

// Run resolves the CNAME and, for an object-storage endpoint, classifies what
// the owned hostname serves at /.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	host := checkutil.Norm(t.Asset.Key)
	res := &check.Result{}
	obs := map[string]any{"host": host}
	defer func() { res.Observations = append(res.Observations, model.ObservationInput{Check: Name, Data: obs}) }()

	// SERVFAIL, timeouts and unreachable hosts are unknown, not clean: such a
	// run is partial so it cannot count a miss against an open finding.
	cname, err := t.Resolver.LookupCNAME(ctx, host)
	if err != nil {
		if !checkutil.IsNotFound(err) {
			obs["cname_error"] = err.Error()
			res.Partial = true
		}
		return res, nil
	}
	final := checkutil.Norm(cname)
	if final == host {
		return res, nil
	}
	obs["cname"] = final
	pv := MatchProvider(final)
	if pv == nil {
		return res, nil
	}
	obs["provider"] = pv.name

	timeout := time.Duration(checkutil.Int(cfg, "timeout_seconds", 10)) * time.Second
	var errs []string
	var last *answer
	for _, scheme := range []string{"https", "http"} {
		a, err := fetch(ctx, t.HTTP, scheme, host, timeout)
		if err != nil {
			errs = append(errs, scheme+": "+err.Error())
			continue
		}
		last = a
		obs[scheme+"_status"] = a.status
		if !a.conclusive() {
			continue // a redirect or an upstream error says nothing about the bucket
		}
		break
	}
	if len(errs) > 0 {
		obs["fetch_errors"] = errs
	}
	if last == nil {
		obs["bucket_state"] = StateNoAnswer
		res.Partial = true // neither scheme answered: nothing was checked
		return res, nil
	}
	obs["bucket_state"] = last.state
	if last.code != "" {
		obs["error_code"] = last.code
	}
	switch last.state {
	case StateListable:
		res.Findings = append(res.Findings, listingFinding(host, final, pv, last, sensitiveWords(cfg)))
	case StateWebsite:
		obs["website"], obs["index_bytes"] = true, last.size
	case StateInconclusive:
		res.Partial = true
	}
	return res, nil
}

// answer is one classified response.
type answer struct {
	scheme string
	status int
	state  State
	code   string // provider error code, when the body is an error document
	size   int

	bucket    string
	keys      []string // every key on the first page (capped), untruncated names
	truncated bool     // the listing says more pages exist
}

func (a *answer) conclusive() bool { return a.state != StateInconclusive }

func fetch(ctx context.Context, client *http.Client, scheme, host string, timeout time.Duration) (*answer, error) {
	r, err := checkutil.Fetch(ctx, client, scheme+"://"+host+"/", checkutil.FetchOpts{Timeout: timeout})
	if err != nil {
		return nil, err
	}
	a := classify(r.Status, r.Body)
	a.scheme = scheme
	return a, nil
}

// classify decides what a GET / answer means for the bucket behind the host.
func classify(status int, body []byte) *answer {
	a := &answer{status: status, size: len(body)}
	root, doc := parseXML(body)
	switch {
	case root == "listbucketresult" || root == "enumerationresults":
		if status/100 != 2 {
			a.state = StateInconclusive
			return a
		}
		a.state = StateListable
		a.bucket, a.keys, a.truncated = doc.bucket, doc.keys, doc.truncated
	case root == "error":
		a.code = doc.code
		switch strings.ToLower(doc.code) {
		case "accessdenied", "allaccessdisabled", "nosuchwebsiteconfiguration", "forbidden", "anonymouscallerdoesnothavestorageobjectslistaccess",
			"publicaccessnotpermitted", "authorizationfailure", "authenticationfailed", "authorizationpermissionmismatch", "invalidaccesskeyid", "signaturedoesnotmatch":
			a.state = StatePrivate
		case "nosuchbucket", "containernotfound", "resourcenotfound":
			a.state = StateNoSuchBucket
		default:
			a.state = StateOtherError
		}
	case status == http.StatusForbidden || status == http.StatusUnauthorized:
		a.state = StatePrivate
	case status/100 == 2:
		a.state = StateWebsite
	case status == http.StatusNotFound || status == http.StatusGone:
		a.state = StateNotFound
	default: // 3xx, 429, 5xx and anything unexpected
		a.state = StateInconclusive
	}
	return a
}

// xmlDoc is what classify needs from a provider's XML document.
type xmlDoc struct {
	bucket    string
	keys      []string
	truncated bool
	code      string
}

// parseXML returns the lower-cased root element name ("" when the body is not
// XML, or is an HTML page) and the fields of a listing or an error document.
// It never expands entities and keeps going on a cut-off body, so a first page
// larger than the fetch cap still classifies. Only the first page is read.
func parseXML(body []byte) (string, xmlDoc) {
	var doc xmlDoc
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	var stack []string
	var text strings.Builder
	root := ""
	for {
		tok, err := dec.Token()
		if err != nil {
			break // end of document, not XML, or cut off: keep what was read
		}
		switch e := tok.(type) {
		case xml.StartElement:
			name := strings.ToLower(e.Name.Local)
			if root == "" {
				root = name
				if root == "html" {
					return "", doc
				}
				if root != "listbucketresult" && root != "enumerationresults" && root != "error" {
					return root, doc // not a provider document; no need to read on
				}
			}
			stack = append(stack, name)
			text.Reset()
		case xml.CharData:
			if len(stack) > 0 && text.Len() < 4*maxKeyLen {
				text.Write(e)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			name, parent := stack[len(stack)-1], ""
			if len(stack) > 1 {
				parent = stack[len(stack)-2]
			}
			val := strings.TrimSpace(text.String())
			switch {
			case name == "key" && parent == "contents", name == "name" && (parent == "blob" || parent == "container"):
				if len(doc.keys) < maxCountedKeys {
					doc.keys = append(doc.keys, val)
				}
			case name == "name" && parent == root:
				doc.bucket = clip(val)
			case name == "istruncated" && strings.EqualFold(val, "true"):
				doc.truncated = true
			case name == "nextmarker" && val != "":
				doc.truncated = true
			case name == "code" && parent == "error":
				doc.code = clip(val)
			}
			stack = stack[:len(stack)-1]
			text.Reset()
		}
	}
	return root, doc
}

func clip(s string) string {
	if utf8.RuneCountInString(s) <= maxKeyLen {
		return strings.ToValidUTF8(s, "")
	}
	return strings.ToValidUTF8(string([]rune(s)[:maxKeyLen]), "") + "…"
}

func sensitiveWords(cfg map[string]any) []string {
	words := append([]string{}, defaultSensitive...)
	for _, w := range checkutil.Strings(cfg, "sensitive_keywords", nil) {
		if w = strings.ToLower(strings.TrimSpace(w)); w != "" {
			words = append(words, w)
		}
	}
	return words
}

// listingFinding builds the "publicly listable" finding.
func listingFinding(host, cname string, pv *provider, a *answer, words []string) model.FindingInput {
	var sensitive, others []string
	markers := map[string]bool{}
	for _, k := range a.keys {
		lk, hit := strings.ToLower(k), false
		for _, w := range words {
			if strings.Contains(lk, w) {
				markers[w], hit = true, true
			}
		}
		if hit {
			sensitive = append(sensitive, k)
		} else {
			others = append(others, k)
		}
	}
	// Names that triggered the severity come first so they survive the cap.
	var recorded []string
	for _, k := range append(append([]string{}, sensitive...), others...) {
		if len(recorded) == maxRecordedKeys {
			break
		}
		recorded = append(recorded, clip(k))
	}
	var hitWords []string
	for _, w := range words {
		if markers[w] {
			hitWords = append(hitWords, w)
			delete(markers, w)
		}
	}

	sev := model.SeverityHigh
	more := ""
	if len(sensitive) > 0 {
		sev = model.SeverityCritical
		more = fmt.Sprintf(" %d of the keys on the first page look sensitive (matching %s).", len(sensitive), strings.Join(hitWords, ", "))
	}
	page := fmt.Sprintf("%d keys", len(a.keys))
	if a.truncated {
		page += " (the listing is truncated: more pages exist)"
	}
	ev := map[string]any{
		"host": host, "cname": cname, "provider": pv.name, "url": a.scheme + "://" + host + "/",
		"http_status": a.status, "keys_on_page": len(a.keys), "truncated": a.truncated,
		"keys": recorded, "keys_recorded_max": maxRecordedKeys,
	}
	if a.bucket != "" {
		ev["bucket"] = a.bucket
	}
	if len(sensitive) > 0 {
		ev["sensitive_keys"], ev["sensitive_markers"] = len(sensitive), hitWords
	}
	return model.FindingInput{
		Check: Name, Key: "listable", Severity: sev,
		Title: fmt.Sprintf("object storage behind %s is publicly listable", host),
		Description: fmt.Sprintf("%s is a CNAME to %s (%s) and answers GET / with a bucket listing, so anyone on the internet can enumerate the objects in the bucket (%s on the first page).%s Only the first page was read; no object was requested and nothing was written.",
			host, cname, pv.name, page, more),
		Remediation: remediation(pv, host),
		Evidence:    ev, Tags: []string{"cloud", "storage", "listing", pv.name},
	}
}

func remediation(pv *provider, host string) string {
	var fix string
	switch {
	case strings.HasPrefix(pv.name, "aws"):
		fix = "Turn on S3 Block Public Access for the bucket (and the account) and remove the bucket policy statements or ACL grants that give s3:ListBucket, or the AllUsers READ ACL, to everyone. Serve public objects through CloudFront with an origin access control instead of making the bucket listable."
	case pv.name == "gcs":
		fix = "Remove allUsers and allAuthenticatedUsers from every role that includes storage.objects.list (for example roles/storage.legacyBucketReader or roles/storage.objectViewer on the bucket), enforce public access prevention and uniform bucket-level access, and grant public reads with roles/storage.legacyObjectReader, which reads a known object but cannot list."
	case strings.HasPrefix(pv.name, "azure"):
		fix = "Set the container's public access level to Private (or Blob, which allows reads by exact name but not listing) and disable anonymous access on the storage account (AllowBlobPublicAccess = false) unless a container needs it."
	default:
		fix = "Turn off public access to the bucket (disable the r2.dev subdomain, or expose only object reads through a custom domain) so it cannot be listed."
	}
	return fix + " Review the listed keys for exposed secrets, backups and personal data and rotate any credential found; if " + host + " should not point at object storage at all, remove the CNAME."
}
