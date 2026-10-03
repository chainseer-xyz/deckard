// Package history implements web.history: sensitive paths that the Internet
// Archive's Wayback Machine saw served by an owned hostname.
//
// The check asks the Wayback CDX API (through Target.Intel, service wayback)
// which URLs under the host it captured with HTTP 200, and matches them against
// a curated pattern table (patterns.go: secrets and VCS metadata, database and
// archive dumps, admin and debug surfaces, a few low-signal leftovers). It never
// requests the live host or the archived URL: an archived hit says the path WAS
// served, not that it still is. Pair it with the active http.exposed check,
// which probes the live host where that is allowed.
//
// Findings: one per matched path (subtree rules such as .git/ report the
// directory), key "path:<normalised path>", at most max_findings per host,
// highest severity first, newest capture first. A path served as text/html that
// should be a file (a .env, a .sql) is probably a soft 404 and is one severity
// lower.
//
// Config keys (checks.web.history):
//
//	max_findings  int       findings per host (default 10, 1..50)
//	max_results   int       CDX rows requested per host (default 3000, 100..10000);
//	                        a full page means the history was cut off
//	min_severity  string    drop findings below this severity (default low)
//	ignore_paths  []string  path prefixes never reported, for paths that are
//	                        public on purpose (for example /admin)
//	max_age_days  int       ignore captures older than this (default 0: no limit)
//
// A disabled or missing intel client, a lookup error, an unusable answer, a
// truncated history or more matches than max_findings never raise or resolve
// anything on missing data: the observation says why and the run is partial.
package history

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/intel"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "web.history"

// DefaultInterval is the check's cadence: the archive changes slowly and a new
// hostname is still checked once straight away (on_new_asset).
const DefaultInterval = 7 * 24 * time.Hour

// Defaults and bounds for the config keys.
const (
	DefaultMaxFindings = 10
	DefaultMaxResults  = 3000
	maxFindingsLimit   = 50
	minResults         = 100
	maxResultsLimit    = 10000
	maxEvidenceURLs    = 5
	maxPathLen         = 200
)

// Observation states for the lookup.
const (
	StateOK          = "ok"
	StateSkipped     = "skipped"
	StateUnsupported = "unsupported"
	StateNotFound    = "not_found"
	StateRateLimited = "rate_limited"
	StateTooLarge    = "too_large"
	StateUnusable    = "unusable"
	StateUnavailable = "unavailable"
)

const cdxEndpoint = "https://web.archive.org/cdx/search/cdx"

// Check is the web.history check.
type Check struct {
	base map[string]any
	now  func() time.Time
}

// New builds the check.
func New(cfg map[string]any) *Check { return &Check{base: cfg, now: time.Now} }

// Checks is the wiring constructor.
func Checks(cfg map[string]map[string]any) []check.Check { return []check.Check{New(cfg[Name])} }

func (*Check) Name() string                   { return Name }
func (*Check) Tier() model.Tier               { return model.TierPassive }
func (*Check) DefaultInterval() time.Duration { return DefaultInterval }

// SlowLookups: every run waits on the rate-limited Wayback CDX API (about half
// a minute per asset), so it runs in the intel queue.
func (*Check) SlowLookups() bool { return true }

// Applies matches owned hostnames (IP addresses are not archived by name).
func (*Check) Applies(a model.Asset) bool {
	return a.Kind == model.KindHostname && a.Scope == model.ScopeOwned
}

type options struct {
	maxFindings int
	maxResults  int
	minSev      model.Severity
	ignore      []string
	maxAge      time.Duration
}

func readOptions(cfg map[string]any, obs map[string]any) options {
	o := options{
		maxFindings: checkutil.Int(cfg, "max_findings", DefaultMaxFindings),
		maxResults:  checkutil.Int(cfg, "max_results", DefaultMaxResults),
		minSev:      model.Severity(checkutil.Str(cfg, "min_severity", string(model.SeverityLow))),
	}
	var notes []string
	if o.maxFindings < 1 || o.maxFindings > maxFindingsLimit {
		notes = append(notes, fmt.Sprintf("max_findings must be 1..%d; using %d", maxFindingsLimit, DefaultMaxFindings))
		o.maxFindings = DefaultMaxFindings
	}
	if o.maxResults < minResults || o.maxResults > maxResultsLimit {
		notes = append(notes, fmt.Sprintf("max_results must be %d..%d; using %d", minResults, maxResultsLimit, DefaultMaxResults))
		o.maxResults = DefaultMaxResults
	}
	if !o.minSev.Valid() {
		notes = append(notes, "min_severity must be info|low|medium|high|critical; using low")
		o.minSev = model.SeverityLow
	}
	if days := checkutil.Int(cfg, "max_age_days", 0); days > 0 {
		o.maxAge = time.Duration(days) * 24 * time.Hour
	} else if days < 0 {
		notes = append(notes, "max_age_days must be >= 0; ignoring it")
	}
	for _, p := range checkutil.Strings(cfg, "ignore_paths", nil) {
		p = strings.ToLower(strings.TrimRight(strings.TrimSpace(p), "/"))
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		o.ignore = append(o.ignore, p)
	}
	if len(notes) > 0 {
		obs["options_note"] = strings.Join(notes, "; ")
	}
	return o
}

func (o options) ignored(p string) bool {
	for _, i := range o.ignore {
		if p == i || strings.HasPrefix(p, i+"/") {
			return true
		}
	}
	return false
}

// Run asks the archive for the host's history and matches it.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	host := checkutil.Norm(t.Asset.Key)
	obs := map[string]any{"host": host}
	res := &check.Result{}
	// A run that did not see the whole history proves nothing: nothing resolves.
	stop := func(state, note string) (*check.Result, error) {
		obs["wayback"], obs["wayback_note"] = state, note
		res.Observations = []model.ObservationInput{{Check: Name, Data: obs}}
		res.Partial = true
		return res, nil
	}
	if !validHost(host) {
		return stop(StateUnsupported, "not a plain hostname the archive can be queried for")
	}
	if t.Intel == nil {
		return stop(StateSkipped, "metadata client not available")
	}
	opts := readOptions(cfg, obs)

	q := url.Values{}
	q.Set("url", host+"/*")
	q.Set("output", "json")
	q.Set("fl", "original,statuscode,timestamp,mimetype")
	q.Set("filter", "statuscode:200")
	q.Set("collapse", "urlkey")
	q.Set("limit", fmt.Sprint(opts.maxResults))
	resp, err := t.Intel.Get(ctx, intel.ServiceWayback, cdxEndpoint+"?"+q.Encode())
	if err != nil {
		return stop(classify(err))
	}
	rows, truncated, err := parseCDX(resp.Body, opts.maxResults)
	if err != nil {
		return stop(StateUnusable, "unusable cdx response: "+err.Error())
	}

	now := c.now()
	obs["wayback"] = StateOK
	obs["rows"] = len(rows.captures)
	if rows.skipped > 0 {
		obs["rows_skipped"] = rows.skipped
	}
	if truncated {
		obs["truncated"] = true
		obs["truncated_note"] = fmt.Sprintf("the archive returned %d rows (max_results); older or later paths may be missing, so the run is partial", opts.maxResults)
		res.Partial = true
	}

	hits := collect(host, rows.captures, opts, now)
	var kept []*hit
	below := 0
	for _, h := range hits {
		if !h.severity().AtLeast(opts.minSev) {
			below++
			continue
		}
		kept = append(kept, h)
	}
	if below > 0 {
		obs["below_min_severity"] = below
	}
	sort.Slice(kept, func(i, j int) bool {
		a, b := kept[i], kept[j]
		if a.severity() != b.severity() {
			return a.severity().Rank() > b.severity().Rank()
		}
		if !a.newest.Equal(b.newest) {
			return a.newest.After(b.newest)
		}
		return a.path < b.path
	})
	obs["matched"] = len(kept)
	if len(kept) > opts.maxFindings {
		obs["capped"] = len(kept) - opts.maxFindings
		res.Partial = true // a finding cut by the cap must not be resolved by a later run that ranks it lower
		kept = kept[:opts.maxFindings]
	}
	for _, h := range kept {
		res.Findings = append(res.Findings, h.finding(host))
	}
	res.Observations = []model.ObservationInput{{Check: Name, Data: obs}}
	return res, nil
}

// classify maps an intel error onto an observation state and note. None of
// them is a finding.
func classify(err error) (string, string) {
	switch {
	case errors.Is(err, intel.ErrDisabled):
		return StateSkipped, "intel disabled (intel.enabled or intel.services.wayback.enabled is false)"
	case errors.Is(err, intel.ErrNotFound):
		return StateNotFound, "the archive has no answer for this host"
	case errors.Is(err, intel.ErrRateLimited):
		return StateRateLimited, "the archive rate limited the lookup; it is retried at the next interval"
	case errors.Is(err, intel.ErrTooLarge):
		return StateTooLarge, "the archive's answer exceeds the size cap (intel.services.wayback.max_bytes); the history is too large to read"
	}
	return StateUnavailable, err.Error()
}

// validHost accepts plain LDH hostnames (underscores allowed): wildcards, IDNs
// in unicode form and anything with a path or port are not queried.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

// capture is one CDX row.
type capture struct {
	original string
	mime     string
	at       time.Time
}

type cdxRows struct {
	captures []capture
	skipped  int // rows with a missing field, a non-200 status or a bad timestamp
}

// parseCDX reads the CDX JSON array row by row so a huge answer is never
// materialised: it stops after limit data rows. truncated reports that the
// archive filled the page (more rows may exist). An empty body or "[]" is an
// archive with no captures, not an error.
func parseCDX(body []byte, limit int) (cdxRows, bool, error) {
	var out cdxRows
	if len(bytes.TrimSpace(body)) == 0 {
		return out, false, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return out, false, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return out, false, errors.New("not a json array")
	}
	if !dec.More() {
		return out, false, nil
	}
	var header []string
	if err := dec.Decode(&header); err != nil {
		return out, false, fmt.Errorf("header row: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	for _, need := range []string{"original", "statuscode", "timestamp", "mimetype"} {
		if _, ok := col[need]; !ok {
			return out, false, fmt.Errorf("header lacks column %q", need)
		}
	}
	n := 0
	for dec.More() {
		if n >= limit {
			return out, true, nil
		}
		var row []string
		if err := dec.Decode(&row); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return out, false, errors.New("cut-off json")
			}
			return out, false, fmt.Errorf("row %d: %w", n+1, err)
		}
		n++
		if len(row) < len(header) || row[col["statuscode"]] != "200" {
			out.skipped++
			continue
		}
		at, err := time.Parse("20060102150405", row[col["timestamp"]])
		if err != nil {
			out.skipped++
			continue
		}
		out.captures = append(out.captures, capture{original: row[col["original"]], mime: row[col["mimetype"]], at: at.UTC()})
	}
	if _, err := dec.Token(); err != nil {
		return out, false, errors.New("cut-off json")
	}
	return out, n >= limit, nil
}

// hit accumulates the captures of one normalised path.
type hit struct {
	rule   rule
	path   string
	urls   map[string]time.Time // query-less URL -> newest capture
	newest time.Time
	newMIM string
	total  int
	allHTM bool // every capture was an HTML page
}

func (h *hit) severity() model.Severity {
	if h.rule.file && h.allHTM {
		return lower(h.rule.sev)
	}
	return h.rule.sev
}

// collect matches captures against the table and groups them by path. Captures
// of other hosts (the archive's prefix match can return odd rows), unparsable
// URLs, ignored paths and captures older than max_age_days are dropped.
func collect(host string, caps []capture, o options, now time.Time) []*hit {
	byPath := map[string]*hit{}
	for _, c := range caps {
		if o.maxAge > 0 && now.Sub(c.at) > o.maxAge {
			continue
		}
		clean, p, ok := archivedPath(host, c.original)
		if !ok {
			continue
		}
		ru, reported, ok := matchRule(p)
		if !ok || o.ignored(reported) {
			continue
		}
		reported = clip(reported)
		h := byPath[reported]
		if h == nil {
			h = &hit{rule: ru, path: reported, urls: map[string]time.Time{}, allHTM: true}
			byPath[reported] = h
		}
		h.total++
		if prev, seen := h.urls[clean]; !seen || c.at.After(prev) {
			h.urls[clean] = c.at
		}
		if !softMIME(c.mime) {
			h.allHTM = false
		}
		if c.at.After(h.newest) {
			h.newest, h.newMIM = c.at, c.mime
		}
	}
	out := make([]*hit, 0, len(byPath))
	for _, h := range byPath {
		out = append(out, h)
	}
	return out
}

// archivedPath parses an archived URL for host. clean is the URL without query
// string or fragment, p the lower-cased cleaned path used for matching.
func archivedPath(host, original string) (clean, p string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(original))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || checkutil.Norm(u.Hostname()) != host {
		return "", "", false
	}
	if port := u.Port(); port != "" && port != "80" && port != "443" {
		return "", "", false
	}
	raw := u.Path
	if raw == "" {
		raw = "/"
	}
	p = strings.ToLower(path.Clean("/" + strings.TrimLeft(raw, "/")))
	if strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", "", false
	}
	clean = u.Scheme + "://" + host + (&url.URL{Path: u.Path}).EscapedPath()
	if u.Path == "" {
		clean += "/"
	}
	return clip(clean), p, true
}

// clip bounds a string taken from the archive.
func clip(s string) string {
	if len(s) <= maxPathLen {
		return s
	}
	return strings.ToValidUTF8(s[:maxPathLen], "")
}

// finding renders the hit.
func (h *hit) finding(host string) model.FindingInput {
	sev := h.severity()
	date := h.newest.Format("2006-01-02")

	urls := make([]string, 0, len(h.urls))
	for u := range h.urls {
		urls = append(urls, u)
	}
	sort.Slice(urls, func(i, j int) bool {
		if !h.urls[urls[i]].Equal(h.urls[urls[j]]) {
			return h.urls[urls[i]].After(h.urls[urls[j]])
		}
		return urls[i] < urls[j]
	})
	shown := urls
	if len(shown) > maxEvidenceURLs {
		shown = shown[:maxEvidenceURLs]
	}
	newest := h.path
	if len(urls) > 0 {
		newest = urls[0]
	}
	ev := map[string]any{
		"host": host, "path": h.path, "class": h.rule.class, "match": h.rule.label,
		"urls": shown, "urls_total": len(urls), "captures": h.total,
		"status": 200, "mimetype": h.newMIM, "captured_at": h.newest.Format(time.RFC3339),
		"source": "web.archive.org",
	}
	if sev != h.rule.sev {
		ev["downgraded"] = "every capture was served as text/html, so this is probably a soft 404 or an application shell rather than the file itself"
	}
	return model.FindingInput{
		Check: Name, Key: "path:" + h.path, Severity: sev,
		Title: fmt.Sprintf("Wayback Machine saw %s served on %s: %s", h.rule.label, host, h.path),
		Description: fmt.Sprintf("%s was archived as publicly served on %s (HTTP 200): the %s was reachable by anyone then, and the archive may still hold a copy. This check does not request the live URL.%s",
			newest, date, h.rule.label, h.classNote()),
		Remediation: remediation(h.rule.class, h.path),
		Evidence:    ev,
		Tags:        []string{"web", "history", "wayback", h.rule.class},
	}
}

func (h *hit) classNote() string {
	if h.rule.sev != h.severity() {
		return " Every capture was served as text/html, so it may only be a soft 404 or an application shell."
	}
	return ""
}

func remediation(class, p string) string {
	const verify = "Confirm %s is no longer served (the active http.exposed check probes the live host where it is allowed; otherwise request it yourself) and remove it from the web root and the deployment pipeline. "
	const exclude = " If the archived copy itself exposes data, ask the Internet Archive to exclude it (info@archive.org)."
	head := fmt.Sprintf(verify, p)
	switch class {
	case ClassSecrets:
		return head + "Treat every credential, token, key and secret the file could have held as exposed and rotate it, whether or not it is still served; block dotfiles and VCS directories at the web server." + exclude
	case ClassDump:
		return head + "Treat the data in the dump as disclosed: rotate any credentials and tokens in it, assess whether personal data was exposed and notify as required, and keep backups outside the web root." + exclude
	case ClassAdmin:
		return head + "Restrict the admin or debug interface to a VPN, an IP allow-list or single sign-on and disable debug tooling in production builds. If the path is meant to be public, add it to checks.web.history.ignore_paths."
	}
	return head + "Block the file type at the web server and exclude it from deployments."
}
