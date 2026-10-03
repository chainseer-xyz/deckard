package prowlerapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Options select and bound what is pulled.
type Options struct {
	// ProviderTypes and ProviderUIDs restrict the providers (any match of each
	// non-empty list); both empty means every provider.
	ProviderTypes []string
	ProviderUIDs  []string
	// MinSeverity is the floor; findings below it are not reported, so they are
	// not part of what a complete run asserts.
	MinSeverity  model.Severity
	IncludeMuted bool
	// MaxScanAge: a completed scan older than this never makes a complete run.
	MaxScanAge time.Duration
	// MaxFindings caps the findings of one request (ingest.MaxFindings at most).
	MaxFindings int
	// Now is the clock (tests inject one).
	Now  func() time.Time
	Logf func(format string, args ...any)
}

func (o *Options) normalize() {
	if o.MaxFindings <= 0 || o.MaxFindings > ingest.MaxFindings {
		o.MaxFindings = ingest.MaxFindings
	}
	if o.MinSeverity == "" {
		o.MinSeverity = model.SeverityMedium
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxScanAge <= 0 {
		o.MaxScanAge = 48 * time.Hour
	}
}

// Run is the result of pulling one provider.
type Run struct {
	Provider Provider
	Scope    string
	// ScanID is the scan the findings come from ("" when none was usable).
	ScanID string
	// Request is the ingest request to post; nil when there is nothing valid to
	// post (see Err).
	Request *ingest.Request
	// Total counts the findings found before the cap and the size limit cut
	// the request.
	Total int
	// Merged counts duplicate keys merged away (the key set is unaffected).
	Merged int
	// Reasons say why Request is not complete (empty when it is).
	Reasons []string
	// Err is why there is no Request.
	Err error
}

// Complete is whether the request asserts completeness.
func (r *Run) Complete() bool { return r.Request != nil && r.Request.Complete }

// Collector pulls runs from a Prowler App.
type Collector struct {
	c *Client
	o Options
}

// NewCollector builds a collector over c.
func NewCollector(c *Client, o Options) *Collector {
	o.normalize()
	return &Collector{c: c, o: o}
}

func (col *Collector) logf(format string, args ...any) {
	if col.o.Logf != nil {
		col.o.Logf(format, args...)
	}
}

// Providers lists the providers to pull, in a stable order. skipped counts
// providers Prowler listed that could not be decoded.
func (col *Collector) Providers(ctx context.Context) (providers []Provider, skipped int, err error) {
	all, skipped, err := col.c.Providers(ctx)
	if err != nil {
		return nil, 0, err
	}
	for _, p := range all {
		if matches(col.o.ProviderTypes, p.Type, true) && matches(col.o.ProviderUIDs, p.UID, false) {
			providers = append(providers, p)
		}
	}
	sort.Slice(providers, func(i, j int) bool {
		a, b := providers[i], providers[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.UID < b.UID
	})
	return providers, skipped, nil
}

func matches(want []string, got string, fold bool) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		if w == got || fold && strings.EqualFold(w, got) {
			return true
		}
	}
	return false
}

// Collect pulls one provider's latest scan and builds the ingest request. It
// never returns a complete request unless every condition holds:
//
//  1. the provider is connected;
//  2. its newest scan that has run is completed (not executing, failed or
//     cancelled) and has a completed_at;
//  3. that scan is no older than MaxScanAge;
//  4. every page of findings was fetched without error, the findings count
//     matches the server's own count, no finding repeated across pages and
//     every finding belongs to that scan;
//  5. no newer completed scan appeared while fetching;
//  6. no finding was unmappable or mapped from doubtful data, and the run
//     fits in one request (finding cap and body size).
//
// Anything else yields an incomplete request (which can open and refresh but
// never resolves) when there is something valid to post, with the reasons.
func (col *Collector) Collect(ctx context.Context, p Provider) *Run {
	run := &Run{Provider: p, Scope: Scope(p)}
	why := &reasons{}

	scans, err := col.c.RecentScans(ctx, p.ID)
	if err != nil {
		run.Err = fmt.Errorf("list scans: %w", err)
		return run
	}
	latest, basis := pickScans(scans)
	switch {
	case latest == nil:
		run.Err = errors.New("no scan has run for this provider yet")
		return run
	case basis == nil:
		run.Err = fmt.Errorf("no completed scan (the latest, %s, is %s)", latest.ID, latest.State)
		return run
	}
	run.ScanID = basis.ID
	now := col.o.Now()
	switch {
	case basis.CompletedAt.IsZero():
		run.Err = fmt.Errorf("scan %s is completed but has no completed_at", basis.ID)
		return run
	case basis.CompletedAt.After(now.Add(ingest.MaxFutureSkew)):
		run.Err = fmt.Errorf("scan %s completed_at (%s) is in the future: clock skew between Prowler and this host", basis.ID, basis.CompletedAt.Format(time.RFC3339))
		return run
	}
	if latest.ID != basis.ID {
		why.add(fmt.Sprintf("the latest scan %s is %s; using the last completed scan %s", latest.ID, latest.State, basis.ID))
	}
	if age := now.Sub(basis.CompletedAt); age > col.o.MaxScanAge {
		why.add(fmt.Sprintf("scan %s is stale: completed %s ago, over --max-scan-age %s", basis.ID, age.Round(time.Minute), col.o.MaxScanAge))
	}
	if !p.Connected {
		why.add("the provider is not connected")
	}

	found, err := col.fetch(ctx, p, *basis, why)
	if err != nil {
		why.add("fetching findings failed: " + redactErr(err))
		run.Err = err
	}
	if err == nil {
		// A newer completed scan would have replaced the latest findings midway.
		if again, rerr := col.c.RecentScans(ctx, p.ID); rerr != nil {
			why.add("could not re-check the latest scan: " + redactErr(rerr))
		} else if _, b2 := pickScans(again); b2 == nil || b2.ID != basis.ID || !b2.CompletedAt.Equal(basis.CompletedAt) {
			why.add("a newer scan completed while the findings were being fetched")
		}
	}

	merged, n := Merge(found.findings)
	run.Merged = n
	run.Total = len(merged)
	if found.stoppedEarly {
		why.add("stopped reading findings once the per-request cap was exceeded")
	}
	if len(merged) == 0 && err != nil {
		run.Reasons = why.list()
		return run // nothing gathered and the fetch failed: nothing valid to post
	}
	merged = col.fit(p, merged, why)
	obs := basis.CompletedAt
	req := &ingest.Request{Tool: Tool, Scope: run.Scope, Complete: why.empty() && err == nil, ObservedAt: &obs, Findings: merged}
	if req.Findings == nil {
		req.Findings = []ingest.Finding{}
	}
	if problems := ingest.Validate(req, ingest.Options{Now: now}); len(problems) > 0 {
		run.Err = fmt.Errorf("the request would be rejected: %s", ingest.Summary(problems))
		run.Reasons = why.list()
		return run
	}
	run.Request = req
	run.Reasons = why.list()
	if err != nil {
		run.Err = nil // posted what was gathered, incomplete; the reasons say why
	}
	return run
}

// pickScans returns the newest scan that has run (not merely scheduled) and
// the newest completed one.
func pickScans(scans []Scan) (latest, completed *Scan) {
	ran := make([]Scan, 0, len(scans))
	for _, s := range scans {
		if s.State != "scheduled" && s.State != "available" {
			ran = append(ran, s)
		}
	}
	sort.SliceStable(ran, func(i, j int) bool { return ran[i].Sort.After(ran[j].Sort) })
	for i := range ran {
		if latest == nil {
			latest = &ran[i]
		}
		if ran[i].State == "completed" {
			return latest, &ran[i]
		}
	}
	return latest, nil
}

type fetched struct {
	findings     []ingest.Finding
	stoppedEarly bool
}

// fetch pages through the latest findings of p. Problems that make the result
// doubtful are added to why; an error means the pages could not all be read.
func (col *Collector) fetch(ctx context.Context, p Provider, scan Scan, why *reasons) (fetched, error) {
	q := FindingsQuery{ProviderID: p.ID, Severities: ProwlerSeverities(col.o.MinSeverity), IncludeMuted: col.o.IncludeMuted, Sparse: true}
	out, err := col.fetchPages(ctx, p, scan, q, why)
	var he *HTTPError
	if q.Sparse && len(out.findings) == 0 && errors.As(err, &he) && he.Status == http.StatusBadRequest {
		col.logf("%s: the server refused sparse fieldsets; asking for full findings", Scope(p))
		q.Sparse = false
		out, err = col.fetchPages(ctx, p, scan, q, why)
	}
	return out, err
}

func (col *Collector) fetchPages(ctx context.Context, p Provider, scan Scan, q FindingsQuery, why *reasons) (fetched, error) {
	var out fetched
	var raw []ingest.Finding
	seen := map[string]bool{}
	expect, got, pages := -1, 0, 0
	err := col.c.LatestFindings(ctx, q, func(d *Document) (bool, error) {
		pages++
		if pages == 1 {
			expect = d.Meta.Count
		}
		ix := d.IndexIncluded()
		mc := MapContext{Provider: p, ScanID: scan.ID, Resource: func(r Ref) (RawResource, bool) {
			res, ok := ix[r]
			if !ok {
				return RawResource{}, false
			}
			rr, err := AsResource(res)
			return rr, err == nil
		}}
		for _, r := range d.Data {
			got++
			if r.Type != "findings" {
				why.add(fmt.Sprintf("unexpected %q item in the findings", ingest.Line(r.Type, 32)))
				continue
			}
			if seen[r.ID] {
				why.add("a finding appeared on two pages: the result set shifted while paging")
				continue
			}
			seen[r.ID] = true
			f, err := AsFinding(r)
			if err != nil {
				why.add("a finding could not be decoded: " + redactErr(err))
				continue
			}
			if f.Scan.Known && len(f.Scan.Refs) > 0 && f.Scan.Refs[0].ID != scan.ID {
				why.add(fmt.Sprintf("finding %s belongs to scan %s, not %s: the latest scan changed while paging", ingest.Line(f.ID, 64), ingest.Line(f.Scan.Refs[0].ID, 64), scan.ID))
				continue
			}
			if !Wanted(f, col.o.MinSeverity, col.o.IncludeMuted) {
				continue
			}
			m := MapFinding(mc, f)
			if m.Incomplete != "" {
				why.add(m.Incomplete)
			}
			raw = append(raw, m.Findings...)
			if len(raw) > col.o.MaxFindings+col.o.MaxFindings/10 {
				out.stoppedEarly = true
				return true, nil
			}
		}
		return false, nil
	})
	out.findings = raw
	if err == nil && !out.stoppedEarly && expect >= 0 && got != expect {
		why.add(fmt.Sprintf("the server announced %d findings but %d were returned", expect, got))
	}
	col.logf("%s: %d pages, %d findings returned, %d mapped", Scope(p), pages, got, len(raw))
	return out, err
}

// fit makes the findings one valid request: at most MaxFindings and within the
// body size limit. It cuts the least severe first and says so in why; a
// truncated run is never complete.
func (col *Collector) fit(p Provider, in []ingest.Finding, why *reasons) []ingest.Finding {
	keep := len(in)
	if keep > col.o.MaxFindings {
		keep = col.o.MaxFindings
		why.add(fmt.Sprintf("%d findings exceed the %d per request: raise --min-severity (sending the %d most severe)", len(in), col.o.MaxFindings, keep))
	}
	const headroom = 4096 // the envelope around the findings
	out := mostSevere(in, keep)
	cutBySize := false
	for keep > 0 {
		body, err := json.Marshal(&ingest.Request{Tool: Tool, Scope: Scope(p), ObservedAt: &time.Time{}, Findings: out})
		if err != nil || len(body) <= ingest.MaxBodyBytes-headroom {
			break
		}
		keep = keep * (ingest.MaxBodyBytes - headroom) / len(body) * 95 / 100
		out = mostSevere(in, keep)
		cutBySize = true
	}
	if cutBySize {
		why.add(fmt.Sprintf("the request would exceed %d MiB: raise --min-severity (sending the %d most severe)", ingest.MaxBodyBytes>>20, keep))
	}
	return out
}

// mostSevere returns the n most severe findings, ordered by key again.
func mostSevere(in []ingest.Finding, n int) []ingest.Finding {
	if n >= len(in) {
		return in
	}
	ranked := append([]ingest.Finding(nil), in...)
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].Severity.Rank() > ranked[j].Severity.Rank() })
	ranked = ranked[:n]
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].Key < ranked[j].Key })
	return ranked
}

// redactErr is err's text on one bounded line.
func redactErr(err error) string { return ingest.Line(err.Error(), 300) }

// reasons collects distinct reasons a run is not complete.
type reasons struct {
	seen map[string]int
	ord  []string
}

func (r *reasons) add(s string) {
	if r.seen == nil {
		r.seen = map[string]int{}
	}
	if r.seen[s]++; r.seen[s] == 1 {
		r.ord = append(r.ord, s)
	}
}

func (r *reasons) empty() bool { return len(r.ord) == 0 }

// list is the reasons, at most five plus a count of the rest.
func (r *reasons) list() []string {
	const show = 5
	if len(r.ord) <= show {
		return append([]string(nil), r.ord...)
	}
	return append(append([]string(nil), r.ord[:show]...), fmt.Sprintf("and %d more reasons", len(r.ord)-show))
}
