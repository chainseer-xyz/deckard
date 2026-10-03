// Package lookalike implements domain.lookalike: typosquats and other
// lookalike registrations of the operator's own registrable domains, a common
// phishing and brand-abuse vector.
//
// The check is DNS-only. For each owned registrable apex (once per apex) it
// generates permutations of the brand label (internal/lookalike) and asks the
// configured recursive resolvers whether each name exists and what its NS, A,
// AAAA and MX answers are. It never connects to a lookalike: no HTTP, no TLS,
// no probe of any kind. The names are third parties' hosts, so the queries do
// not go through the scope guard (which rightly refuses them) but through
// Target.Lookup, a dedicated client that sends DNS queries to the configured
// resolvers only, behind one process-wide rate limit.
//
// A candidate is registered when it has NS records, an A or AAAA record, or a
// usable MX (a null MX, RFC 7505, is not one), or when its name is an alias
// (CNAME). Each registered lookalike is its own finding, keyed by the domain,
// so a new registration opens a new finding and alerts, and one that
// disappears resolves normally:
//
//	registered:<domain>  medium  it has MX: it can receive mail, which makes it
//	                             usable for business-email-compromise and phishing
//	                     low     it only resolves or only delegates (typically parked)
//
// The registered domain is not escalated when a certificate for it shows up in
// Certificate Transparency: the CT client deckard has queries crt.sh from the
// inventory expander, outside both the scope guard and Target.Intel, and
// giving checks a third network path was not worth one severity step.
//
// SERVFAIL, timeouts and every other lookup error mean "unknown": the run is
// partial and never reads them as "does not exist". A run that ran out of time
// before every candidate was checked is partial too. Partial runs raise and
// refresh findings but resolve nothing.
//
// Config under checks.domain.lookalike (invalid values fall back to the
// defaults and are noted in the observation):
//
//	enabled                  bool      false skips the check (default true)
//	zones                    []string  only these apexes are checked (default every owned apex)
//	exclude                  []string  names to ignore, and everything under them
//	tlds                     []string  suffixes for tld-swap (default about 25); [] disables it
//	max_candidates_per_zone  int       cap on names checked per apex (default 600)
//	max_findings_per_zone    int       cap on findings per apex (default 50)
//	min_label_length         int       shorter brand labels are not permuted (default 5)
//	rate_per_second          number    process-wide ceiling on queries (default 20)
//	interval                 duration  default 7d (set by the check, generic key)
package lookalike

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/check/domain/expiry"
	"github.com/chainseer-xyz/deckard/internal/dnsx"
	perm "github.com/chainseer-xyz/deckard/internal/lookalike"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "domain.lookalike"

// Defaults.
const (
	// DefaultInterval is the check's cadence: registrations appear slowly and
	// a sweep costs hundreds of queries.
	DefaultInterval = 7 * 24 * time.Hour
	// DefaultTimeout is the run deadline the engine applies (checks.<name>.timeout
	// overrides it): a sweep at the default rate takes about a minute alone and
	// longer when zones share the rate ceiling.
	DefaultTimeout = 30 * time.Minute

	DefaultMaxCandidates = 600
	DefaultMaxFindings   = 50
	DefaultRate          = 20.0

	maxMaxCandidates = 5000
	maxMaxFindings   = 500
	maxRate          = 1000.0
	workers          = 16
	listCap          = 10 // entries per answer list in evidence
	unknownSample    = 5
)

// Observation states.
const (
	StateOK          = "ok"
	StateSkipped     = "skipped"      // no lookup client: nothing was checked
	StateDisabled    = "disabled"     // enabled: false
	StateNotSelected = "not_selected" // zones is set and does not list this apex
	StateShortLabel  = "label_too_short"
	StateUnsupported = "unsupported_label" // an internationalised (xn--) brand label
)

// Check is the domain.lookalike check.
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
func (*Check) DefaultTimeout() time.Duration  { return DefaultTimeout }

// SlowLookups: a sweep sends up to DefaultMaxCandidates queries behind one
// process-wide rate ceiling (DefaultRate per second), so a run lasts at least
// half a minute and longer while zones share the ceiling. The queries are
// DNS-only, but the wait is the same as for a third-party service, so it runs
// in the intel queue.
func (*Check) SlowLookups() bool { return true }

// WantsOwnedZones: every owned zone's names are never lookalikes.
func (*Check) WantsOwnedZones() bool { return true }

// WantsOpenFindings: the open findings carry the first-seen time.
func (*Check) WantsOpenFindings() bool { return true }

// Applies matches owned zones that are registrable domains: lookalikes imitate
// the registered brand name, which a subzone shares with its apex.
func (*Check) Applies(a model.Asset) bool {
	if a.Kind != model.KindZone || a.Scope != model.ScopeOwned {
		return false
	}
	apex, ok := expiry.Registrable(a.Key)
	return ok && apex == checkutil.Norm(a.Key)
}

// options is the parsed checks.domain.lookalike configuration.
type options struct {
	enabled       bool
	zones         []string
	exclude       []string
	tlds          []string // nil: default list
	maxCandidates int
	maxFindings   int
	minLabel      int
	rate          float64
	notes         []string
}

func parseOptions(cfg map[string]any) options {
	o := options{
		enabled:       checkutil.Bool(cfg, "enabled", true),
		maxCandidates: checkutil.Int(cfg, "max_candidates_per_zone", DefaultMaxCandidates),
		maxFindings:   checkutil.Int(cfg, "max_findings_per_zone", DefaultMaxFindings),
		minLabel:      checkutil.Int(cfg, "min_label_length", perm.DefaultMinLabelLength),
		rate:          rateOf(cfg),
	}
	if o.maxCandidates < 1 || o.maxCandidates > maxMaxCandidates {
		o.notes = append(o.notes, fmt.Sprintf("max_candidates_per_zone must be 1..%d; using %d", maxMaxCandidates, DefaultMaxCandidates))
		o.maxCandidates = DefaultMaxCandidates
	}
	if o.maxFindings < 1 || o.maxFindings > maxMaxFindings {
		o.notes = append(o.notes, fmt.Sprintf("max_findings_per_zone must be 1..%d; using %d", maxMaxFindings, DefaultMaxFindings))
		o.maxFindings = DefaultMaxFindings
	}
	if o.minLabel < 1 || o.minLabel > 63 {
		o.notes = append(o.notes, fmt.Sprintf("min_label_length must be 1..63; using %d", perm.DefaultMinLabelLength))
		o.minLabel = perm.DefaultMinLabelLength
	}
	if v, present := cfg["rate_per_second"]; present {
		if f, ok := number(v); !ok || f <= 0 || f > maxRate {
			o.notes = append(o.notes, fmt.Sprintf("rate_per_second must be a number in (0, %g]; using %g", maxRate, DefaultRate))
		}
	}
	var bad []string
	o.zones, bad = names(cfg, "zones")
	o.notes = append(o.notes, invalidNames("zones", bad)...)
	o.exclude, bad = names(cfg, "exclude")
	o.notes = append(o.notes, invalidNames("exclude", bad)...)
	if _, present := cfg["tlds"]; present {
		o.tlds, bad = names(cfg, "tlds")
		if o.tlds == nil {
			o.tlds = []string{} // an explicit empty list disables tld-swap
		}
		o.notes = append(o.notes, invalidNames("tlds", bad)...)
	}
	return o
}

// names reads a list of DNS names, normalised and de-duplicated; entries that
// are not valid names are returned separately.
func names(cfg map[string]any, key string) (good, bad []string) {
	seen := map[string]bool{}
	for _, s := range checkutil.Strings(cfg, key, nil) {
		n := strings.TrimLeft(checkutil.Norm(strings.TrimPrefix(strings.TrimSpace(s), "*.")), ".")
		switch {
		case !perm.ValidName(n):
			bad = append(bad, s)
		case !seen[n]:
			seen[n] = true
			good = append(good, n)
		}
	}
	return good, bad
}

func invalidNames(key string, bad []string) []string {
	if len(bad) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%s: ignored invalid names %q", key, bad)}
}

// number reads a numeric config value.
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	}
	return 0, false
}

func rateOf(cfg map[string]any) float64 {
	if f, ok := number(cfg["rate_per_second"]); ok && f > 0 && f <= maxRate {
		return f
	}
	return DefaultRate
}

// RatePerSecond returns the configured process-wide query ceiling for the
// wiring code that builds the shared client, with the same fallback to the
// default the check applies.
func RatePerSecond(cfg map[string]any) float64 { return rateOf(cfg) }

// ---- run --------------------------------------------------------------------

// countingLookup counts the queries a run sends.
type countingLookup struct {
	check.Lookup
	n atomic.Int64
}

// Query counts the queries that were actually sent: one that never got a rate
// token is not.
func (c *countingLookup) Query(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	r, err := c.Lookup.Query(ctx, name, qtype)
	if !errors.Is(err, dnsx.ErrRateWait) {
		c.n.Add(1)
	}
	return r, err
}

// Run sweeps the apex's lookalikes.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	apex := checkutil.Norm(t.Asset.Key)
	o := parseOptions(cfg)
	obs := map[string]any{"domain": apex}
	if len(o.notes) > 0 {
		obs["config_notes"] = o.notes
	}
	res := &check.Result{}
	// done ends the run with one observation. partial says whether absence
	// proves nothing: it does not when the operator switched the check off or
	// away from this apex (findings then resolve), it does when deckard could
	// not look.
	done := func(state, note string, partial bool) (*check.Result, error) {
		obs["lookalike"] = state
		if note != "" {
			obs["lookalike_note"] = note
		}
		res.Observations = []model.ObservationInput{{Check: Name, Data: obs}}
		res.Partial = partial
		return res, nil
	}

	label, suffix, ok := split(apex)
	switch {
	case !ok:
		return done(StateSkipped, "not a registrable domain (a subzone or public suffix)", true)
	case !o.enabled:
		return done(StateDisabled, "checks.domain.lookalike.enabled is false", false)
	case len(o.zones) > 0 && !slices.Contains(o.zones, apex):
		return done(StateNotSelected, "this apex is not listed in checks.domain.lookalike.zones", false)
	case t.Lookup == nil:
		return done(StateSkipped, "no DNS lookup client for third-party names is available", true)
	case strings.HasPrefix(label, "xn--"):
		return done(StateUnsupported, "the brand label is internationalised (xn--); its permutations are not generated", false)
	case len(label) < o.minLabel:
		return done(StateShortLabel, fmt.Sprintf("the label %q is shorter than min_label_length (%d)", label, o.minLabel), false)
	}

	skip := append(slices.Clone(t.OwnedZones), apex)
	skip = append(skip, o.exclude...)
	all := perm.Generate(label, suffix, perm.Options{TLDs: o.tlds, MinLabelLength: o.minLabel, Skip: skip})
	cands := perm.Limit(all, o.maxCandidates)
	obs["candidates"] = len(all)
	obs["candidates_selected"] = len(cands)
	if dropped := len(all) - len(cands); dropped > 0 {
		obs["candidates_dropped_by_cap"] = dropped
	}

	lk := &countingLookup{Lookup: t.Lookup}
	budget, cancel := context.WithTimeout(ctx, budgetFor(ctx))
	defer cancel()
	sweep := runSweep(budget, lk, cands)

	obs["lookalike"] = StateOK
	obs["queries"] = int(lk.n.Load())
	obs["checked"] = sweep.checked
	obs["registered"] = len(sweep.found)
	obs["unknown"] = len(sweep.unknown)
	if len(sweep.unknown) > 0 {
		obs["unknown_sample"] = sweep.unknown[:min(unknownSample, len(sweep.unknown))]
	}
	unchecked := len(cands) - sweep.checked
	if unchecked > 0 {
		obs["unchecked"] = unchecked
		obs["budget_exhausted"] = true
		obs["lookalike_note"] = fmt.Sprintf("the time budget ran out with %d of %d candidates unchecked: absence proves nothing, nothing resolves", unchecked, len(cands))
	}
	res.Partial = unchecked > 0 || len(sweep.unknown) > 0

	first := firstSeen(t.OpenFindings)
	now := c.now().UTC().Format(time.RFC3339)
	var fs []model.FindingInput
	for _, r := range sweep.found {
		fs = append(fs, c.finding(apex, r, first, now))
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if ri, rj := fs[i].Severity.Rank(), fs[j].Severity.Rank(); ri != rj {
			return ri > rj
		}
		return fs[i].Key < fs[j].Key
	})
	if len(fs) > o.maxFindings {
		obs["findings_truncated"] = len(fs) - o.maxFindings
		obs["findings_truncated_note"] = fmt.Sprintf("%d registered lookalikes found; only the %d most severe are reported (max_findings_per_zone)", len(fs), o.maxFindings)
		fs = fs[:o.maxFindings]
	}
	res.Findings = fs
	res.Observations = []model.ObservationInput{{Check: Name, Data: obs}}
	return res, nil
}

// split returns apex's brand label and public suffix.
func split(apex string) (label, suffix string, ok bool) {
	reg, ok := expiry.Registrable(apex)
	if !ok || reg != apex {
		return "", "", false
	}
	label, suffix, _ = strings.Cut(apex, ".")
	return label, suffix, true
}

// budgetFor leaves the engine's deadline a tenth (at least a few seconds) to
// store the result: a check that returns after the engine's context ended has
// its result thrown away.
func budgetFor(ctx context.Context) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return DefaultTimeout
	}
	left := time.Until(dl)
	return max(left-max(left/10, 5*time.Second), left/2)
}

// firstSeen maps a lookalike domain to the first-seen time recorded in its
// open finding's evidence, so a refresh keeps it.
func firstSeen(open []check.OpenFinding) map[string]string {
	out := map[string]string{}
	for _, of := range open {
		d, _ := of.Evidence["domain"].(string)
		f, _ := of.Evidence["first_seen"].(string)
		if d != "" && f != "" {
			out[d] = f
		}
	}
	return out
}

// ---- sweep ------------------------------------------------------------------

// hit is a registered lookalike with its answers.
type hit struct {
	cand       perm.Candidate
	ns, a      []string
	aaaa, mx   []string
	cname      string
	hasMX      bool
	incomplete bool // a follow-up query was unknown: the answers may be partial
}

type sweepResult struct {
	found   []hit
	unknown []string // "<name>: <reason>"
	checked int
}

// runSweep probes every candidate with a small worker pool. The Lookup client
// enforces the query ceiling; the pool only keeps slow answers from serialising
// the run. A candidate is checked when its probe finished, whatever it found.
func runSweep(ctx context.Context, lk check.Lookup, cands []perm.Candidate) sweepResult {
	type outcome struct {
		hit     *hit
		unknown string
		checked bool
	}
	out := make([]outcome, len(cands))
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(workers, max(len(cands), 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if ctx.Err() != nil {
					continue
				}
				h, unknown, checked := probe(ctx, lk, cands[i])
				out[i] = outcome{hit: h, unknown: unknown, checked: checked}
			}
		}()
	}
	for i := range cands {
		next <- i
	}
	close(next)
	wg.Wait()

	var res sweepResult
	for i, o := range out {
		if o.checked {
			res.checked++
		}
		if o.unknown != "" {
			res.unknown = append(res.unknown, cands[i].Domain+": "+o.unknown)
		}
		if o.hit != nil {
			res.found = append(res.found, *o.hit)
		}
	}
	return res
}

// errUnchecked marks a lookup that never got an answer because the budget ran
// out or the rate wait failed.
var errUnchecked = errors.New("not asked")

// ask sends one query. state is StateUnknown for SERVFAIL and every error;
// err is errUnchecked when the budget ended (the candidate must not count as
// checked), and any other error is the reason of an unknown answer.
func ask(ctx context.Context, lk check.Lookup, name string, qtype uint16) (*dnsx.Response, error) {
	r, err := lk.Query(ctx, name, qtype)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, dnsx.ErrRateWait) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, errUnchecked
		}
		return nil, err
	}
	return r, nil
}

// probe classifies one candidate. checked is false when the budget ended
// before the classification was settled; unknown is set when the resolvers
// could not say.
//
// The NS query comes first: NXDOMAIN there means the name does not exist at
// all (RFC 8020), which settles almost every candidate in a single query. Any
// other answer is followed by A, AAAA and MX to learn what the name does.
func probe(ctx context.Context, lk check.Lookup, cand perm.Candidate) (h *hit, unknown string, checked bool) {
	r, err := ask(ctx, lk, cand.Domain, dns.TypeNS)
	if err != nil {
		return nil, reason(err), !errors.Is(err, errUnchecked) // an error that is not the budget is an answer: unknown
	}
	if r.State() == dnsx.StateUnknown {
		return nil, fmt.Sprintf("NS rcode %s", dns.RcodeToString[r.Rcode]), true
	}
	if r.State() == dnsx.StateNXDomain && len(r.Chain) == 0 {
		return nil, "", true // does not exist
	}
	found := &hit{cand: cand}
	if r.State() == dnsx.StateResolved {
		for _, rr := range r.Records(dns.TypeNS) {
			found.ns = append(found.ns, dnsx.Norm(rr.(*dns.NS).Ns))
		}
	}
	noteAlias(found, r)

	checked = true
	for _, q := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX} {
		r, err := ask(ctx, lk, cand.Domain, q)
		if err != nil {
			found.incomplete = true
			if errors.Is(err, errUnchecked) {
				// The budget ended mid-probe: report what is known, but the
				// candidate is not fully checked.
				checked = false
				break
			}
			unknown = joinReason(unknown, dns.TypeToString[q]+": "+reason(err))
			continue
		}
		if r.State() == dnsx.StateUnknown {
			found.incomplete = true
			unknown = joinReason(unknown, fmt.Sprintf("%s rcode %s", dns.TypeToString[q], dns.RcodeToString[r.Rcode]))
			continue
		}
		noteAlias(found, r)
		for _, rr := range r.Records(q) {
			switch v := rr.(type) {
			case *dns.A:
				found.a = append(found.a, addr(v.A.String()))
			case *dns.AAAA:
				found.aaaa = append(found.aaaa, addr(v.AAAA.String()))
			case *dns.MX:
				// A null MX (RFC 7505) says the domain accepts no mail.
				if t := dnsx.Norm(v.Mx); t != "" {
					found.mx = append(found.mx, fmt.Sprintf("%d %s", v.Preference, t))
					found.hasMX = true
				}
			}
		}
	}
	sortUnique(&found.ns)
	sortUnique(&found.a)
	sortUnique(&found.aaaa)
	sortUnique(&found.mx)
	registered := len(found.ns) > 0 || len(found.a) > 0 || len(found.aaaa) > 0 || found.hasMX || found.cname != ""
	if !registered {
		found = nil // exists without data of its own (an empty non-terminal)
	}
	return found, unknown, checked
}

func noteAlias(h *hit, r *dnsx.Response) {
	if len(r.Chain) > 0 && h.cname == "" {
		h.cname = r.Final
	}
}

func addr(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String()
	}
	return s
}

func reason(err error) string {
	if errors.Is(err, errUnchecked) {
		return ""
	}
	return err.Error()
}

func joinReason(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func sortUnique(s *[]string) {
	slices.Sort(*s)
	*s = slices.Compact(*s)
}

// ---- findings ---------------------------------------------------------------

func (c *Check) finding(apex string, h hit, first map[string]string, now string) model.FindingInput {
	d := h.cand.Domain
	ev := map[string]any{
		"domain":     d,
		"zone":       apex,
		"technique":  string(h.cand.Technique),
		"first_seen": now,
	}
	if f, ok := first[d]; ok {
		ev["first_seen"] = f
	}
	if u, err := idna.Lookup.ToUnicode(d); err == nil && u != d {
		ev["unicode"] = u
	}
	for k, v := range map[string][]string{"ns": h.ns, "a": h.a, "aaaa": h.aaaa, "mx": h.mx} {
		if len(v) > 0 {
			ev[k] = v[:min(listCap, len(v))]
		}
	}
	if h.cname != "" {
		ev["cname"] = h.cname
	}
	if h.incomplete {
		ev["incomplete"] = true
	}

	sev := model.SeverityLow
	state := "resolves or delegates"
	switch {
	case h.hasMX:
		sev, state = model.SeverityMedium, "has MX records and can receive mail"
	case len(h.a)+len(h.aaaa) == 0 && h.cname == "":
		state = "delegates to nameservers but has no address (typically parked)"
	}
	title := fmt.Sprintf("Lookalike domain %s is registered", d)
	if h.hasMX {
		title = fmt.Sprintf("Lookalike domain %s is registered and can receive mail", d)
	}
	desc := fmt.Sprintf("%s looks like %s (%s) and is registered by someone else: it %s. "+
		"Lookalike domains are used for phishing, credential harvesting and brand abuse against your staff, customers and partners. "+
		"deckard only read its DNS records; it never connected to the domain.",
		d, apex, h.cand.Technique, state)
	if h.hasMX {
		desc += " Because it has MX records it can send and receive mail, which makes it usable for business e-mail compromise."
	}
	return model.FindingInput{
		Check: Name, Key: "registered:" + d, Severity: sev, Title: title, Description: desc,
		Remediation: remediation(apex, h.hasMX), Evidence: ev,
		Tags: []string{"domain", "lookalike", "phishing", string(h.cand.Technique)},
	}
}

func remediation(apex string, mail bool) string {
	s := "Find out who registered it (RDAP/WHOIS) and what it is used for, without visiting it from a work machine: use a URL scanner or an isolated browser. " +
		"If it belongs to you or a partner, add it to the inventory or to checks.domain.lookalike.exclude. " +
		"If it does not, report it to the registrar's abuse contact (and to the hosting provider and browser safe-browsing if it serves a phishing page), " +
		"consider a UDRP or URS complaint when it infringes your trademark, and block it at the mail gateway and web proxy."
	if mail {
		s += " Publish a DMARC policy of p=reject for " + apex + " so mail spoofing your own domain is refused, and warn staff and finance teams about invoices or requests from the lookalike."
	}
	return s
}
