package expiry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/intel"
	"github.com/chainseer-xyz/deckard/internal/model"
)

var now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// fakeIntel scripts RDAPBase and Get. Unscripted URLs answer ErrNotFound.
type fakeIntel struct {
	mu      sync.Mutex
	bases   map[string]string // tld -> base
	baseErr error
	bodies  map[string]string // url -> body
	errs    map[string]error  // url -> error
	calls   []string
}

func newFakeIntel() *fakeIntel {
	return &fakeIntel{
		bases:  map[string]string{"com": "https://rdap.example.net/com/v1/", "eu": "https://rdap.example.eu/", "org": "https://rdap.example.org/"},
		bodies: map[string]string{}, errs: map[string]error{},
	}
}

func (f *fakeIntel) RDAPBase(_ context.Context, domain string) (string, error) {
	if f.baseErr != nil {
		return "", f.baseErr
	}
	base, ok := f.bases[domain[strings.LastIndexByte(domain, '.')+1:]]
	if !ok {
		return "", intel.ErrUnsupported
	}
	return base, nil
}

func (f *fakeIntel) Get(_ context.Context, service, u string) (intel.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, service+" "+u)
	f.mu.Unlock()
	if service != intel.ServiceRDAP {
		return intel.Response{}, intel.ErrBlocked
	}
	if err := f.errs[u]; err != nil {
		return intel.Response{}, err
	}
	b, ok := f.bodies[u]
	if !ok {
		return intel.Response{Status: 404}, intel.ErrNotFound
	}
	return intel.Response{Status: 200, Body: []byte(b)}, nil
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// verisignStyle renders a .com-shaped answer.
func verisignStyle(name string, expires time.Time, registrar string, statuses, ns []string) string {
	type nsT struct {
		LDHName string `json:"ldhName"`
	}
	nss := make([]nsT, 0, len(ns))
	for _, n := range ns {
		nss = append(nss, nsT{n})
	}
	doc := map[string]any{
		"objectClassName": "domain", "ldhName": strings.ToUpper(name), "status": statuses, "nameservers": nss,
		"entities": []any{map[string]any{"roles": []string{"registrar"},
			"vcardArray": []any{"vcard", []any{[]any{"version", map[string]any{}, "text", "4.0"}, []any{"fn", map[string]any{}, "text", registrar}}}}},
		"events": []any{
			map[string]any{"eventAction": "registration", "eventDate": "2001-02-03T04:05:06Z"},
			map[string]any{"eventAction": "expiration", "eventDate": expires.Format(time.RFC3339)},
			map[string]any{"eventAction": "last changed", "eventDate": "2026-01-02T03:04:05Z"},
		},
	}
	b, _ := json.Marshal(doc)
	return string(b)
}

var locked = []string{"client delete prohibited", "client transfer prohibited", "client update prohibited"}
var defaultNS = []string{"ns1.dns.example.net", "ns2.dns.example.net"}

func zone(key string) model.Asset {
	return model.Asset{ID: 1, Kind: model.KindZone, Key: key, Scope: model.ScopeOwned}
}

type run struct {
	res  *check.Result
	keys map[string]model.Severity
	obs  map[string]any
}

func runCheck(t *testing.T, key string, fi check.Intel, cfg map[string]any, opts ...checktest.Option) run {
	t.Helper()
	c := New(nil)
	c.now = func() time.Time { return now }
	opts = append([]checktest.Option{checktest.WithConfig(cfg)}, opts...)
	if fi != nil {
		opts = append(opts, checktest.WithIntel(fi))
	}
	res, err := c.Run(context.Background(), checktest.NewTarget(zone(key), opts...))
	if err != nil {
		t.Fatalf("Run returned an error (lookup problems must never be errors): %v", err)
	}
	r := run{res: res, keys: map[string]model.Severity{}}
	for _, f := range res.Findings {
		if f.Check != Name {
			t.Errorf("finding %s has check %q", f.Key, f.Check)
		}
		r.keys[f.Key] = f.Severity
	}
	if len(res.Observations) != 1 || res.Observations[0].Check != Name {
		t.Fatalf("observations = %+v", res.Observations)
	}
	r.obs = res.Observations[0].Data
	return r
}

func TestCheckBasics(t *testing.T) {
	c := New(nil)
	if c.Name() != "domain.expiry" || c.Tier() != model.TierPassive || c.DefaultInterval() != 12*time.Hour {
		t.Fatal("identity")
	}
	var _ check.DefaultIntervaler = c
}

func TestRegistrableAndApplies(t *testing.T) {
	for name, want := range map[string]string{
		"example.com":           "example.com",
		"Example.COM.":          "example.com",
		"corp.example.com":      "example.com",
		"example.co.uk":         "example.co.uk",
		"shop.example.co.uk":    "example.co.uk",
		"user.github.io":        "github.io", // private suffix walked past: the ICANN registration is github.io
		"xn--bcher-kva.example": "",
		"com":                   "",
		"co.uk":                 "",
		"example.internal":      "",
		"":                      "",
		"exa_mple.com":          "",
		"-bad.com":              "",
	} {
		got, ok := Registrable(name)
		if got != want || ok != (want != "") {
			t.Errorf("Registrable(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	c := New(nil)
	for _, tc := range []struct {
		a    model.Asset
		want bool
	}{
		{zone("example.com"), true},
		{zone("example.co.uk"), true},
		{zone("corp.example.com"), false}, // subzone: the registration lives at the apex
		{zone("co.uk"), false},            // public suffix
		{zone("example.internal"), false}, // no ICANN suffix, no registry
		{model.Asset{Kind: model.KindHostname, Key: "example.com", Scope: model.ScopeOwned}, false},
		{model.Asset{Kind: model.KindZone, Key: "example.com", Scope: model.ScopeExternal}, false},
	} {
		if got := c.Applies(tc.a); got != tc.want {
			t.Errorf("Applies(%s %s %s) = %v", tc.a.Kind, tc.a.Key, tc.a.Scope, got)
		}
	}
}

func TestRegistryFixtures(t *testing.T) {
	cases := []struct {
		zone, url, file string
		want            map[string]model.Severity
		registrar       string
		expires         string
		ns              []string
	}{
		{"example.com", "https://rdap.example.net/com/v1/domain/example.com", "verisign_example_com.json",
			map[string]model.Severity{}, "Example Registrar, Inc.", "2027-08-13T04:00:00Z",
			[]string{"a.iana-servers.net", "b.iana-servers.net"}},
		{"example.eu", "https://rdap.example.eu/domain/example.eu", "cctld_example_eu.json",
			map[string]model.Severity{}, "Example Domains SA", "2027-04-30T00:00:00Z",
			[]string{"ns1.dns.example.net", "ns2.dns.example.net"}},
		{"example.org", "https://rdap.example.org/domain/example.org", "noevents_example_org.json",
			map[string]model.Severity{"transfer-unlocked": model.SeverityMedium, "no-delete-protection": model.SeverityInfo},
			"9999", "", []string{"ns.example.org"}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			fi := newFakeIntel()
			fi.bodies[tc.url] = fixture(t, tc.file)
			r := runCheck(t, tc.zone, fi, nil)
			if r.res.Partial {
				t.Error("successful lookup marked partial")
			}
			if !maps(r.keys, tc.want) {
				t.Errorf("findings = %v, want %v", r.keys, tc.want)
			}
			if r.obs["rdap"] != StateOK || r.obs["registrar"] != tc.registrar || !slices.Equal(r.obs["nameservers"].([]string), tc.ns) {
				t.Errorf("observation = %v", r.obs)
			}
			if got, _ := r.obs["expires"].(string); got != tc.expires {
				t.Errorf("expires = %q, want %q", got, tc.expires)
			}
			if _, has := r.obs["last_changed"]; has {
				t.Error("last_changed must stay out of the baselined observation")
			}
		})
	}
}

func maps(a, b map[string]model.Severity) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range b {
		if a[k] != v {
			return false
		}
	}
	return true
}

func TestExpiryThresholds(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		name     string
		expires  time.Time
		statuses []string
		cfg      map[string]any
		key      string
		sev      model.Severity
	}{
		{"61 days", now.Add(61 * day), locked, nil, "", ""},
		{"60 days", now.Add(60 * day), locked, nil, "expiring", model.SeverityLow},
		{"31 days", now.Add(31 * day), locked, nil, "expiring", model.SeverityLow},
		{"30 days", now.Add(30 * day), locked, nil, "expiring", model.SeverityMedium},
		{"15 days", now.Add(15 * day), locked, nil, "expiring", model.SeverityMedium},
		{"14 days", now.Add(14 * day), locked, nil, "expiring", model.SeverityHigh},
		{"14 days and a bit", now.Add(14*day + time.Hour), locked, nil, "expiring", model.SeverityHigh},
		{"an hour", now.Add(time.Hour), locked, nil, "expiring", model.SeverityHigh},
		{"exactly now", now, locked, nil, "expired", model.SeverityCritical},
		{"yesterday", now.Add(-day), locked, nil, "expired", model.SeverityCritical},
		{"redemption period", now.Add(300 * day), append([]string{"redemption period"}, locked...), nil, "expired", model.SeverityCritical},
		{"pending delete", now.Add(-40 * day), append([]string{"pendingDelete"}, locked...), nil, "expired", model.SeverityCritical},
		{"custom high", now.Add(10 * day), locked, map[string]any{"high_days": 7, "medium_days": 21, "low_days": 90}, "expiring", model.SeverityMedium},
		{"custom low", now.Add(80 * day), locked, map[string]any{"high_days": 7, "medium_days": 21, "low_days": 90}, "expiring", model.SeverityLow},
		{"invalid falls back", now.Add(10 * day), locked, map[string]any{"high_days": 40, "medium_days": 20}, "expiring", model.SeverityHigh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fi := newFakeIntel()
			fi.bodies["https://rdap.example.net/com/v1/domain/example.com"] = verisignStyle("example.com", tc.expires, "Example Registrar, Inc.", tc.statuses, defaultNS)
			r := runCheck(t, "example.com", fi, tc.cfg)
			want := map[string]model.Severity{}
			if tc.key != "" {
				want[tc.key] = tc.sev
			}
			if !maps(r.keys, want) {
				t.Fatalf("findings = %v, want %v", r.keys, want)
			}
			for _, f := range r.res.Findings {
				ev := f.Evidence
				if ev["expires"] != tc.expires.Format(time.RFC3339) || ev["registrar"] != "Example Registrar, Inc." ||
					ev["days_remaining"] == nil || ev["nameservers"] == nil || ev["statuses"] == nil {
					t.Errorf("evidence = %v", ev)
				}
				if !strings.Contains(f.Remediation, "enable auto-renew") {
					t.Errorf("remediation = %q", f.Remediation)
				}
			}
			if _, bad := tc.cfg["high_days"]; bad && tc.name == "invalid falls back" && r.obs["thresholds_note"] == nil {
				t.Error("invalid thresholds not noted")
			}
		})
	}
}

func TestLockFindings(t *testing.T) {
	far := now.Add(400 * 24 * time.Hour)
	cases := []struct {
		name     string
		statuses []string
		cfg      map[string]any
		want     map[string]model.Severity
	}{
		{"fully locked", locked, nil, map[string]model.Severity{}},
		{"registry lock only", []string{"server transfer prohibited", "server delete prohibited"}, nil, map[string]model.Severity{}},
		{"active only", []string{"active"}, nil, map[string]model.Severity{"transfer-unlocked": model.SeverityMedium, "no-delete-protection": model.SeverityInfo}},
		{"transfer only", []string{"clientTransferProhibited"}, nil, map[string]model.Severity{"no-delete-protection": model.SeverityInfo}},
		{"delete only", []string{"client delete prohibited"}, nil, map[string]model.Severity{"transfer-unlocked": model.SeverityMedium}},
		{"no statuses published", nil, nil, map[string]model.Severity{}},
		{"exempt tld", []string{"active"}, map[string]any{"lock_exempt_tlds": []any{".COM"}}, map[string]model.Severity{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fi := newFakeIntel()
			fi.bodies["https://rdap.example.net/com/v1/domain/example.com"] = verisignStyle("example.com", far, "R", tc.statuses, defaultNS)
			r := runCheck(t, "example.com", fi, tc.cfg)
			if !maps(r.keys, tc.want) {
				t.Errorf("findings = %v, want %v", r.keys, tc.want)
			}
			if tc.statuses == nil && r.obs["locks_note"] == nil {
				t.Error("missing status list not noted")
			}
			for _, f := range r.res.Findings {
				if f.Key == "transfer-unlocked" && !strings.Contains(f.Remediation, "registrar lock") {
					t.Errorf("remediation = %q", f.Remediation)
				}
			}
		})
	}
}

func TestLookupFailuresArePartialObservations(t *testing.T) {
	const u = "https://rdap.example.net/com/v1/domain/example.com"
	cases := []struct {
		name  string
		setup func(*fakeIntel)
		state string
	}{
		{"unsupported tld", func(f *fakeIntel) { delete(f.bases, "com") }, StateUnsupported},
		{"not found", func(*fakeIntel) {}, StateNotFound},
		{"bootstrap unavailable", func(f *fakeIntel) { f.baseErr = fmt.Errorf("%w: boom", intel.ErrUnavailable) }, StateUnavailable},
		{"upstream unavailable", func(f *fakeIntel) { f.errs[u] = fmt.Errorf("%w: http 503", intel.ErrUnavailable) }, StateUnavailable},
		{"rate limited", func(f *fakeIntel) { f.errs[u] = intel.ErrRateLimited }, StateUnavailable},
		{"blocked", func(f *fakeIntel) { f.errs[u] = intel.ErrBlocked }, StateUnavailable},
		{"invalid json", func(f *fakeIntel) { f.bodies[u] = `{"ldhName":` }, StateUnavailable},
		{"other domain", func(f *fakeIntel) {
			f.bodies[u] = verisignStyle("example.net", now, "R", locked, defaultNS)
		}, StateUnavailable},
		{"intel disabled", func(f *fakeIntel) { f.baseErr = intel.ErrDisabled }, StateSkipped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fi := newFakeIntel()
			tc.setup(fi)
			r := runCheck(t, "example.com", fi, nil)
			if !r.res.Partial || len(r.res.Findings) != 0 {
				t.Errorf("partial = %v findings = %v", r.res.Partial, r.keys)
			}
			if r.obs["rdap"] != tc.state || r.obs["rdap_note"] == "" {
				t.Errorf("observation = %v", r.obs)
			}
		})
	}
	t.Run("no intel client", func(t *testing.T) {
		r := runCheck(t, "example.com", nil, nil)
		if !r.res.Partial || len(r.res.Findings) != 0 || r.obs["rdap"] != StateSkipped {
			t.Errorf("%+v %v", r.res, r.obs)
		}
	})
}

func TestApexQueriedOnceAndSubzonesSkipped(t *testing.T) {
	fi := newFakeIntel()
	fi.bodies["https://rdap.example.net/com/v1/domain/example.com"] = fixture(t, "verisign_example_com.json")
	for _, key := range []string{"example.com", "EXAMPLE.com."} {
		runCheck(t, key, fi, nil)
	}
	// Both spellings of the apex produce one canonical URL, which the intel
	// client's cache and single-flight serve with a single registry query.
	if len(fi.calls) != 2 || fi.calls[0] != fi.calls[1] || fi.calls[0] != "rdap https://rdap.example.net/com/v1/domain/example.com" {
		t.Errorf("calls = %v", fi.calls)
	}
	r := runCheck(t, "corp.example.com", fi, nil)
	if len(fi.calls) != 2 || !r.res.Partial || r.obs["rdap"] != StateSkipped {
		t.Errorf("subzone queried: calls = %v obs = %v", fi.calls, r.obs)
	}
}

func TestBaselineDrift(t *testing.T) {
	far := now.Add(400 * 24 * time.Hour)
	// The store hands the baseline back JSON-normalised.
	baseline := func(registrar string, ns ...string) map[string]map[string]any {
		raw, _ := json.Marshal(map[string]any{"rdap": "ok", "domain": "example.com", "registrar": registrar, "nameservers": ns})
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return map[string]map[string]any{Name: m}
	}
	cases := []struct {
		name      string
		base      map[string]map[string]any
		registrar string
		ns        []string
		want      []string
	}{
		{"no baseline yet", nil, "New Registrar", defaultNS, nil},
		{"unchanged", baseline("Example Registrar, Inc.", defaultNS...), "Example Registrar, Inc.", defaultNS, nil},
		{"registrar case only", baseline("EXAMPLE REGISTRAR, INC.", defaultNS...), "Example Registrar, Inc.", defaultNS, nil},
		{"nameserver order only", baseline("R", "NS2.dns.example.net.", "ns1.dns.example.net"), "R", defaultNS, nil},
		{"registrar changed", baseline("Old Registrar", defaultNS...), "New Registrar", defaultNS, []string{"drift/registrar"}},
		{"nameserver swapped", baseline("R", "ns1.dns.example.net", "ns.attacker.example"), "R", defaultNS, []string{"drift/nameservers"}},
		{"both", baseline("Old", "ns.other.example"), "New", defaultNS, []string{"drift/nameservers", "drift/registrar"}},
		{"baseline from a skipped run", map[string]map[string]any{Name: {"rdap": "unavailable", "registrar": "Old"}}, "New", defaultNS, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fi := newFakeIntel()
			fi.bodies["https://rdap.example.net/com/v1/domain/example.com"] = verisignStyle("example.com", far, tc.registrar, locked, tc.ns)
			c := New(nil)
			c.now = func() time.Time { return now }
			tg := checktest.NewTarget(zone("example.com"), checktest.WithIntel(fi))
			tg.Baseline = tc.base
			res, err := c.Run(context.Background(), tg)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range res.Findings {
				if f.Severity != model.SeverityHigh || !slices.Contains(f.Tags, "drift") || f.Evidence["old"] == nil || f.Evidence["new"] == nil {
					t.Errorf("drift finding %+v", f)
				}
				got = append(got, f.Key)
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("findings = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLiveNameserversCompared(t *testing.T) {
	far := now.Add(400 * 24 * time.Hour)
	for _, tc := range []struct {
		live []string
		want any
	}{
		{[]string{"NS2.dns.example.net.", "ns1.dns.example.net."}, true},
		{[]string{"ns1.other.example."}, false},
		{nil, nil}, // NS lookup failed: nothing recorded
	} {
		fi := newFakeIntel()
		fi.bodies["https://rdap.example.net/com/v1/domain/example.com"] = verisignStyle("example.com", far, "R", locked, defaultNS)
		res := &checktest.Resolver{NSs: map[string][]string{}}
		if tc.live != nil {
			res.NSs["example.com"] = tc.live
		}
		r := runCheck(t, "example.com", fi, nil, checktest.WithResolver(res))
		if r.obs["live_nameservers_match"] != tc.want {
			t.Errorf("live %v: match = %v", tc.live, r.obs["live_nameservers_match"])
		}
	}
}

func TestIntelErrorsAreNotFindings(t *testing.T) {
	// Every sentinel the client can return maps to an observation state.
	for _, err := range []error{intel.ErrDisabled, intel.ErrBlocked, intel.ErrNotFound, intel.ErrRateLimited,
		intel.ErrUnavailable, intel.ErrTooLarge, intel.ErrUnsupported, errors.New("other")} {
		if state, note := classify(err); state == StateOK || state == "" || note == "" {
			t.Errorf("classify(%v) = %q %q", err, state, note)
		}
	}
}
