package history

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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

// fakeIntel answers every wayback request with one scripted body or error.
type fakeIntel struct {
	mu    sync.Mutex
	body  string
	err   error
	calls []string
}

func (f *fakeIntel) Get(_ context.Context, service, u string) (intel.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, service+" "+u)
	f.mu.Unlock()
	if service != intel.ServiceWayback {
		return intel.Response{}, intel.ErrBlocked
	}
	if f.err != nil {
		return intel.Response{}, f.err
	}
	return intel.Response{Status: 200, Body: []byte(f.body)}, nil
}

func (*fakeIntel) RDAPBase(context.Context, string) (string, error) { return "", intel.ErrUnsupported }

// row is one CDX row: original URL, mimetype, 14-digit timestamp.
type row struct{ url, mime, ts string }

func cdx(rows ...row) string {
	out := [][]string{{"original", "statuscode", "timestamp", "mimetype"}}
	for _, r := range rows {
		if r.mime == "" {
			r.mime = "application/octet-stream"
		}
		if r.ts == "" {
			r.ts = "20200315101500"
		}
		out = append(out, []string{r.url, "200", r.ts, r.mime})
	}
	b, _ := json.Marshal(out)
	return string(b)
}

const host = "www.example.com"

func u(p string) string { return "https://" + host + p }

type outcome struct {
	res  *check.Result
	keys map[string]model.FindingInput
	obs  map[string]any
}

func run(t *testing.T, f *fakeIntel, cfg map[string]any) outcome {
	t.Helper()
	opts := []checktest.Option{checktest.WithConfig(cfg)}
	if f != nil {
		opts = append(opts, checktest.WithIntel(f))
	}
	return runTarget(t, checktest.NewTarget(checktest.Hostname(host, "example.com"), opts...))
}

func runTarget(t *testing.T, tg check.Target) outcome {
	t.Helper()
	c := New(nil)
	c.now = func() time.Time { return now }
	res, err := c.Run(context.Background(), tg)
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}
	o := outcome{res: res, keys: map[string]model.FindingInput{}}
	for _, f := range res.Findings {
		if _, dup := o.keys[f.Key]; dup {
			t.Errorf("duplicate finding key %q", f.Key)
		}
		o.keys[f.Key] = f
	}
	if len(res.Observations) != 1 {
		t.Fatalf("want one observation, got %d", len(res.Observations))
	}
	o.obs = res.Observations[0].Data
	return o
}

func TestAppliesOwnedHostnamesOnly(t *testing.T) {
	c := New(nil)
	for _, tc := range []struct {
		a    model.Asset
		want bool
	}{
		{model.Asset{Kind: model.KindHostname, Key: host, Scope: model.ScopeOwned}, true},
		{model.Asset{Kind: model.KindHostname, Key: host, Scope: model.ScopeExternal}, false},
		{model.Asset{Kind: model.KindIP, Key: "203.0.113.7", Scope: model.ScopeOwned}, false},
		{model.Asset{Kind: model.KindZone, Key: "example.com", Scope: model.ScopeOwned}, false},
		{model.Asset{Kind: model.KindURL, Key: "https://www.example.com/", Scope: model.ScopeOwned}, false},
	} {
		if got := c.Applies(tc.a); got != tc.want {
			t.Errorf("Applies(%s %s %s) = %v", tc.a.Kind, tc.a.Key, tc.a.Scope, got)
		}
	}
	if c.Name() != Name || c.Tier() != model.TierPassive || c.DefaultInterval() != 7*24*time.Hour {
		t.Errorf("metadata: %s %s %s", c.Name(), c.Tier(), c.DefaultInterval())
	}
}

func TestRequestShape(t *testing.T) {
	f := &fakeIntel{body: cdx()}
	run(t, f, map[string]any{"max_results": 500})
	if len(f.calls) != 1 {
		t.Fatalf("calls = %v", f.calls)
	}
	service, raw, _ := strings.Cut(f.calls[0], " ")
	if service != intel.ServiceWayback {
		t.Errorf("service = %s", service)
	}
	pu, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pu.Scheme != "https" || pu.Host != "web.archive.org" || pu.Path != "/cdx/search/cdx" {
		t.Errorf("url = %s", raw)
	}
	q := pu.Query()
	want := map[string]string{"url": host + "/*", "output": "json", "fl": "original,statuscode,timestamp,mimetype",
		"filter": "statuscode:200", "collapse": "urlkey", "limit": "500"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
}

// Every class and severity, one path each.
func TestFindingPaths(t *testing.T) {
	cases := []struct {
		path  string
		key   string
		class string
		sev   model.Severity
	}{
		{"/.env", "path:/.env", ClassSecrets, model.SeverityHigh},
		{"/app/.env.production", "path:/app/.env.production", ClassSecrets, model.SeverityHigh},
		{"/.git/config", "path:/.git", ClassSecrets, model.SeverityHigh},
		{"/.svn/entries", "path:/.svn", ClassSecrets, model.SeverityHigh},
		{"/.hg/store/data", "path:/.hg", ClassSecrets, model.SeverityHigh},
		{"/backup/id_rsa", "path:/backup/id_rsa", ClassSecrets, model.SeverityHigh},
		{"/ssl/server.key", "path:/ssl/server.key", ClassSecrets, model.SeverityHigh},
		{"/certs/site.pem", "path:/certs/site.pem", ClassSecrets, model.SeverityHigh},
		{"/.aws/credentials", "path:/.aws/credentials", ClassSecrets, model.SeverityHigh},
		{"/terraform.tfstate", "path:/terraform.tfstate", ClassSecrets, model.SeverityHigh},
		{"/.npmrc", "path:/.npmrc", ClassSecrets, model.SeverityHigh},
		{"/wp-config.php.bak", "path:/wp-config.php.bak", ClassSecrets, model.SeverityHigh},
		{"/inc/config.php.bak", "path:/inc/config.php.bak", ClassSecrets, model.SeverityHigh},
		{"/dump.sql", "path:/dump.sql", ClassDump, model.SeverityHigh},
		{"/db/prod.sql.gz", "path:/db/prod.sql.gz", ClassDump, model.SeverityHigh},
		{"/export.dump", "path:/export.dump", ClassDump, model.SeverityHigh},
		{"/index.php.bak", "path:/index.php.bak", ClassDump, model.SeverityHigh},
		{"/index.php.old", "path:/index.php.old", ClassDump, model.SeverityHigh},
		{"/site-backup-2019.zip", "path:/site-backup-2019.zip", ClassDump, model.SeverityHigh},
		{"/www.tar.gz", "path:/www.tar.gz", ClassDump, model.SeverityHigh},
		{"/db.7z", "path:/db.7z", ClassDump, model.SeverityHigh},
		{"/phpmyadmin/index.php", "path:/phpmyadmin", ClassAdmin, model.SeverityMedium},
		{"/adminer.php", "path:/adminer", ClassAdmin, model.SeverityMedium},
		{"/admin/login", "path:/admin", ClassAdmin, model.SeverityMedium},
		{"/actuator/env", "path:/actuator", ClassAdmin, model.SeverityMedium},
		{"/server-status", "path:/server-status", ClassAdmin, model.SeverityMedium},
		{"/debug/pprof/heap", "path:/debug", ClassAdmin, model.SeverityMedium},
		{"/_profiler/latest", "path:/_profiler", ClassAdmin, model.SeverityMedium},
		{"/telescope/requests", "path:/telescope", ClassAdmin, model.SeverityMedium},
		{"/horizon/dashboard", "path:/horizon", ClassAdmin, model.SeverityMedium},
		{"/graphiql", "path:/graphiql", ClassAdmin, model.SeverityMedium},
		{"/swagger-ui/index.html", "path:/swagger-ui", ClassAdmin, model.SeverityMedium},
		{"/swagger.json", "path:/swagger.json", ClassAdmin, model.SeverityMedium},
		{"/openapi.json", "path:/openapi.json", ClassAdmin, model.SeverityMedium},
		{"/v2/api-docs", "path:/v2/api-docs", ClassAdmin, model.SeverityMedium},
		{"/api-docs", "path:/api-docs", ClassAdmin, model.SeverityMedium},
		{"/.DS_Store", "path:/.ds_store", ClassMisc, model.SeverityLow},
		{"/web.config", "path:/web.config", ClassMisc, model.SeverityLow},
	}
	var rows []row
	for _, c := range cases {
		rows = append(rows, row{url: u(c.path)})
	}
	rows = append(rows, row{url: u("/index.html"), mime: "text/html"}, row{url: u("/css/site.css"), mime: "text/css"})
	o := run(t, &fakeIntel{body: cdx(rows...)}, map[string]any{"max_findings": 50})
	for _, c := range cases {
		f, ok := o.keys[c.key]
		if !ok {
			t.Errorf("%s: no finding with key %s (have %d)", c.path, c.key, len(o.keys))
			continue
		}
		if f.Severity != c.sev || f.Evidence["class"] != c.class || f.Check != Name {
			t.Errorf("%s: severity %s class %v", c.path, f.Severity, f.Evidence["class"])
		}
		if f.Remediation == "" || f.Title == "" || f.Description == "" {
			t.Errorf("%s: empty text", c.path)
		}
	}
	if len(o.keys) != len(cases) {
		t.Errorf("findings = %d, want %d", len(o.keys), len(cases))
	}
	if o.res.Partial {
		t.Error("a complete history must not be partial")
	}
	if o.obs["wayback"] != StateOK {
		t.Errorf("obs = %v", o.obs)
	}
}

func TestNonMatchingPaths(t *testing.T) {
	var rows []row
	for _, p := range []string{
		"/", "/index.html", "/.gitignore", "/.github/workflows/ci.yml", "/blog/admin-guide", "/feedback.zip",
		"/wp-config.php", "/wp-config-sample.php", "/.envrc", "/environment.js", "/id_rsa.pub", "/administrator/",
		"/blog/phpmyadmin", "/news/telescope-review", "/bak", "/old", "/site.zip.html", "/img/key.png", "/robots.txt",
	} {
		rows = append(rows, row{url: u(p)})
	}
	o := run(t, &fakeIntel{body: cdx(rows...)}, nil)
	if len(o.res.Findings) != 0 {
		for _, f := range o.res.Findings {
			t.Errorf("unexpected finding %s", f.Key)
		}
	}
	if o.res.Partial {
		t.Error("clean complete history must not be partial")
	}
}

func TestGroupingEvidenceAndNoQueryStrings(t *testing.T) {
	b := cdx(
		row{url: "http://" + host + ":80/.git/HEAD?token=secret", ts: "20180101000000"},
		row{url: "https://" + host + "/.git/config?x=1#frag", ts: "20210606123000"},
		row{url: "https://" + host + "/.git/index", ts: "20190101000000"},
		row{url: "https://" + host + "/.GIT/refs/heads/main", ts: "20190101000000"},
	)
	o := run(t, &fakeIntel{body: b}, nil)
	f, ok := o.keys["path:/.git"]
	if !ok || len(o.keys) != 1 {
		t.Fatalf("want exactly one grouped finding, got %v", o.keys)
	}
	urls := f.Evidence["urls"].([]string)
	if len(urls) != 4 {
		t.Fatalf("urls = %v", urls)
	}
	if urls[0] != "https://"+host+"/.git/config" {
		t.Errorf("newest URL first, got %v", urls)
	}
	for _, s := range urls {
		if strings.ContainsAny(s, "?#") {
			t.Errorf("url %q carries a query string or fragment", s)
		}
	}
	if f.Evidence["captured_at"] != "2021-06-06T12:30:00Z" || f.Evidence["status"] != 200 {
		t.Errorf("evidence = %v", f.Evidence)
	}
	for _, s := range []string{f.Description, f.Title, f.Remediation} {
		if strings.Contains(s, "token=") || strings.Contains(s, "?") && strings.Contains(s, "x=1") {
			t.Errorf("query string leaked: %s", s)
		}
	}
	for _, want := range []string{"archived as publicly served on 2021-06-06", "does not request the live URL"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("description lacks %q: %s", want, f.Description)
		}
	}
	for _, want := range []string{"http.exposed", "rotate", "exclu"} {
		if !strings.Contains(f.Remediation, want) {
			t.Errorf("remediation lacks %q: %s", want, f.Remediation)
		}
	}
}

func TestEvidenceURLsAreCapped(t *testing.T) {
	var rows []row
	for i := range 12 {
		rows = append(rows, row{url: u(fmt.Sprintf("/.git/objects/%02d", i)), ts: fmt.Sprintf("2020010100%04d", i)})
	}
	f := run(t, &fakeIntel{body: cdx(rows...)}, nil).keys["path:/.git"]
	if got := len(f.Evidence["urls"].([]string)); got != maxEvidenceURLs {
		t.Errorf("urls = %d", got)
	}
	if f.Evidence["urls_total"] != 12 || f.Evidence["captures"] != 12 {
		t.Errorf("evidence = %v", f.Evidence)
	}
}

func TestForeignHostsAndPortsAreDropped(t *testing.T) {
	b := cdx(
		row{url: "https://other.example.com/.env"},
		row{url: "https://" + host + ":8443/.env"},
		row{url: "ftp://" + host + "/.env"},
		row{url: "https://sub." + host + "/.env"},
		row{url: "not a url"},
		row{url: "https://" + host + ":443/dump.sql"},
		row{url: "https://WWW.EXAMPLE.COM./.npmrc"},
	)
	o := run(t, &fakeIntel{body: b}, nil)
	if len(o.keys) != 2 || o.keys["path:/dump.sql"].Key == "" || o.keys["path:/.npmrc"].Key == "" {
		t.Errorf("findings = %v", o.keys)
	}
}

func TestCapAndOrdering(t *testing.T) {
	var rows []row
	// 8 low, 8 medium, 8 high with distinct dates: the cap keeps high first,
	// then medium, newest first within a severity.
	for i := range 8 {
		rows = append(rows,
			row{url: u(fmt.Sprintf("/a%d/.ds_store", i)), ts: fmt.Sprintf("2020010%d000000", i+1)},
			row{url: u(fmt.Sprintf("/admin%d.json", i))}, // not a match: padding
			row{url: u(fmt.Sprintf("/swagger%d/x", i)), ts: fmt.Sprintf("2020010%d000000", i+1)},
			row{url: u(fmt.Sprintf("/b%d/dump.sql", i)), ts: fmt.Sprintf("2020010%d000000", i+1)},
		)
	}
	o := run(t, &fakeIntel{body: cdx(rows...)}, nil)
	if len(o.res.Findings) != DefaultMaxFindings {
		t.Fatalf("findings = %d", len(o.res.Findings))
	}
	if !o.res.Partial || o.obs["capped"] != 14 {
		t.Errorf("a capped run is partial: partial=%v capped=%v", o.res.Partial, o.obs["capped"])
	}
	for i := range 8 {
		if got := o.res.Findings[i].Severity; got != model.SeverityHigh {
			t.Errorf("finding %d severity = %s, want high first", i, got)
		}
	}
	if o.res.Findings[0].Key != "path:/b7/dump.sql" || o.res.Findings[7].Key != "path:/b0/dump.sql" {
		t.Errorf("newest first within severity: %s ... %s", o.res.Findings[0].Key, o.res.Findings[7].Key)
	}
	if o.res.Findings[8].Severity != model.SeverityMedium || o.res.Findings[9].Severity != model.SeverityMedium {
		t.Errorf("then medium: %s %s", o.res.Findings[8].Severity, o.res.Findings[9].Severity)
	}
}

func TestTruncatedHistoryIsPartial(t *testing.T) {
	var rows []row
	for i := range 100 {
		rows = append(rows, row{url: u(fmt.Sprintf("/page%d.html", i)), mime: "text/html"})
	}
	rows[3].url = u("/.env")
	o := run(t, &fakeIntel{body: cdx(rows...)}, map[string]any{"max_results": 100})
	if !o.res.Partial || o.obs["truncated"] != true {
		t.Errorf("a full page must be partial: partial=%v obs=%v", o.res.Partial, o.obs)
	}
	if _, ok := o.keys["path:/.env"]; !ok {
		t.Error("what was seen is still reported")
	}
	// One row fewer than the limit is complete.
	o = run(t, &fakeIntel{body: cdx(rows[:99]...)}, map[string]any{"max_results": 100})
	if o.res.Partial {
		t.Error("99 of 100 rows is a complete answer")
	}
}

func TestParseCDXBoundsMemory(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`[["original","statuscode","timestamp","mimetype"]`)
	for i := range 50000 {
		fmt.Fprintf(&sb, `,["https://%s/p%d","200","20200101000000","text/html"]`, host, i)
	}
	sb.WriteString("]")
	rows, truncated, err := parseCDX([]byte(sb.String()), 100)
	if err != nil || !truncated || len(rows.captures) != 100 {
		t.Errorf("rows=%d truncated=%v err=%v", len(rows.captures), truncated, err)
	}
}

func TestSoftNotFoundDowngradeAndMinSeverity(t *testing.T) {
	b := cdx(
		row{url: u("/.env"), mime: "text/html"},       // high -> medium
		row{url: u("/dump.sql"), mime: "text/html"},   // another soft hit
		row{url: u("/backup.old"), mime: "text/html"}, // soft
		row{url: u("/.git/"), mime: "text/html"},      // directory listing: never downgraded
		row{url: u("/real.sql"), mime: "text/html", ts: "20200101000000"},
		row{url: u("/real.sql"), mime: "application/sql", ts: "20190101000000"}, // one real capture keeps high
		row{url: u("/.DS_Store"), mime: "text/html"},                            // low -> info
		row{url: u("/admin/"), mime: "text/html"},                               // admin is html by nature
	)
	o := run(t, &fakeIntel{body: b}, nil)
	for key, want := range map[string]model.Severity{
		"path:/.env": model.SeverityMedium, "path:/dump.sql": model.SeverityMedium, "path:/backup.old": model.SeverityMedium,
		"path:/.git": model.SeverityHigh, "path:/real.sql": model.SeverityHigh, "path:/admin": model.SeverityMedium,
	} {
		if got := o.keys[key].Severity; got != want {
			t.Errorf("%s severity = %q, want %s", key, got, want)
		}
	}
	if _, ok := o.keys["path:/.ds_store"]; ok {
		t.Error("an info-level soft hit is below the default min_severity (low)")
	}
	if o.obs["below_min_severity"] != 1 {
		t.Errorf("obs = %v", o.obs)
	}
	if o.keys["path:/.env"].Evidence["downgraded"] == nil {
		t.Error("a downgrade must be explained in evidence")
	}

	o = run(t, &fakeIntel{body: b}, map[string]any{"min_severity": "high"})
	if len(o.keys) != 2 || o.keys["path:/.git"].Key == "" || o.keys["path:/real.sql"].Key == "" {
		t.Errorf("min_severity high: %v", o.keys)
	}
	o = run(t, &fakeIntel{body: b}, map[string]any{"min_severity": "info"})
	if _, ok := o.keys["path:/.ds_store"]; !ok {
		t.Error("min_severity info keeps it")
	}
}

func TestIgnorePathsAndMaxAge(t *testing.T) {
	b := cdx(
		row{url: u("/admin/login")},
		row{url: u("/admin2")},
		row{url: u("/swagger-ui/")},
		row{url: u("/old.sql"), ts: "20100101000000"},
		row{url: u("/new.sql"), ts: "20260901000000"},
	)
	o := run(t, &fakeIntel{body: b}, map[string]any{"ignore_paths": []any{"/admin/", "swagger-ui"}})
	if _, ok := o.keys["path:/admin"]; ok {
		t.Error("/admin is ignored")
	}
	if _, ok := o.keys["path:/swagger-ui"]; ok {
		t.Error("swagger-ui is ignored (leading slash optional)")
	}
	if _, ok := o.keys["path:/old.sql"]; !ok {
		t.Error("without max_age_days old captures count")
	}
	o = run(t, &fakeIntel{body: b}, map[string]any{"max_age_days": 365})
	if _, ok := o.keys["path:/old.sql"]; ok {
		t.Error("a 2010 capture is older than 365 days")
	}
	if _, ok := o.keys["path:/new.sql"]; !ok {
		t.Error("a recent capture stays")
	}
}

func TestInvalidOptionsFallBack(t *testing.T) {
	o := run(t, &fakeIntel{body: cdx(row{url: u("/.env")})},
		map[string]any{"max_findings": 0, "max_results": 5, "min_severity": "loud", "max_age_days": -3})
	if len(o.keys) != 1 {
		t.Errorf("defaults apply: %v", o.keys)
	}
	note, _ := o.obs["options_note"].(string)
	for _, want := range []string{"max_findings", "max_results", "min_severity", "max_age_days"} {
		if !strings.Contains(note, want) {
			t.Errorf("options_note lacks %s: %q", want, note)
		}
	}
}

func TestEmptyHistoryIsCompleteNotPartial(t *testing.T) {
	for name, body := range map[string]string{"empty body": "", "whitespace": "\n", "empty array": "[]", "header only": cdx()} {
		o := run(t, &fakeIntel{body: body}, nil)
		if len(o.res.Findings) != 0 || o.res.Partial || o.obs["wayback"] != StateOK {
			t.Errorf("%s: findings=%d partial=%v obs=%v", name, len(o.res.Findings), o.res.Partial, o.obs)
		}
	}
}

// Every way of not getting an answer is partial and never a finding or an error.
func TestLookupFailuresArePartial(t *testing.T) {
	for _, tc := range []struct {
		name  string
		f     *fakeIntel
		state string
	}{
		{"disabled", &fakeIntel{err: intel.ErrDisabled}, StateSkipped},
		{"rate limited", &fakeIntel{err: fmt.Errorf("%w: wayback", intel.ErrRateLimited)}, StateRateLimited},
		{"too large", &fakeIntel{err: intel.ErrTooLarge}, StateTooLarge},
		{"unavailable", &fakeIntel{err: intel.ErrUnavailable}, StateUnavailable},
		{"blocked", &fakeIntel{err: intel.ErrBlocked}, StateUnavailable},
		{"not found", &fakeIntel{err: intel.ErrNotFound}, StateNotFound},
		{"other error", &fakeIntel{err: errors.New("boom")}, StateUnavailable},
		{"not json", &fakeIntel{body: "<html>maintenance</html>"}, StateUnusable},
		{"not an array", &fakeIntel{body: `{"a":1}`}, StateUnusable},
		{"no header columns", &fakeIntel{body: `[["a","b"],["x","y"]]`}, StateUnusable},
		{"cut off", &fakeIntel{body: `[["original","statuscode","timestamp","mimetype"],["https://www.example.com/.env","200","2020`}, StateUnusable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := run(t, tc.f, nil)
			if !o.res.Partial || len(o.res.Findings) != 0 || o.obs["wayback"] != tc.state {
				t.Errorf("partial=%v findings=%d obs=%v, want state %s", o.res.Partial, len(o.res.Findings), o.obs, tc.state)
			}
		})
	}
}

func TestNilAndDisabledIntelAreSkipped(t *testing.T) {
	o := run(t, nil, nil)
	if !o.res.Partial || len(o.res.Findings) != 0 || o.obs["wayback"] != StateSkipped {
		t.Errorf("nil intel: %v", o.obs)
	}
	disabled, err := intel.New(intel.Options{Disabled: true})
	if err != nil {
		t.Fatal(err)
	}
	o = runTarget(t, checktest.NewTarget(checktest.Hostname(host, "example.com"), checktest.WithIntel(disabled)))
	if !o.res.Partial || len(o.res.Findings) != 0 || o.obs["wayback"] != StateSkipped {
		t.Errorf("disabled client: %v", o.obs)
	}
	var typedNil *intel.Client
	o = runTarget(t, checktest.NewTarget(checktest.Hostname(host, "example.com"), checktest.WithIntel(typedNil)))
	if !o.res.Partial || len(o.res.Findings) != 0 || o.obs["wayback"] != StateSkipped {
		t.Errorf("typed-nil client: %v", o.obs)
	}
}

func TestUnsupportedHostnamesAreNotQueried(t *testing.T) {
	for _, h := range []string{"*.example.com", "bücher.example", "a b.example.com", "-x.example.com", "x..example.com", ""} {
		f := &fakeIntel{body: cdx(row{url: u("/.env")})}
		tg := checktest.NewTarget(checktest.Hostname(h, "example.com"), checktest.WithIntel(f))
		o := runTarget(t, tg)
		if !o.res.Partial || len(f.calls) != 0 || o.obs["wayback"] != StateUnsupported || len(o.res.Findings) != 0 {
			t.Errorf("%q: partial=%v calls=%v obs=%v", h, o.res.Partial, f.calls, o.obs)
		}
	}
}

func TestPatternTableIsWellFormed(t *testing.T) {
	order := map[string]int{ClassSecrets: 3, ClassDump: 2, ClassAdmin: 1, ClassMisc: 0}
	last := 99
	for _, ru := range rules {
		if ru.label == "" || ru.re == nil || !ru.sev.Valid() {
			t.Errorf("incomplete rule %+v", ru)
		}
		if o, ok := order[ru.class]; !ok || o > last {
			t.Errorf("rule %q (%s) is out of class order", ru.label, ru.class)
		} else {
			last = o
		}
		if ru.root && ru.re.NumSubexp() < 1 {
			t.Errorf("subtree rule %q needs a capture group", ru.label)
		}
	}
}
