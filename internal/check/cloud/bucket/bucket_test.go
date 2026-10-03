package bucket

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/intel"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const host = "assets.example.com"

// served records every request and answers with a fixed status and body.
type served struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []string
}

func newServer(tls bool, status int, body string) *served {
	s := &served{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, r.Method+" "+r.Host+r.URL.RequestURI())
		s.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	if tls {
		s.Server = httptest.NewTLSServer(h)
	} else {
		s.Server = httptest.NewServer(h)
	}
	return s
}

func (s *served) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.reqs...)
}

func listing(keys ...string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>assets-bucket</Name><Prefix></Prefix><Marker></Marker><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>`)
	for _, k := range keys {
		fmt.Fprintf(&b, `<Contents><Key>%s</Key><LastModified>2024-01-01T00:00:00.000Z</LastModified><Size>1</Size></Contents>`, k)
	}
	b.WriteString(`</ListBucketResult>`)
	return b.String()
}

func errorDoc(code string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><Error><Code>` + code + `</Code><Message>msg</Message></Error>`
}

type outcome struct {
	res  *check.Result
	obs  map[string]any
	res0 *checktest.Resolver
}

// run points host at an S3 endpoint and serves it from the given servers on
// port 80 (plain) and 443 (TLS); either may be nil (connection refused).
func run(t *testing.T, plain, tls *served, cfg map[string]any, cname string) outcome {
	t.Helper()
	routes := map[string]*httptest.Server{}
	if plain != nil {
		routes[host+":80"] = plain.Server
	}
	if tls != nil {
		routes[host+":443"] = tls.Server
	}
	r := &checktest.Resolver{CNAMEs: map[string]string{host: cname}}
	tg := checktest.NewTarget(checktest.Hostname(host, "example.com"),
		checktest.WithResolver(r), checktest.WithHTTP(checktest.HostClient(routes)), checktest.WithConfig(cfg))
	return runTarget(t, tg, r)
}

func runTarget(t *testing.T, tg check.Target, r *checktest.Resolver) outcome {
	t.Helper()
	res, err := New(nil).Run(context.Background(), tg)
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}
	if len(res.Observations) != 1 {
		t.Fatalf("want one observation, got %d", len(res.Observations))
	}
	return outcome{res: res, obs: res.Observations[0].Data, res0: r}
}

const s3 = "assets-bucket.s3.amazonaws.com"

func TestAppliesAndMetadata(t *testing.T) {
	c := New(nil)
	if !c.Applies(checktest.Hostname(host, "example.com")) {
		t.Error("owned hostname applies")
	}
	for _, a := range []model.Asset{
		{Kind: model.KindHostname, Key: host, Scope: model.ScopeExternal},
		{Kind: model.KindIP, Key: "203.0.113.7", Scope: model.ScopeOwned},
		{Kind: model.KindZone, Key: "example.com", Scope: model.ScopeOwned},
	} {
		if c.Applies(a) {
			t.Errorf("must not apply to %s %s %s", a.Kind, a.Key, a.Scope)
		}
	}
	if c.Name() != Name || c.Tier() != model.TierPassive || c.DefaultInterval() != 12*time.Hour {
		t.Errorf("metadata: %s %s %s", c.Name(), c.Tier(), c.DefaultInterval())
	}
}

func TestMatchProvider(t *testing.T) {
	cases := map[string]string{
		"assets.s3.amazonaws.com":                        "aws-s3",
		"assets.s3-us-west-2.amazonaws.com":              "aws-s3",
		"assets.s3.us-west-2.amazonaws.com":              "aws-s3",
		"assets.s3.dualstack.eu-west-1.amazonaws.com":    "aws-s3",
		"s3.amazonaws.com":                               "aws-s3",
		"assets.s3.cn-north-1.amazonaws.com.cn":          "aws-s3",
		"assets.s3-website-us-east-1.amazonaws.com":      "aws-s3-website",
		"assets.s3-website.eu-west-1.amazonaws.com":      "aws-s3-website",
		"c.storage.googleapis.com":                       "gcs",
		"assets.storage.googleapis.com":                  "gcs",
		"storage.googleapis.com":                         "gcs",
		"acct.blob.core.windows.net":                     "azure-blob",
		"acct.z13.web.core.windows.net":                  "azure-static-website",
		"pub-abc123.r2.dev":                              "cloudflare-r2",
		"acct.r2.cloudflarestorage.com":                  "cloudflare-r2",
		"ASSETS.S3.AMAZONAWS.COM.":                       "aws-s3",
		"d111.cloudfront.net":                            "",
		"notes3.amazonaws.com":                           "",
		"evil-s3.amazonaws.com":                          "",
		"assets.s3.amazonaws.com.evil.example.net":       "",
		"s3.amazonaws.com.example.net":                   "",
		"foo.storage.googleapis.com.example.net":         "",
		"mystorage.googleapis.com":                       "",
		"acct.blob.core.windows.net.example.net":         "",
		"acct.queue.core.windows.net":                    "",
		"www.example.net":                                "",
		"r2.dev.example.net":                             "",
		"bucket.s3.amazonaws.com.example.com":            "",
		"ec2-1-2-3-4.compute-1.amazonaws.com":            "",
		"my-s3-website.example.net":                      "",
		"bucket.s3-website-us-east-1.amazonaws.com.evil": "",
	}
	for target, want := range cases {
		got := ""
		if p := MatchProvider(target); p != nil {
			got = p.name
		}
		if got != want {
			t.Errorf("%s: got %q want %q", target, got, want)
		}
	}
}

func TestListableBucketIsHigh(t *testing.T) {
	srv := newServer(false, 200, listing("images/logo.png", "css/site.css", "index.html"))
	defer srv.Close()
	o := run(t, srv, nil, nil, s3)
	if len(o.res.Findings) != 1 || o.res.Partial {
		t.Fatalf("findings=%+v partial=%v obs=%v", o.res.Findings, o.res.Partial, o.obs)
	}
	f := o.res.Findings[0]
	if f.Check != Name || f.Key != "listable" || f.Severity != model.SeverityHigh {
		t.Errorf("finding: %+v", f)
	}
	ev := f.Evidence
	if ev["provider"] != "aws-s3" || ev["cname"] != s3 || ev["url"] != "http://"+host+"/" || ev["bucket"] != "assets-bucket" ||
		ev["keys_on_page"] != 3 || ev["truncated"] != false || ev["http_status"] != 200 {
		t.Errorf("evidence: %v", ev)
	}
	if keys := ev["keys"].([]string); len(keys) != 3 || keys[0] != "images/logo.png" {
		t.Errorf("keys: %v", keys)
	}
	if _, ok := ev["sensitive_keys"]; ok {
		t.Error("nothing sensitive was listed")
	}
	for _, want := range []string{"anyone on the internet", "first page", "no object was requested"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("description lacks %q: %s", want, f.Description)
		}
	}
	for _, want := range []string{"Block Public Access", "s3:ListBucket", "CloudFront"} {
		if !strings.Contains(f.Remediation, want) {
			t.Errorf("remediation lacks %q: %s", want, f.Remediation)
		}
	}
	// Exactly one plain GET of the owned hostname's root: no key, no query.
	if got := srv.requests(); len(got) != 1 || got[0] != "GET "+host+"/" {
		t.Errorf("requests = %v", got)
	}
	// The provider endpoint is never resolved or contacted.
	for _, c := range o.res0.Calls {
		if c != "cname "+host {
			t.Errorf("unexpected lookup %q", c)
		}
	}
}

func TestHTTPSIsTriedFirst(t *testing.T) {
	tlsSrv := newServer(true, 200, listing("a.txt"))
	defer tlsSrv.Close()
	plain := newServer(false, 200, "never asked")
	defer plain.Close()
	o := run(t, plain, tlsSrv, nil, s3)
	if len(o.res.Findings) != 1 || o.res.Findings[0].Evidence["url"] != "https://"+host+"/" {
		t.Fatalf("findings: %+v", o.res.Findings)
	}
	if len(plain.requests()) != 0 {
		t.Errorf("a conclusive https answer ends the probing: %v", plain.requests())
	}
}

func TestHTTPFallbackWhenHTTPSFails(t *testing.T) {
	plain := newServer(false, 200, listing("a.txt"))
	defer plain.Close()
	// Port 443 is routed at a plain-HTTP server: the TLS handshake fails.
	o := run(t, plain, plain, nil, s3)
	if len(o.res.Findings) != 1 || o.res.Partial || o.res.Findings[0].Evidence["url"] != "http://"+host+"/" {
		t.Fatalf("findings=%+v partial=%v obs=%v", o.res.Findings, o.res.Partial, o.obs)
	}
	if o.obs["fetch_errors"] == nil {
		t.Error("the failed https attempt is recorded")
	}
}

func TestSensitiveKeysMakeItCritical(t *testing.T) {
	var keys []string
	for i := range 30 {
		keys = append(keys, fmt.Sprintf("public/img%02d.png", i))
	}
	keys = append(keys, "db/Backup-2024.tar", "deploy/.env.production", "infra/prod.tfstate", "keys/id_rsa", "keys/server.pem", "aws/credentials", "dump.sql", "custom/payroll.xlsx")
	srv := newServer(false, 200, listing(keys...))
	defer srv.Close()
	o := run(t, srv, nil, map[string]any{"sensitive_keywords": []any{"PAYROLL", " "}}, s3)
	f := o.res.Findings[0]
	if f.Severity != model.SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
	ev := f.Evidence
	if ev["sensitive_keys"] != 8 || ev["keys_on_page"] != 38 {
		t.Errorf("evidence: %v", ev)
	}
	recorded := ev["keys"].([]string)
	if len(recorded) != maxRecordedKeys {
		t.Fatalf("recorded %d keys, want %d", len(recorded), maxRecordedKeys)
	}
	// The names that raised the severity survive the cap, in page order.
	if recorded[0] != "db/Backup-2024.tar" || recorded[7] != "custom/payroll.xlsx" || recorded[8] != "public/img00.png" {
		t.Errorf("recorded = %v", recorded)
	}
	markers := strings.Join(ev["sensitive_markers"].([]string), ",")
	for _, m := range []string{".env", "backup", ".sql", "id_rsa", "credentials", "tfstate", ".pem", "payroll"} {
		if !strings.Contains(markers, m) {
			t.Errorf("markers %q lack %s", markers, m)
		}
	}
}

func TestEachDefaultSensitiveMarker(t *testing.T) {
	for _, k := range []string{"x/.env", "My-BACKUP.zip", "a.sql", "id_rsa", "AWS/Credentials.csv", "state.tfstate", "k.PEM"} {
		srv := newServer(false, 200, listing("harmless.txt", k))
		o := run(t, srv, nil, nil, s3)
		srv.Close()
		if o.res.Findings[0].Severity != model.SeverityCritical {
			t.Errorf("%s did not raise the severity", k)
		}
	}
}

func TestLongKeyNamesAreTruncated(t *testing.T) {
	srv := newServer(false, 200, listing(strings.Repeat("k", 5000)+".env"))
	defer srv.Close()
	o := run(t, srv, nil, nil, s3)
	keys := o.res.Findings[0].Evidence["keys"].([]string)
	if len(keys) != 1 || len([]rune(keys[0])) > maxKeyLen+1 {
		t.Errorf("key not truncated: %d chars", len([]rune(keys[0])))
	}
}

func TestTruncatedListingIsRecorded(t *testing.T) {
	body := strings.Replace(listing("a.txt"), "<IsTruncated>false</IsTruncated>", "<IsTruncated>true</IsTruncated>", 1)
	srv := newServer(false, 200, body)
	defer srv.Close()
	f := run(t, srv, nil, nil, s3).res.Findings[0]
	if f.Evidence["truncated"] != true || !strings.Contains(f.Description, "more pages exist") {
		t.Errorf("finding: %+v", f)
	}
	if reqs := srv.requests(); len(reqs) != 1 {
		t.Errorf("only the first page is read: %v", reqs)
	}
}

func TestGCSAndAzureListings(t *testing.T) {
	gcs := newServer(false, 200, `<?xml version='1.0' encoding='UTF-8'?><ListBucketResult xmlns='http://doc.s3.amazonaws.com/2006-03-01'><Name>assets-bucket</Name><IsTruncated>false</IsTruncated><Contents><Key>a/b.txt</Key></Contents></ListBucketResult>`)
	defer gcs.Close()
	o := run(t, gcs, nil, nil, "c.storage.googleapis.com")
	f := o.res.Findings[0]
	if f.Evidence["provider"] != "gcs" || f.Severity != model.SeverityHigh || !strings.Contains(f.Remediation, "legacyObjectReader") {
		t.Errorf("gcs: %+v", f)
	}

	az := newServer(false, 200, `<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://acct.blob.core.windows.net/" ContainerName="pub"><Blobs><Blob><Name>report.pdf</Name><Properties><Content-Length>3</Content-Length></Properties></Blob><Blob><Name>prod-backup.bak</Name></Blob></Blobs><NextMarker>2!abc</NextMarker></EnumerationResults>`)
	defer az.Close()
	o = run(t, az, nil, nil, "acct.blob.core.windows.net")
	f = o.res.Findings[0]
	if f.Evidence["provider"] != "azure-blob" || f.Severity != model.SeverityCritical || f.Evidence["truncated"] != true ||
		f.Evidence["keys_on_page"] != 2 || !strings.Contains(f.Remediation, "AllowBlobPublicAccess") {
		t.Errorf("azure: %+v", f)
	}
}

func TestPrivateBucketsRaiseNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		state  State
	}{
		"AccessDenied":      {403, errorDoc("AccessDenied"), StatePrivate},
		"AllAccessDisabled": {403, errorDoc("AllAccessDisabled"), StatePrivate},
		"plain 403":         {403, "Forbidden", StatePrivate},
		"no website config": {404, errorDoc("NoSuchWebsiteConfiguration"), StatePrivate},
		"azure anonymous":   {409, errorDoc("PublicAccessNotPermitted"), StatePrivate},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newServer(false, tc.status, tc.body)
			defer srv.Close()
			o := run(t, srv, nil, nil, s3)
			if len(o.res.Findings) != 0 || o.res.Partial || o.obs["bucket_state"] != tc.state {
				t.Errorf("findings=%d partial=%v obs=%v", len(o.res.Findings), o.res.Partial, o.obs)
			}
		})
	}
}

func TestNoSuchBucketIsLeftToTakeover(t *testing.T) {
	srv := newServer(false, 404, errorDoc("NoSuchBucket"))
	defer srv.Close()
	o := run(t, srv, nil, nil, s3)
	if len(o.res.Findings) != 0 || o.res.Partial || o.obs["bucket_state"] != StateNoSuchBucket {
		t.Errorf("findings=%d partial=%v obs=%v", len(o.res.Findings), o.res.Partial, o.obs)
	}
}

func TestStaticWebsiteIsObservationOnly(t *testing.T) {
	srv := newServer(false, 200, "<html><body><h1>Welcome</h1> a page about ListBucketResult</body></html>")
	defer srv.Close()
	o := run(t, srv, nil, nil, "assets.s3-website-us-east-1.amazonaws.com")
	if len(o.res.Findings) != 0 || o.res.Partial || o.obs["bucket_state"] != StateWebsite || o.obs["website"] != true {
		t.Errorf("findings=%d partial=%v obs=%v", len(o.res.Findings), o.res.Partial, o.obs)
	}
}

func TestOtherAnswersAreNotListings(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		state  State
	}{
		"other error code": {400, errorDoc("InvalidRequest"), StateOtherError},
		"plain 404":        {404, "nothing here", StateNotFound},
		"xml index page":   {200, `<?xml version="1.0"?><feed><title>x</title></feed>`, StateWebsite},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newServer(false, tc.status, tc.body)
			defer srv.Close()
			o := run(t, srv, nil, nil, s3)
			if len(o.res.Findings) != 0 || o.res.Partial || o.obs["bucket_state"] != tc.state {
				t.Errorf("findings=%d partial=%v obs=%v", len(o.res.Findings), o.res.Partial, o.obs)
			}
		})
	}
}

// A listing that comes with an error status, an upstream failure, a redirect
// or no answer at all proves nothing: the run is partial.
func TestInconclusiveRunsArePartial(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"503":                 {503, "slow down"},
		"429":                 {429, ""},
		"redirect":            {301, ""},
		"listing but not 2xx": {400, listing("a.txt")},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newServer(false, tc.status, tc.body)
			defer srv.Close()
			o := run(t, srv, srv, nil, s3)
			if !o.res.Partial || len(o.res.Findings) != 0 || o.obs["bucket_state"] != StateInconclusive {
				t.Errorf("partial=%v findings=%d obs=%v", o.res.Partial, len(o.res.Findings), o.obs)
			}
		})
	}
}

func TestNoAnswerIsPartial(t *testing.T) {
	o := run(t, nil, nil, nil, s3)
	if !o.res.Partial || len(o.res.Findings) != 0 || o.obs["bucket_state"] != StateNoAnswer || o.obs["fetch_errors"] == nil {
		t.Errorf("partial=%v obs=%v", o.res.Partial, o.obs)
	}
}

func TestDNSPaths(t *testing.T) {
	srv := newServer(false, 200, listing("a.txt"))
	defer srv.Close()
	routes := map[string]*httptest.Server{host + ":80": srv.Server}
	do := func(r *checktest.Resolver) outcome {
		tg := checktest.NewTarget(checktest.Hostname(host, "example.com"),
			checktest.WithResolver(r), checktest.WithHTTP(checktest.HostClient(routes)))
		return runTarget(t, tg, r)
	}

	// NXDOMAIN: nothing to check and nothing unknown.
	o := do(&checktest.Resolver{})
	if o.res.Partial || len(o.res.Findings) != 0 || o.obs["cname"] != nil {
		t.Errorf("nxdomain: partial=%v obs=%v", o.res.Partial, o.obs)
	}
	// An address record without a CNAME.
	o = do(&checktest.Resolver{Hosts: map[string][]string{host: {"203.0.113.9"}}})
	if o.res.Partial || len(o.res.Findings) != 0 || o.obs["provider"] != nil {
		t.Errorf("no cname: partial=%v obs=%v", o.res.Partial, o.obs)
	}
	// A CNAME to something else: no request is made at all.
	before := len(srv.requests())
	o = do(&checktest.Resolver{CNAMEs: map[string]string{host: "d111.cloudfront.net"}})
	if o.res.Partial || len(o.res.Findings) != 0 || o.obs["external"] != nil || len(srv.requests()) != before {
		t.Errorf("other provider: partial=%v obs=%v", o.res.Partial, o.obs)
	}
	// SERVFAIL and the like are unknown, not clean.
	o = do(&checktest.Resolver{Errs: map[string]error{host: errors.New("servfail")}})
	if !o.res.Partial || len(o.res.Findings) != 0 || o.obs["cname_error"] == nil {
		t.Errorf("servfail: partial=%v obs=%v", o.res.Partial, o.obs)
	}
	// Control: the same server does produce a finding for an S3 CNAME.
	o = do(&checktest.Resolver{CNAMEs: map[string]string{host: s3}})
	if len(o.res.Findings) != 1 {
		t.Errorf("control: %+v", o.obs)
	}
}

// The check never needs Target.Intel: a missing, disabled or failing metadata
// client changes nothing.
func TestIndependentOfIntel(t *testing.T) {
	srv := newServer(false, 200, listing("a.txt"))
	defer srv.Close()
	r := &checktest.Resolver{CNAMEs: map[string]string{host: s3}}
	for name, in := range map[string]check.Intel{"nil": nil, "disabled": disabledIntel{}} {
		tg := checktest.NewTarget(checktest.Hostname(host, "example.com"), checktest.WithResolver(r),
			checktest.WithHTTP(checktest.HostClient(map[string]*httptest.Server{host + ":80": srv.Server})), checktest.WithIntel(in))
		o := runTarget(t, tg, r)
		if len(o.res.Findings) != 1 || o.res.Partial {
			t.Errorf("%s intel: findings=%d partial=%v", name, len(o.res.Findings), o.res.Partial)
		}
	}
}

type disabledIntel struct{}

func (disabledIntel) Get(context.Context, string, string) (intel.Response, error) {
	return intel.Response{}, intel.ErrDisabled
}
func (disabledIntel) RDAPBase(context.Context, string) (string, error) { return "", intel.ErrDisabled }

func TestParseXMLIsBounded(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`<ListBucketResult><Name>b</Name>`)
	for range maxCountedKeys + 500 {
		sb.WriteString(`<Contents><Key>k</Key></Contents>`)
	}
	sb.WriteString(`</ListBucketResult>`)
	root, doc := parseXML([]byte(sb.String()))
	if root != "listbucketresult" || len(doc.keys) != maxCountedKeys {
		t.Errorf("root=%q keys=%d", root, len(doc.keys))
	}
}

func TestHostileBodies(t *testing.T) {
	for name, body := range map[string]string{
		"entity bomb": `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><ListBucketResult><Name>&b;</Name><Contents><Key>&b;&b;</Key></Contents></ListBucketResult>`,
		"cut off":     `<ListBucketResult><Name>b</Name><Contents><Key>a.txt</Key></Contents><Contents><Key>half`,
		"binary":      "\x00\x01\x02\xff\xfe",
		"empty":       "",
		"html":        "<!DOCTYPE html><html><head><title>x",
	} {
		a := classify(200, []byte(body))
		if name == "cut off" && (a.state != StateListable || len(a.keys) == 0) {
			t.Errorf("%s: %+v", name, a)
		}
		if (name == "binary" || name == "empty" || name == "html") && a.state != StateWebsite {
			t.Errorf("%s: state %s", name, a.state)
		}
	}
	// Go's decoder rejects undeclared entities, so a bomb never expands and
	// cannot make the key list large.
	if a := classify(200, []byte(`<ListBucketResult><Contents><Key>&lol9;</Key></Contents></ListBucketResult>`)); a.state != StateListable {
		t.Errorf("undeclared entity: %+v", a)
	}
}

func TestListenerNeverDialledForProviderHosts(t *testing.T) {
	// The check speaks HTTP to the owned hostname through the injected client
	// only: the scope-guarded dialer is never used for the provider endpoint.
	d := &checktest.Dialer{Routes: map[string]string{}}
	srv := newServer(false, 403, errorDoc("AccessDenied"))
	defer srv.Close()
	r := &checktest.Resolver{CNAMEs: map[string]string{host: s3}}
	tg := checktest.NewTarget(checktest.Hostname(host, "example.com"), checktest.WithResolver(r), checktest.WithDialer(d),
		checktest.WithHTTP(checktest.HostClient(map[string]*httptest.Server{host + ":80": srv.Server})))
	runTarget(t, tg, r)
	if len(d.Dialed) != 0 {
		t.Errorf("dialled %v", d.Dialed)
	}
}
