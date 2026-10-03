package prowlerapp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/prowlerapp"
	pt "github.com/chainseer-xyz/deckard/internal/ingest/prowlerapp/prowlerapptest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

var (
	scanDone  = clock.Add(-3 * time.Hour)
	scanStart = clock.Add(-4 * time.Hour)
)

func world(t *testing.T) *pt.Server { return pt.Sample(t, testKey, scanDone) }

func awsFinding(i int) pt.Finding { return pt.AWSFinding(i) }

func collector(t *testing.T, srv *pt.Server, mod func(*prowlerapp.Options)) *prowlerapp.Collector {
	t.Helper()
	c, _ := newClient(t, srv, nil)
	o := prowlerapp.Options{Now: func() time.Time { return clock }}
	if mod != nil {
		mod(&o)
	}
	return prowlerapp.NewCollector(c, o)
}

func collectAWS(t *testing.T, srv *pt.Server, mod func(*prowlerapp.Options)) *prowlerapp.Run {
	t.Helper()
	col := collector(t, srv, mod)
	return col.Collect(context.Background(), prowlerapp.Provider{ID: "p-aws", Type: "aws", UID: "123456789012", Connected: srv.Providers[1].Connected})
}

func mustValid(t *testing.T, r *prowlerapp.Run) {
	t.Helper()
	if r.Request == nil {
		t.Fatalf("no request (err %v, reasons %v)", r.Err, r.Reasons)
	}
	if p := ingest.Validate(r.Request, ingest.Options{Now: clock}); len(p) > 0 {
		t.Fatalf("invalid request: %s", ingest.Summary(p))
	}
}

func hasReason(r *prowlerapp.Run, sub string) bool {
	for _, x := range r.Reasons {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

func TestProvidersAreSelectedAndOrdered(t *testing.T) {
	srv := world(t)
	names := func(o prowlerapp.Options) string {
		ps, _, err := collector(t, srv, func(x *prowlerapp.Options) { *x = o; x.Now = func() time.Time { return clock } }).Providers(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var s []string
		for _, p := range ps {
			s = append(s, prowlerapp.Scope(p))
		}
		return strings.Join(s, ",")
	}
	for name, tc := range map[string]struct {
		o    prowlerapp.Options
		want string
	}{
		"all, ordered by type": {prowlerapp.Options{}, "aws:123456789012,gcp:my-project"},
		"by type":              {prowlerapp.Options{ProviderTypes: []string{"GCP"}}, "gcp:my-project"},
		"by uid":               {prowlerapp.Options{ProviderUIDs: []string{"123456789012"}}, "aws:123456789012"},
		"type and uid":         {prowlerapp.Options{ProviderTypes: []string{"aws"}, ProviderUIDs: []string{"my-project"}}, ""},
		"none":                 {prowlerapp.Options{ProviderTypes: []string{"azure"}}, ""},
	} {
		if got := names(tc.o); got != tc.want {
			t.Errorf("%s: %q want %q", name, got, tc.want)
		}
	}
}

func TestCompleteRunAcrossThreePagesWithJoinedResources(t *testing.T) {
	srv := world(t)
	srv.PlantSecrets = true
	run := collectAWS(t, srv, nil)
	mustValid(t, run)
	if !run.Complete() || len(run.Reasons) != 0 || run.Scope != "aws:123456789012" || run.ScanID != "s-aws" || run.Total != 5 {
		t.Fatalf("%+v", run)
	}
	if !run.Request.ObservedAt.Equal(scanDone) || run.Request.Tool != "prowler" {
		t.Fatalf("observed_at %v tool %s", run.Request.ObservedAt, run.Request.Tool)
	}
	if n := srv.Count("/api/v1/findings/latest"); n != 3 {
		t.Fatalf("%d finding pages", n)
	}
	f := run.Request.Findings[0]
	if f.Key != "s3_public:arn:aws:s3:::bucket-1" || f.Asset.Key != "arn:aws:s3:::bucket-1" || f.Asset.Kind != model.KindCloudResource ||
		f.Title != "S3 bucket is public" || f.Severity != model.SeverityHigh || f.Evidence["scan_id"] != "s-aws" || f.Evidence["delta"] != "new" ||
		!strings.Contains(f.Description, "Risk: data leak") || !strings.Contains(f.Remediation, "https://docs.example.com/s3") {
		t.Fatalf("%+v", f)
	}
	b, _ := json.Marshal(run.Request)
	for _, planted := range []string{pt.SecretRaw, pt.SecretTag, pt.SecretMeta} {
		if strings.Contains(string(b), planted) {
			t.Fatalf("%s leaked into the request", planted)
		}
	}
}

func TestTheQuerySentToProwler(t *testing.T) {
	srv := world(t)
	collectAWS(t, srv, nil)
	var q url.Values
	for _, r := range srv.Requests() {
		if strings.HasPrefix(r, "GET /api/v1/findings/latest") {
			u, _ := url.Parse(strings.TrimPrefix(r, "GET "))
			q = u.Query()
			break
		}
	}
	for k, v := range map[string]string{"filter[provider]": "p-aws", "filter[status]": "FAIL", "filter[muted]": "false",
		"filter[severity__in]": "critical,high,medium", "include": "resources", "page[size]": "100"} {
		if q.Get(k) != v {
			t.Errorf("%s = %q want %q (query %v)", k, q.Get(k), v, q)
		}
	}
	if !strings.Contains(q.Get("fields[findings]"), "status_extended") || strings.Contains(q.Get("fields[findings]"), "raw_result") {
		t.Errorf("sparse fieldset %q", q.Get("fields[findings]"))
	}
	srv2 := world(t)
	collectAWS(t, srv2, func(o *prowlerapp.Options) { o.IncludeMuted = true; o.MinSeverity = model.SeverityInfo })
	for _, r := range srv2.Requests() {
		if strings.HasPrefix(r, "GET /api/v1/findings/latest") && (strings.Contains(r, "filter%5Bmuted%5D") || !strings.Contains(r, "informational")) {
			t.Fatalf("--include-muted and the info floor are not reflected: %s", r)
		}
	}
}

func TestStatusMutedAndSeverityAreFiltered(t *testing.T) {
	for _, lax := range []bool{false, true} { // a server that honours the filters, and one that ignores them
		srv := world(t)
		srv.IgnoreFilters = lax
		more := []pt.Finding{awsFinding(1), awsFinding(1), awsFinding(1), awsFinding(1), awsFinding(1)}
		for i, mod := range []func(*pt.Finding){
			func(f *pt.Finding) { f.Status = "PASS" },
			func(f *pt.Finding) { f.Status = "MANUAL" },
			func(f *pt.Finding) { f.Muted = true },
			func(f *pt.Finding) { f.Severity = "low" },
			func(f *pt.Finding) { f.Severity = "informational" },
		} {
			more[i].ID = fmt.Sprintf("x%d", i)
			mod(&more[i])
		}
		srv.Findings = append(srv.Findings, more...)
		run := collectAWS(t, srv, nil)
		mustValid(t, run)
		if !run.Complete() || len(run.Request.Findings) != 5 {
			t.Fatalf("lax=%v: complete %v with %d findings, reasons %v", lax, run.Complete(), len(run.Request.Findings), run.Reasons)
		}
	}
	srv := world(t)
	srv.Findings = append(srv.Findings, awsFinding(1))
	srv.Findings[len(srv.Findings)-1].ID, srv.Findings[len(srv.Findings)-1].Muted = "muted1", true
	srv.Findings[len(srv.Findings)-1].CheckID = "s3_other"
	run := collectAWS(t, srv, func(o *prowlerapp.Options) { o.IncludeMuted = true })
	if len(run.Request.Findings) != 6 {
		t.Fatalf("--include-muted: %d findings", len(run.Request.Findings))
	}
}

func TestUnknownSeverityValuesAreMedium(t *testing.T) {
	srv := world(t)
	srv.IgnoreFilters = true
	srv.Findings[0].Severity = "catastrophic"
	srv.Findings[1].Severity = "INFORMATIONAL"
	run := collectAWS(t, srv, func(o *prowlerapp.Options) { o.MinSeverity = model.SeverityInfo })
	mustValid(t, run)
	got := map[string]model.Severity{}
	for _, f := range run.Request.Findings {
		got[f.Evidence["scan_id"].(string)+f.Key] = f.Severity
	}
	if got["s-awss3_public:arn:aws:s3:::bucket-1"] != model.SeverityMedium || got["s-awss3_public:arn:aws:s3:::bucket-2"] != model.SeverityInfo {
		t.Fatalf("%v", got)
	}
}

func TestFindingWithoutAResourceIsKeyedOnASynthesizedID(t *testing.T) {
	srv := world(t)
	srv.Findings = append(srv.Findings, pt.Finding{ID: "fnr", UID: "prowler-aws-iam_root_mfa-123456789012-us-east-1", ProviderID: "p-aws", ScanID: "s-aws",
		CheckID: "iam_root_mfa", CheckTitle: "Root MFA", Severity: "critical", Status: "FAIL", StatusExtended: "no MFA on root"})
	run := collectAWS(t, srv, nil)
	mustValid(t, run)
	var key string
	for _, f := range run.Request.Findings {
		if strings.HasPrefix(f.Key, "iam_root_mfa:") {
			key = f.Asset.Key
		}
	}
	if !run.Complete() || key != "prowler:aws:123456789012:prowler-aws-iam_root_mfa-123456789012-us-east-1" {
		t.Fatalf("complete %v asset key %q reasons %v", run.Complete(), key, run.Reasons)
	}
}

func TestDoubtfulFindingsForbidACompleteRun(t *testing.T) {
	for name, tc := range map[string]struct {
		mod    func(*pt.Server)
		reason string
		found  int
	}{
		"no resources relationship": {func(s *pt.Server) { s.Findings[0].OmitResourcesRel = true }, "no resources relationship", 5},
		"resource missing":          {func(s *pt.Server) { s.Findings[0].ResourceIDs = []string{"ghost"} }, "missing from the response", 4},
		"undecodable finding":       {func(s *pt.Server) { s.Findings[0].RawAttrs = map[string]any{"severity": []string{"x"}} }, "could not be decoded", 4},
		"another scan's finding":    {func(s *pt.Server) { s.Findings[0].ScanID = "s-other" }, "belongs to scan s-other", 4},
	} {
		t.Run(name, func(t *testing.T) {
			srv := world(t)
			tc.mod(srv)
			run := collectAWS(t, srv, nil)
			mustValid(t, run)
			if run.Complete() || !hasReason(run, tc.reason) || len(run.Request.Findings) != tc.found {
				t.Fatalf("complete %v findings %d reasons %v", run.Complete(), len(run.Request.Findings), run.Reasons)
			}
		})
	}
}

func TestServerThatDisagreesWithItselfForbidsACompleteRun(t *testing.T) {
	srv := world(t)
	srv.CountDelta = 3
	run := collectAWS(t, srv, nil)
	mustValid(t, run)
	if run.Complete() || !hasReason(run, "announced 8 findings but 5 were returned") {
		t.Fatalf("%v %v", run.Complete(), run.Reasons)
	}
	srv = world(t)
	srv.ShiftPages = true
	run = collectAWS(t, srv, nil)
	if run.Complete() || !hasReason(run, "appeared on two pages") {
		t.Fatalf("%v %v", run.Complete(), run.Reasons)
	}
}

func TestScanStates(t *testing.T) {
	older := pt.Scan{ID: "s-old", ProviderID: "p-aws", State: "completed", StartedAt: scanStart.Add(-30 * time.Hour), CompletedAt: scanDone.Add(-30 * time.Hour)}
	for name, tc := range map[string]struct {
		scans    []pt.Scan
		complete bool
		scan     string
		reason   string
		err      string
	}{
		"completed": {scans: []pt.Scan{{ID: "s-aws", State: "completed", StartedAt: scanStart, CompletedAt: scanDone}}, complete: true, scan: "s-aws"},
		"a scheduled placeholder is not a scan that ran": {
			scans:    []pt.Scan{{ID: "s-next", State: "scheduled", StartedAt: clock.Add(20 * time.Hour)}, {ID: "s-aws", State: "completed", StartedAt: scanStart, CompletedAt: scanDone}},
			complete: true, scan: "s-aws"},
		"available is not a scan that ran": {
			scans:    []pt.Scan{{ID: "s-av", State: "available", StartedAt: clock}, {ID: "s-aws", State: "completed", StartedAt: scanStart, CompletedAt: scanDone}},
			complete: true, scan: "s-aws"},
		"executing, older completed scan": {
			scans: []pt.Scan{{ID: "s-run", State: "executing", StartedAt: clock.Add(-time.Minute)}, {ID: "s-aws", State: "completed", StartedAt: scanStart, CompletedAt: scanDone}},
			scan:  "s-aws", reason: "latest scan s-run is executing"},
		"failed, older completed scan": {
			scans: []pt.Scan{{ID: "s-bad", State: "failed", StartedAt: clock.Add(-time.Hour)}, {ID: "s-aws", State: "completed", StartedAt: scanStart, CompletedAt: scanDone}},
			scan:  "s-aws", reason: "latest scan s-bad is failed"},
		"cancelled, older completed scan": {
			scans: []pt.Scan{{ID: "s-x", State: "cancelled", StartedAt: clock.Add(-time.Hour)}, {ID: "s-aws", State: "completed", StartedAt: scanStart, CompletedAt: scanDone}},
			scan:  "s-aws", reason: "latest scan s-x is cancelled"},
		"only a failed scan":        {scans: []pt.Scan{{ID: "s-bad", State: "failed", StartedAt: scanStart}}, err: "no completed scan"},
		"only an executing scan":    {scans: []pt.Scan{{ID: "s-run", State: "executing", StartedAt: scanStart}}, err: "no completed scan"},
		"only scheduled":            {scans: []pt.Scan{{ID: "s-next", State: "scheduled", StartedAt: clock.Add(time.Hour)}}, err: "no scan has run"},
		"no scans":                  {err: "no scan has run"},
		"completed without a time":  {scans: []pt.Scan{{ID: "s-aws", State: "completed", StartedAt: scanStart}}, err: "no completed_at"},
		"completed in the future":   {scans: []pt.Scan{{ID: "s-aws", State: "completed", StartedAt: scanStart, CompletedAt: clock.Add(time.Hour)}}, err: "in the future"},
		"a little clock skew is ok": {scans: []pt.Scan{{ID: "s-aws", State: "completed", StartedAt: scanStart, CompletedAt: clock.Add(time.Minute)}}, complete: true, scan: "s-aws"},
		"stale": {scans: []pt.Scan{{ID: "s-aws", State: "completed", StartedAt: scanStart.Add(-72 * time.Hour), CompletedAt: scanDone.Add(-72 * time.Hour)}},
			scan: "s-aws", reason: "is stale"},
		"just inside max-scan-age": {scans: []pt.Scan{{ID: "s-aws", State: "completed", StartedAt: scanStart, CompletedAt: clock.Add(-48 * time.Hour)}}, complete: true, scan: "s-aws"},
		"two completed, the newer wins": {scans: []pt.Scan{older, {ID: "s-aws", State: "completed", StartedAt: scanStart, CompletedAt: scanDone}},
			complete: true, scan: "s-aws"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := world(t)
			srv.Scans = srv.Scans[:0]
			for _, s := range tc.scans {
				s.ProviderID = "p-aws"
				srv.Scans = append(srv.Scans, s)
			}
			// The fake serves the findings of scan s-aws whichever scan is meant.
			run := collectAWS(t, srv, nil)
			if tc.err != "" {
				if run.Err == nil || !strings.Contains(run.Err.Error(), tc.err) || run.Request != nil {
					t.Fatalf("err %v request %v", run.Err, run.Request)
				}
				return
			}
			mustValid(t, run)
			if run.Complete() != tc.complete || run.ScanID != tc.scan || (tc.reason != "" && !hasReason(run, tc.reason)) {
				t.Fatalf("complete %v scan %s reasons %v", run.Complete(), run.ScanID, run.Reasons)
			}
			if !tc.complete && run.Request.Complete {
				t.Fatal("an incomplete run claims completeness")
			}
			if tc.reason == "is stale" && !run.Request.ObservedAt.Equal(scanDone.Add(-72*time.Hour)) {
				t.Fatalf("observed_at %v", run.Request.ObservedAt)
			}
		})
	}
}

func TestDisconnectedProviderPostsIncomplete(t *testing.T) {
	for _, omit := range []bool{false, true} {
		srv := world(t)
		srv.Providers[1].Connected, srv.Providers[1].OmitConnection = false, omit
		run := collectAWS(t, srv, nil)
		mustValid(t, run)
		if run.Complete() || !hasReason(run, "not connected") || len(run.Request.Findings) != 5 {
			t.Fatalf("omit=%v complete %v reasons %v", omit, run.Complete(), run.Reasons)
		}
	}
}

func TestAPIFailureMidRunPostsWhatWasGatheredAsIncomplete(t *testing.T) {
	srv := world(t)
	srv.Intercept = func(r *http.Request, n int) *pt.Reply {
		if r.URL.Path == "/api/v1/findings/latest" && n >= 2 {
			return &pt.Reply{Status: 500, Body: `{"errors":[{"status":"500","code":"error","detail":"db down"}]}`}
		}
		return nil
	}
	run := collectAWS(t, srv, nil)
	mustValid(t, run)
	if run.Complete() || run.Err != nil || len(run.Request.Findings) != 2 || !hasReason(run, "fetching findings failed") {
		t.Fatalf("complete %v err %v findings %d reasons %v", run.Complete(), run.Err, len(run.Request.Findings), run.Reasons)
	}
	// Failing on the first page leaves nothing to post.
	srv.Intercept = func(r *http.Request, n int) *pt.Reply {
		if r.URL.Path == "/api/v1/findings/latest" {
			return &pt.Reply{Status: 500, Body: `{}`}
		}
		return nil
	}
	run = collectAWS(t, srv, nil)
	if run.Request != nil || run.Err == nil || !hasReason(run, "fetching findings failed") {
		t.Fatalf("%+v", run)
	}
}

func TestThrottlingIsRiddenOut(t *testing.T) {
	srv := world(t)
	srv.Intercept = func(r *http.Request, n int) *pt.Reply {
		if r.URL.Path == "/api/v1/findings/latest" && n == 2 {
			return &pt.Reply{Status: 429, Header: map[string]string{"Retry-After": "3"}}
		}
		return nil
	}
	if run := collectAWS(t, srv, nil); !run.Complete() || len(run.Request.Findings) != 5 {
		t.Fatalf("%v %v", run.Complete(), run.Reasons)
	}
}

func TestOversizePageIsIncomplete(t *testing.T) {
	srv := world(t)
	srv.Intercept = func(r *http.Request, n int) *pt.Reply {
		if r.URL.Path == "/api/v1/findings/latest" && n == 2 {
			return &pt.Reply{Status: 200, Body: `{"data":[],"meta":"` + strings.Repeat("x", 6000) + `"}`}
		}
		return nil
	}
	c, _ := newClient(t, srv, func(c *prowlerapp.Config) { c.MaxResponseBytes = 4500 })
	col := prowlerapp.NewCollector(c, prowlerapp.Options{Now: func() time.Time { return clock }})
	run := col.Collect(context.Background(), prowlerapp.Provider{ID: "p-aws", Type: "aws", UID: "123456789012", Connected: true})
	mustValid(t, run)
	if run.Complete() || len(run.Request.Findings) != 2 || !hasReason(run, "larger than the allowed size") {
		t.Fatalf("complete %v findings %d reasons %v", run.Complete(), len(run.Request.Findings), run.Reasons)
	}
}

func TestANewerScanCompletingMidRunForbidsACompleteRun(t *testing.T) {
	srv := world(t)
	srv.Intercept = func(r *http.Request, n int) *pt.Reply {
		if r.URL.Path == "/api/v1/findings/latest" && n == 2 {
			srv.Mutate(func(s *pt.Server) {
				s.Scans = append(s.Scans, pt.Scan{ID: "s-new", ProviderID: "p-aws", State: "completed", StartedAt: clock.Add(-time.Minute), CompletedAt: clock})
			})
		}
		return nil
	}
	run := collectAWS(t, srv, nil)
	mustValid(t, run)
	if run.Complete() || !hasReason(run, "newer scan completed") {
		t.Fatalf("%v %v", run.Complete(), run.Reasons)
	}
	// A scan that merely started does not matter: the latest findings are still the completed scan's.
	srv = world(t)
	srv.Intercept = func(r *http.Request, n int) *pt.Reply {
		if r.URL.Path == "/api/v1/findings/latest" && n == 2 {
			srv.Mutate(func(s *pt.Server) {
				s.Scans = append(s.Scans, pt.Scan{ID: "s-run", ProviderID: "p-aws", State: "executing", StartedAt: clock.Add(-time.Minute)})
			})
		}
		return nil
	}
	if run := collectAWS(t, srv, nil); !run.Complete() {
		t.Fatalf("%v", run.Reasons)
	}
}

func TestSparseFieldsetsFallBackWhenRefused(t *testing.T) {
	srv := world(t)
	srv.RejectSparse = true
	run := collectAWS(t, srv, nil)
	mustValid(t, run)
	if !run.Complete() || len(run.Request.Findings) != 5 {
		t.Fatalf("%v %v", run.Complete(), run.Reasons)
	}
	var first, second string
	for _, r := range srv.Requests() {
		if strings.HasPrefix(r, "GET /api/v1/findings/latest") {
			if first == "" {
				first = r
			} else if second == "" {
				second = r
			}
		}
	}
	if !strings.Contains(first, "fields%5B") || strings.Contains(second, "fields%5B") {
		t.Fatalf("first %s second %s", first, second)
	}
}

func manyFindings(srv *pt.Server, n int, sev func(i int) string, desc string) {
	srv.PageSize = 100
	srv.Findings = srv.Findings[:0]
	srv.Resources = srv.Resources[:0]
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("m%05d", i)
		srv.Resources = append(srv.Resources, pt.Resource{ID: id, UID: "arn:aws:s3:::" + id, Region: "us-east-1", Service: "s3", Type: "AwsS3Bucket"})
		srv.Findings = append(srv.Findings, pt.Finding{ID: id, UID: id, ProviderID: "p-aws", ScanID: "s-aws", CheckID: "s3_public", CheckTitle: "t",
			Severity: sev(i), Status: "FAIL", StatusExtended: desc, ResourceIDs: []string{id}})
	}
}

func TestRunOverTheCapIsIncompleteAndKeepsTheMostSevere(t *testing.T) {
	srv := world(t)
	manyFindings(srv, 11, func(i int) string {
		if i%4 == 0 {
			return "critical"
		}
		return "medium"
	}, "x")
	run := collectAWS(t, srv, func(o *prowlerapp.Options) { o.MaxFindings = 10 })
	mustValid(t, run)
	if run.Complete() || !hasReason(run, "raise --min-severity") || len(run.Request.Findings) != 10 || run.Total != 11 {
		t.Fatalf("complete %v findings %d total %d reasons %v", run.Complete(), len(run.Request.Findings), run.Total, run.Reasons)
	}
	crit := 0
	for _, f := range run.Request.Findings {
		if f.Severity == model.SeverityCritical {
			crit++
		}
	}
	if crit != 3 {
		t.Fatalf("%d critical findings kept, want all 3", crit)
	}
	// A run exactly at the cap is complete.
	srv = world(t)
	manyFindings(srv, 10, func(int) string { return "high" }, "x")
	if run := collectAWS(t, srv, func(o *prowlerapp.Options) { o.MaxFindings = 10 }); !run.Complete() || len(run.Request.Findings) != 10 {
		t.Fatalf("%v %v", run.Complete(), run.Reasons)
	}
}

func TestHugeEstateStopsReadingOnceOverTheCap(t *testing.T) {
	srv := world(t)
	manyFindings(srv, 600, func(int) string { return "high" }, "x")
	run := collectAWS(t, srv, func(o *prowlerapp.Options) { o.MaxFindings = 100 })
	mustValid(t, run)
	if run.Complete() || len(run.Request.Findings) != 100 || srv.Count("/api/v1/findings/latest") > 3 {
		t.Fatalf("complete %v findings %d pages %d", run.Complete(), len(run.Request.Findings), srv.Count("/api/v1/findings/latest"))
	}
}

func TestRunOverTheBodyLimitIsCutAndIncomplete(t *testing.T) {
	srv := world(t)
	big := strings.Repeat("d", 7000)
	manyFindings(srv, 1800, func(i int) string {
		if i < 100 {
			return "critical"
		}
		return "high"
	}, big)
	run := collectAWS(t, srv, nil)
	mustValid(t, run)
	body, _ := json.Marshal(run.Request)
	if run.Complete() || len(body) > ingest.MaxBodyBytes || !hasReason(run, "exceed 10 MiB") || len(run.Request.Findings) >= 1800 {
		t.Fatalf("complete %v body %d findings %d reasons %v", run.Complete(), len(body), len(run.Request.Findings), run.Reasons)
	}
	crit := 0
	for _, f := range run.Request.Findings {
		if f.Severity == model.SeverityCritical {
			crit++
		}
	}
	if crit != 100 {
		t.Fatalf("%d critical kept", crit)
	}
}

func TestDuplicateKeysAreMergedWithoutLosingCompleteness(t *testing.T) {
	srv := world(t)
	dup := awsFinding(1)
	dup.ID, dup.Severity = "dup", "critical"
	srv.Findings = append(srv.Findings, dup)
	run := collectAWS(t, srv, nil)
	mustValid(t, run)
	if !run.Complete() || run.Merged != 1 || len(run.Request.Findings) != 5 || run.Request.Findings[0].Severity != model.SeverityCritical {
		t.Fatalf("complete %v merged %d findings %d", run.Complete(), run.Merged, len(run.Request.Findings))
	}
}

func TestEmptyCompleteRunIsValid(t *testing.T) {
	srv := world(t)
	srv.Findings = srv.Findings[:0]
	run := collectAWS(t, srv, nil)
	mustValid(t, run)
	if !run.Complete() || run.Request.Findings == nil || len(run.Request.Findings) != 0 {
		t.Fatalf("%+v", run)
	}
}

func TestRequestBodyIsIdenticalForTheSameScan(t *testing.T) {
	a, b := world(t), world(t)
	b.PageSize = 3 // different paging, same data
	ra, rb := collectAWS(t, a, nil), collectAWS(t, b, nil)
	ja, _ := json.Marshal(ra.Request)
	jb, _ := json.Marshal(rb.Request)
	if string(ja) != string(jb) {
		t.Fatal("re-posting the same scan must produce the same body, so the server sees a replay")
	}
}
