package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	pt "github.com/chainseer-xyz/deckard/internal/ingest/prowlerapp/prowlerapptest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

const (
	paKey      = "pk-PROWLER-KEY-NEVER-PRINT-5b1e"
	paEmail    = "ops-NEVER-PRINT@example.com"
	paPassword = "pw-PROWLER-PASSWORD-NEVER-PRINT-77"
)

var paNow = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// paEnv is the environment of a prowler-app run: every credential is set, and
// runPA fails the test if any of them shows up in an output or a posted body.
func paEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PROWLER_TEST_KEY", paKey)
	t.Setenv("PROWLER_TEST_EMAIL", paEmail)
	t.Setenv("PROWLER_TEST_PASSWORD", paPassword)
	t.Setenv("DECKARD_TEST_TOKEN", testIngestToken)
	prowlerAppNow = func() time.Time { return paNow }
	prowlerAppSleep = func(context.Context, time.Duration) error { return nil }
	backoffUnit = time.Millisecond
	t.Cleanup(func() {
		prowlerAppNow, prowlerAppSleep, backoffUnit = time.Now, nil, time.Second
	})
}

func runPA(t *testing.T, bodies [][]byte, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(append([]string{"ingest", "prowler-app"}, args...), &out, &errb)
	all := out.String() + errb.String()
	for _, b := range bodies {
		all += string(b)
	}
	for _, secret := range []string{paKey, paEmail, paPassword, testIngestToken, "jwt-access-token"} {
		if strings.Contains(all, secret) {
			t.Fatalf("a credential leaked (%q...):\nstdout: %s\nstderr: %s", secret[:6], out.String(), errb.String())
		}
	}
	return code, out.String(), errb.String()
}

// base are the flags every post test uses.
func paBase(prowlerURL, deckardURL string) []string {
	return []string{"--api-url", prowlerURL, "--api-key-env", "PROWLER_TEST_KEY", "--url", deckardURL + "/base/", "--token-env", "DECKARD_TEST_TOKEN"}
}

const okReply = `{"accepted":%d,"opened":%d,"reopened":0,"refreshed":0,"resolved_pending":0,"resolved":0,"complete":true,"replay":false,"rejected":[]}`

func okFor(n int) func(http.ResponseWriter) { return reply(200, fmt.Sprintf(okReply, n, n)) }

func decodeBodies(t *testing.T, bodies [][]byte) []*ingest.Request {
	t.Helper()
	var out []*ingest.Request
	for _, b := range bodies {
		r, err := ingest.Decode(b)
		if err != nil {
			t.Fatalf("posted body is not a request: %v\n%s", err, b)
		}
		if p := ingest.Validate(r, ingest.Options{Now: paNow}); len(p) > 0 {
			t.Fatalf("posted request invalid: %s", ingest.Summary(p))
		}
		out = append(out, r)
	}
	return out
}

func TestProwlerAppPostsEveryProviderAndSummarizesOnStdout(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, paKey, paNow.Add(-3*time.Hour))
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){okFor(5), okFor(1)}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	code, out, errs := runPA(t, nil, paBase(prowler.URL, dk.URL)...)
	if code != 0 || errs != "" {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	reqs := decodeBodies(t, fd.bodies)
	if len(reqs) != 2 || reqs[0].Scope != "aws:123456789012" || reqs[1].Scope != "gcp:my-project" {
		t.Fatalf("%+v", reqs)
	}
	for _, r := range reqs {
		if !r.Complete || r.Tool != "prowler" || !r.ObservedAt.After(paNow.Add(-4*time.Hour)) {
			t.Fatalf("%+v", r)
		}
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "scope=aws:123456789012 scan=s-aws findings=5 complete=true posted=true accepted=5 opened=5") ||
		!strings.Contains(lines[1], "scope=gcp:my-project scan=s-gcp findings=1 complete=true") {
		t.Fatalf("summary:\n%s", out)
	}
}

func TestProwlerAppProviderFilters(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, paKey, paNow.Add(-3*time.Hour))
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){okFor(1)}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	code, out, errs := runPA(t, nil, append(paBase(prowler.URL, dk.URL), "--provider-type", "GCP, azure")...)
	if code != 0 || len(fd.bodies) != 1 || !strings.Contains(out, "scope=gcp:my-project") || strings.Contains(out, "aws") {
		t.Fatalf("exit %d out %q err %q", code, out, errs)
	}
	code, _, errs = runPA(t, nil, append(paBase(prowler.URL, dk.URL), "--provider-uid", "nope")...)
	if code != ingestExitUsage || !strings.Contains(errs, "no Prowler provider matches") {
		t.Fatalf("exit %d: %s", code, errs)
	}
}

func TestProwlerAppDryRunPrintsValidRequestsWithoutPostingOrSecrets(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, paKey, paNow.Add(-3*time.Hour))
	prowler.PlantSecrets = true
	// No deckard URL or token at all: a dry run needs neither.
	code, out, errs := runPA(t, nil, "--api-url", prowler.URL, "--api-key-env", "PROWLER_TEST_KEY", "--dry-run", "-v")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	dec := json.NewDecoder(strings.NewReader(out))
	n := 0
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			t.Fatalf("stdout is not a stream of requests: %v\n%s", err, out)
		}
		decodeBodies(t, [][]byte{raw})
		n++
	}
	if n != 2 || strings.Contains(out, "prowler-app:") {
		t.Fatalf("%d requests; summary lines belong on stderr in a dry run:\n%s", n, out)
	}
	if !strings.Contains(errs, "scope=aws:123456789012") || !strings.Contains(errs, "posted=false") {
		t.Fatalf("stderr %q", errs)
	}
	for _, planted := range []string{pt.SecretRaw, pt.SecretTag, pt.SecretMeta} {
		if strings.Contains(out+errs, planted) {
			t.Fatalf("%s leaked", planted)
		}
	}
}

func TestProwlerAppStaleScanPostsIncompleteAndExits4(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, paKey, paNow.Add(-72*time.Hour))
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){okFor(5), okFor(1)}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	code, out, errs := runPA(t, nil, paBase(prowler.URL, dk.URL)...)
	reqs := decodeBodies(t, fd.bodies)
	if code != ingestExitIncomplete || len(reqs) != 2 || reqs[0].Complete || reqs[1].Complete {
		t.Fatalf("exit %d, %d requests", code, len(reqs))
	}
	if !strings.Contains(errs, "is stale") || !strings.Contains(out, "complete=false") || !strings.Contains(out, `reason="`) {
		t.Fatalf("out %q err %q", out, errs)
	}
	// --max-scan-age raises the bar.
	fd.n.Store(0)
	fd.bodies = nil
	code, _, _ = runPA(t, nil, append(paBase(prowler.URL, dk.URL), "--max-scan-age", "100h")...)
	if reqs = decodeBodies(t, fd.bodies); code != 0 || !reqs[0].Complete {
		t.Fatalf("exit %d complete %v", code, reqs[0].Complete)
	}
}

func TestProwlerAppDisconnectedProviderPostsIncomplete(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, paKey, paNow.Add(-3*time.Hour))
	prowler.Providers[1].Connected = false
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){okFor(5), okFor(1)}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	code, _, errs := runPA(t, nil, paBase(prowler.URL, dk.URL)...)
	reqs := decodeBodies(t, fd.bodies)
	if code != ingestExitIncomplete || reqs[0].Complete || !reqs[1].Complete || !strings.Contains(errs, "not connected") {
		t.Fatalf("exit %d complete %v %v: %s", code, reqs[0].Complete, reqs[1].Complete, errs)
	}
}

func TestProwlerAppProviderWithoutAUsableScanIsReportedAndTheOthersStillPost(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, paKey, paNow.Add(-3*time.Hour))
	prowler.Scans = prowler.Scans[2:] // the AWS account has never completed a scan
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){okFor(1)}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	code, out, errs := runPA(t, nil, paBase(prowler.URL, dk.URL)...)
	if code != ingestExitIncomplete || len(fd.bodies) != 1 || !strings.Contains(out, "scope=aws:123456789012 scan=- findings=0 complete=false posted=false") ||
		!strings.Contains(errs, "no scan has run") {
		t.Fatalf("exit %d out %q err %q", code, out, errs)
	}
}

func TestProwlerAppAPIFailureOnPage2PostsPartialIncompleteAndExits4(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, paKey, paNow.Add(-3*time.Hour))
	prowler.Intercept = func(r *http.Request, n int) *pt.Reply {
		if r.URL.Path == "/api/v1/findings/latest" && n >= 2 && n <= 5 { // page 2 of AWS, every retry
			return &pt.Reply{Status: 500, Body: `{"errors":[{"status":"500","code":"error","detail":"db down"}]}`}
		}
		return nil
	}
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){okFor(2), okFor(1)}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	code, out, errs := runPA(t, nil, paBase(prowler.URL, dk.URL)...)
	reqs := decodeBodies(t, fd.bodies)
	if code != ingestExitIncomplete || len(reqs) != 2 || reqs[0].Complete || len(reqs[0].Findings) != 2 || !reqs[1].Complete {
		t.Fatalf("exit %d out %q err %q", code, out, errs)
	}
	if !strings.Contains(errs, "fetching findings failed") || !strings.Contains(errs, "db down") {
		t.Fatalf("err %q", errs)
	}
}

func TestProwlerAppRejectedCredentialsAreAClearConfigErrorWithoutTheKey(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, "some-other-key", paNow)
	prowler.EchoCredentials = true
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){okFor(0)}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	code, out, errs := runPA(t, fd.bodies, append(paBase(prowler.URL, dk.URL), "-v")...) // runPA fails the test if the key shows up
	if code != ingestExitUsage || !strings.Contains(errs, "401") || !strings.Contains(errs, "list providers") || fd.n.Load() != 0 {
		t.Fatalf("exit %d out %q err %q", code, out, errs)
	}
	// Mid-run revocation: the first provider listing works, the scan lookups do not.
	prowler = pt.Sample(t, paKey, paNow)
	prowler.Intercept = func(r *http.Request, n int) *pt.Reply {
		if r.URL.Path == "/api/v1/scans" {
			return &pt.Reply{Status: 403, Body: `{"errors":[{"status":"403","code":"permission_denied","detail":"nope ` + paKey + `"}]}`}
		}
		return nil
	}
	code, _, errs = runPA(t, fd.bodies, paBase(prowler.URL, dk.URL)...)
	if code != ingestExitUsage || !strings.Contains(errs, "refused the credentials") || fd.n.Load() != 0 {
		t.Fatalf("exit %d err %q", code, errs)
	}
}

func TestProwlerAppJWTLoginPath(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, "", paNow.Add(-3*time.Hour))
	prowler.Email, prowler.Password = paEmail, paPassword
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){okFor(5), okFor(1)}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	args := []string{"--api-url", prowler.URL, "--email-env", "PROWLER_TEST_EMAIL", "--password-env", "PROWLER_TEST_PASSWORD",
		"--url", dk.URL + "/base", "--token-env", "DECKARD_TEST_TOKEN", "-v"}
	code, _, errs := runPA(t, fd.bodies, args...)
	if code != 0 || prowler.Count("/api/v1/tokens") != 1 || len(fd.bodies) != 2 {
		t.Fatalf("exit %d logins %d: %s", code, prowler.Count("/api/v1/tokens"), errs)
	}
	// A wrong password is a configuration error and says nothing about the password.
	t.Setenv("PROWLER_TEST_PASSWORD", "wrong-PASSWORD-NEVER-PRINT")
	var out, errb bytes.Buffer
	code = run(append([]string{"ingest", "prowler-app"}, args...), &out, &errb)
	if code != ingestExitUsage || strings.Contains(out.String()+errb.String(), "wrong-PASSWORD-NEVER-PRINT") || !strings.Contains(errb.String(), "login") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
}

func TestProwlerAppThrottlingIsRiddenOut(t *testing.T) {
	paEnv(t)
	var slept []time.Duration
	prowlerAppSleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	prowler := pt.Sample(t, paKey, paNow.Add(-3*time.Hour))
	prowler.Intercept = func(r *http.Request, n int) *pt.Reply {
		if r.URL.Path == "/api/v1/scans" && n == 1 {
			return &pt.Reply{Status: 429, Header: map[string]string{"Retry-After": "11"}}
		}
		return nil
	}
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){okFor(5), okFor(1)}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	code, _, errs := runPA(t, nil, paBase(prowler.URL, dk.URL)...)
	if code != 0 || len(slept) != 1 || slept[0] != 11*time.Second {
		t.Fatalf("exit %d sleeps %v: %s", code, slept, errs)
	}
}

func TestProwlerAppUnreachableServices(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, paKey, paNow.Add(-3*time.Hour))
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	// Prowler down: nothing to pull.
	code, _, errs := runPA(t, nil, paBase(closedURL, "http://127.0.0.1:1")...)
	if code != ingestExitNetwork || !strings.Contains(errs, "list providers") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	// deckard down: every provider fails to post.
	code, out, errs := runPA(t, nil, paBase(prowler.URL, closedURL)...)
	if code != ingestExitNetwork || strings.Count(out, "posted=false") != 2 || !strings.Contains(errs, "could not reach deckard") {
		t.Fatalf("exit %d out %q err %q", code, out, errs)
	}
}

func TestProwlerAppDeckardRejectionWinsButDoesNotStopTheOtherProviders(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, paKey, paNow.Add(-3*time.Hour))
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){
		reply(422, `{"error":{"code":"invalid_request","message":"request rejected"},"rejected":[{"index":0,"reason":"bad severity"}]}`),
		okFor(1),
	}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	code, out, errs := runPA(t, nil, paBase(prowler.URL, dk.URL)...)
	if code != ingestExitRejected || len(fd.bodies) != 2 || !strings.Contains(errs, "findings[0]: bad severity") ||
		!strings.Contains(out, "scope=gcp:my-project scan=s-gcp findings=1 complete=true posted=true") {
		t.Fatalf("exit %d out %q err %q", code, out, errs)
	}
}

func TestProwlerAppReplayAndServerDowngradeAreHarmless(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, paKey, paNow.Add(-3*time.Hour))
	replay := `{"accepted":0,"opened":0,"reopened":0,"refreshed":0,"resolved_pending":0,"resolved":0,"complete":false,"replay":true,"note":"same request","rejected":[]}`
	downgraded := `{"accepted":1,"opened":0,"reopened":0,"refreshed":1,"resolved_pending":0,"resolved":0,"complete":false,"replay":false,"note":"observed_at is not newer than an accepted run","rejected":[]}`
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){reply(200, replay), reply(200, downgraded)}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	code, out, errs := runPA(t, nil, paBase(prowler.URL, dk.URL)...)
	if code != 0 || !strings.Contains(out, "replay=true") || !strings.Contains(errs, "did not apply absence") {
		t.Fatalf("exit %d out %q err %q", code, out, errs)
	}
	// A server that rejected items is a failure.
	partial := `{"accepted":4,"opened":4,"reopened":0,"refreshed":0,"resolved_pending":0,"resolved":0,"complete":false,"replay":false,"note":"1 item(s) rejected","rejected":[{"index":1,"reason":"asset.ref: no such asset"}]}`
	fd2 := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){reply(200, partial), okFor(1)}}
	dk2 := httptest.NewServer(fd2)
	defer dk2.Close()
	if code, _, errs = runPA(t, nil, paBase(prowler.URL, dk2.URL)...); code != ingestExitRejected || !strings.Contains(errs, "findings[1]") {
		t.Fatalf("exit %d: %s", code, errs)
	}
}

func TestProwlerAppRunOverTheCapIsIncompleteWithAClearMessage(t *testing.T) {
	paEnv(t)
	prowler := pt.Sample(t, paKey, paNow.Add(-3*time.Hour))
	prowler.PageSize = 1000
	prowler.Findings, prowler.Resources = nil, nil
	for i := 0; i < ingest.MaxFindings+50; i++ {
		id := fmt.Sprintf("m%05d", i)
		prowler.Resources = append(prowler.Resources, pt.Resource{ID: id, UID: "arn:aws:s3:::" + id})
		sev := "medium"
		if i < 10 {
			sev = "critical"
		}
		prowler.Findings = append(prowler.Findings, pt.Finding{ID: id, UID: id, ProviderID: "p-aws", ScanID: "s-aws", CheckID: "c", CheckTitle: "t",
			Severity: sev, Status: "FAIL", StatusExtended: "x", ResourceIDs: []string{id}})
	}
	fd := &fakeDeckard{t: t, replies: []func(http.ResponseWriter){okFor(ingest.MaxFindings), okFor(0)}}
	dk := httptest.NewServer(fd)
	defer dk.Close()
	code, out, errs := runPA(t, nil, append(paBase(prowler.URL, dk.URL), "--provider-type", "aws")...)
	reqs := decodeBodies(t, fd.bodies)
	if code != ingestExitIncomplete || len(reqs) != 1 || reqs[0].Complete || len(reqs[0].Findings) != ingest.MaxFindings ||
		!strings.Contains(errs, "raise --min-severity") || !strings.Contains(out, "complete=false") {
		t.Fatalf("exit %d findings %d out %q err %q", code, len(reqs[0].Findings), out, errs)
	}
	crit := 0
	for _, f := range reqs[0].Findings {
		if f.Severity == "critical" {
			crit++
		}
	}
	if crit != 10 {
		t.Fatalf("%d critical findings kept of 10", crit)
	}
}

func TestProwlerAppUsageErrors(t *testing.T) {
	paEnv(t)
	t.Setenv("PROWLER_EMPTY", "")
	for name, args := range map[string][]string{
		"no api url":        {"--api-key-env", "PROWLER_TEST_KEY", "--dry-run"},
		"no credentials":    {"--api-url", "http://p", "--dry-run"},
		"key env unset":     {"--api-url", "http://p", "--api-key-env", "NOPE_UNSET", "--dry-run"},
		"key env empty":     {"--api-url", "http://p", "--api-key-env", "PROWLER_EMPTY", "--dry-run"},
		"key and password":  {"--api-url", "http://p", "--api-key-env", "PROWLER_TEST_KEY", "--password-env", "PROWLER_TEST_PASSWORD", "--dry-run"},
		"email without pw":  {"--api-url", "http://p", "--email-env", "PROWLER_TEST_EMAIL", "--dry-run"},
		"api url creds":     {"--api-url", "http://u:p@p", "--api-key-env", "PROWLER_TEST_KEY", "--dry-run"},
		"api url not http":  {"--api-url", "ftp://p", "--api-key-env", "PROWLER_TEST_KEY", "--dry-run"},
		"bad severity":      {"--api-url", "http://p", "--api-key-env", "PROWLER_TEST_KEY", "--min-severity", "severe", "--dry-run"},
		"zero max age":      {"--api-url", "http://p", "--api-key-env", "PROWLER_TEST_KEY", "--max-scan-age", "0s", "--dry-run"},
		"no deckard url":    {"--api-url", "http://p", "--api-key-env", "PROWLER_TEST_KEY", "--token-env", "DECKARD_TEST_TOKEN"},
		"deckard url creds": {"--api-url", "http://p", "--api-key-env", "PROWLER_TEST_KEY", "--url", "http://u:p@d", "--token-env", "DECKARD_TEST_TOKEN"},
		"no token env":      {"--api-url", "http://p", "--api-key-env", "PROWLER_TEST_KEY", "--url", "http://d"},
		"token env empty":   {"--api-url", "http://p", "--api-key-env", "PROWLER_TEST_KEY", "--url", "http://d", "--token-env", "PROWLER_EMPTY"},
		"unknown flag":      {"--nope"},
		"stray argument":    {"--api-url", "http://p", "--api-key-env", "PROWLER_TEST_KEY", "--dry-run", "extra"},
		"key as a flag":     {"--api-key", paKey},
		"zero max requests": {"--api-url", "http://p", "--api-key-env", "PROWLER_TEST_KEY", "--max-requests", "0", "--dry-run"},
		"negative timeout":  {"--api-url", "http://p", "--api-key-env", "PROWLER_TEST_KEY", "--timeout", "-1s", "--dry-run"},
	} {
		code, out, errs := runPA(t, nil, args...)
		if code != ingestExitUsage || out != "" {
			t.Errorf("%s: exit %d stdout %q stderr %q", name, code, out, errs)
		}
	}
	if code, out, _ := runPA(t, nil, "--help"); code != 0 || !strings.Contains(out, "Exit codes") {
		t.Errorf("--help: %d %q", code, out)
	}
	if code, out, _ := runPA(t, nil); code != ingestExitUsage || out != "" {
		t.Errorf("no flags: %d", code)
	}
}

func TestWorseExit(t *testing.T) {
	for _, tc := range []struct{ a, b, want int }{{0, 4, 4}, {4, 0, 4}, {4, 3, 3}, {3, 2, 2}, {2, 4, 2}, {0, 0, 0}, {3, 3, 3}} {
		if got := worseExit(tc.a, tc.b); got != tc.want {
			t.Errorf("worseExit(%d,%d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestScrubWriterHidesEverySecret(t *testing.T) {
	var b bytes.Buffer
	s := &secretScrubber{}
	s.add("alpha-secret")
	s.add("")
	s.add("beta-secret")
	w := &scrubWriter{w: &b, s: s}
	n, err := w.Write([]byte("a alpha-secret b beta-secret c"))
	if err != nil || n != len("a alpha-secret b beta-secret c") || b.String() != "a [REDACTED] b [REDACTED] c" {
		t.Fatalf("%d %v %q", n, err, b.String())
	}
}

// rollScan completes a new scan of the AWS account at `at`: the findings now
// belong to it, as they do in Prowler after a rescan.
func rollScan(srv *pt.Server, id string, at time.Time) {
	srv.Mutate(func(s *pt.Server) {
		s.Scans = append(s.Scans, pt.Scan{ID: id, ProviderID: "p-aws", State: "completed", StartedAt: at.Add(-time.Hour), CompletedAt: at})
		for i := range s.Findings {
			if s.Findings[i].ProviderID == "p-aws" {
				s.Findings[i].ScanID = id
			}
		}
	})
}

// dropFinding removes one AWS finding (it was fixed or muted in Prowler).
func dropFinding(srv *pt.Server, id string) {
	srv.Mutate(func(s *pt.Server) {
		kept := s.Findings[:0]
		for _, f := range s.Findings {
			if f.ID != id {
				kept = append(kept, f)
			}
		}
		s.Findings = kept
	})
}

// The Prowler App connector against the real ingest handler: findings open as
// ext.prowler, a complete run without one resolves it after the usual misses,
// and a run that is incomplete for any reason never resolves anything.
func TestProwlerAppAgainstTheRealAPI(t *testing.T) {
	paEnv(t)
	prowlerAppNow = time.Now // the server validates observed_at against the real clock
	st := fakestore.New()
	handler := api.New(api.Deps{
		Store: st, Authenticator: auth.NewToken(testIngestToken), BaseURL: "https://deckard.example.com",
		Ingester: finding.NewProcessor(st, finding.ProcessorConfig{ResolveAfter: 2}, nil),
		Ingest:   config.IngestConfig{Enabled: true, RateLimit: "100/s", Burst: 100},
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	var posted [][]byte
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		posted = append(posted, b)
		r.Body = io.NopCloser(bytes.NewReader(b))
		handler.Handler().ServeHTTP(w, r)
	}))
	defer hs.Close()

	now := time.Now().UTC()
	prowler := pt.Sample(t, paKey, now.Add(-9*time.Hour))
	prowler.PlantSecrets = true
	pa := func(extra ...string) (int, string, string) {
		t.Helper()
		return runPA(t, posted, append([]string{"--api-url", prowler.URL, "--api-key-env", "PROWLER_TEST_KEY", "--url", hs.URL, "--token-env", "DECKARD_TEST_TOKEN"}, extra...)...)
	}
	status := func() map[string]model.FindingStatus { // by bucket, AWS only
		t.Helper()
		fs, _, err := st.ListFindings(context.Background(), store.FindingFilter{Check: "ext.prowler"})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]model.FindingStatus{}
		for _, f := range fs {
			if f.Source != "ingest:prowler" {
				t.Fatalf("finding %+v", f)
			}
			if f.IngestScope == "aws:123456789012" {
				out[f.AssetKey] = f.Status
			}
		}
		return out
	}
	open := func(m map[string]model.FindingStatus) (n int) {
		for _, s := range m {
			if s == model.StatusOpen {
				n++
			}
		}
		return n
	}
	bucket := func(i int) string { return fmt.Sprintf("arn:aws:s3:::bucket-%d", i) }
	missed := func(i int) int {
		t.Helper()
		fs, _, _ := st.ListFindings(context.Background(), store.FindingFilter{Check: "ext.prowler"})
		for _, f := range fs {
			if f.AssetKey == bucket(i) {
				return f.MissedRuns
			}
		}
		return -1
	}

	// Run 1: everything opens, for both providers.
	if code, out, errs := pa(); code != 0 {
		t.Fatalf("run 1: exit %d\n%s%s", code, out, errs)
	}
	fs, _, _ := st.ListFindings(context.Background(), store.FindingFilter{Check: "ext.prowler"})
	scopes := map[string]int{}
	for _, f := range fs {
		scopes[f.IngestScope]++
		if f.Check != "ext.prowler" || f.Status != model.StatusOpen {
			t.Fatalf("%+v", f)
		}
	}
	if scopes["aws:123456789012"] != 5 || scopes["gcp:my-project"] != 1 {
		t.Fatalf("scopes %v", scopes)
	}

	// The same scan again is a harmless replay.
	if code, out, errs := pa(); code != 0 || !strings.Contains(out, "replay=true") {
		t.Fatalf("replay: exit %d\n%s%s", code, out, errs)
	}

	// bucket-3 is fixed. Run 2 (a new scan, complete): one miss, still open.
	dropFinding(prowler, "f3")
	rollScan(prowler, "s-aws-2", now.Add(-8*time.Hour))
	if code, out, errs := pa(); code != 0 {
		t.Fatalf("run 2: exit %d\n%s%s", code, out, errs)
	}
	if got := status(); got[bucket(3)] != model.StatusOpen || open(got) != 5 || missed(3) != 1 {
		t.Fatalf("after one complete miss: %v, missed %d", got, missed(3))
	}

	// Run 3: Prowler's API fails on page 2. Incomplete: no miss, nothing resolves.
	prowler.Intercept = func(r *http.Request, n int) *pt.Reply {
		if r.URL.Path == "/api/v1/findings/latest" && r.URL.Query().Get("filter[provider]") == "p-aws" && r.URL.Query().Get("page[number]") == "2" {
			return &pt.Reply{Status: 500, Body: `{}`}
		}
		return nil
	}
	rollScan(prowler, "s-aws-3", now.Add(-7*time.Hour))
	if code, _, errs := pa(); code != ingestExitIncomplete || !strings.Contains(errs, "fetching findings failed") {
		t.Fatalf("run 3: exit %d: %s", code, errs)
	}
	prowler.Intercept = nil
	if got := status(); got[bucket(3)] != model.StatusOpen || open(got) != 5 || missed(3) != 1 || missed(4) != 0 {
		t.Fatalf("an incomplete run (API failure) changed the lifecycle: %v, missed %d/%d", got, missed(3), missed(4))
	}

	// Run 4: a stale scan is incomplete too, even though bucket-3 is still absent.
	rollScan(prowler, "s-aws-4", now.Add(-6*time.Hour))
	if code, _, errs := pa("--max-scan-age", "1h"); code != ingestExitIncomplete || !strings.Contains(errs, "is stale") {
		t.Fatalf("run 4: exit %d: %s", code, errs)
	}
	if got := status(); got[bucket(3)] != model.StatusOpen {
		t.Fatalf("a stale scan resolved a finding: %v", got)
	}

	// Run 5: a disconnected provider, likewise.
	rollScan(prowler, "s-aws-5", now.Add(-5*time.Hour))
	prowler.Mutate(func(s *pt.Server) { s.Providers[1].Connected = false })
	if code, _, errs := pa(); code != ingestExitIncomplete || !strings.Contains(errs, "not connected") {
		t.Fatalf("run 5: exit %d: %s", code, errs)
	}
	prowler.Mutate(func(s *pt.Server) { s.Providers[1].Connected = true })
	if got := status(); got[bucket(3)] != model.StatusOpen {
		t.Fatalf("a disconnected provider resolved a finding: %v", got)
	}

	// Run 6: a failed scan newer than the completed one: incomplete.
	prowler.Mutate(func(s *pt.Server) {
		s.Scans = append(s.Scans, pt.Scan{ID: "s-failed", ProviderID: "p-aws", State: "failed", StartedAt: now.Add(-4 * time.Hour)})
	})
	if code, _, errs := pa(); code != ingestExitIncomplete || !strings.Contains(errs, "latest scan s-failed is failed") {
		t.Fatalf("run 6: exit %d: %s", code, errs)
	}
	if got := status(); got[bucket(3)] != model.StatusOpen {
		t.Fatalf("a failed scan resolved a finding: %v", got)
	}

	// Run 7: a healthy complete scan without bucket-3: the second complete miss resolves it.
	prowler.Mutate(func(s *pt.Server) { s.Scans = s.Scans[:len(s.Scans)-1] })
	rollScan(prowler, "s-aws-7", now.Add(-3*time.Hour))
	if code, out, errs := pa(); code != 0 {
		t.Fatalf("run 7: exit %d\n%s%s", code, out, errs)
	}
	got := status()
	if got[bucket(3)] != model.StatusResolved || open(got) != 4 {
		t.Fatalf("after the second complete miss: %v", got)
	}
	// The other provider was never touched by any of this.
	for _, f := range func() []model.Finding {
		fs, _, _ := st.ListFindings(context.Background(), store.FindingFilter{Check: "ext.prowler"})
		return fs
	}() {
		if f.IngestScope == "gcp:my-project" && f.Status != model.StatusOpen {
			t.Fatalf("gcp finding %+v", f)
		}
	}
}
