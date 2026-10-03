package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/prowlerapp"
)

// Clock and sleeper of `deckard ingest prowler-app` (variables for tests).
var (
	prowlerAppNow   = time.Now
	prowlerAppSleep func(ctx context.Context, d time.Duration) error // nil: really sleep
)

// ingestPostTimeout bounds one post of a provider's run, retries included.
const ingestPostTimeout = 2 * time.Minute

const prowlerAppUsage = `usage: deckard ingest prowler-app --api-url <Prowler API URL> (--api-key-env <VAR> | --email-env <VAR> --password-env <VAR>)
                                  --url <deckard base URL> --token-env <VAR>
                                  [--provider-type aws,gcp,...] [--provider-uid <id>,...]
                                  [--min-severity medium] [--max-scan-age 48h] [--include-muted=false]
                                  [--dry-run] [--timeout 15m] [--max-requests 1000] [--proxy-from-env] [-v]

Pulls the latest scan of every provider of a running Prowler App (its REST API) and posts the failing
findings to deckard's ingest API, one run per provider, scope <provider type>:<provider uid>.
deckard never runs Prowler and never touches the scanned accounts.

Credentials come only from environment variables, named by the *-env flags:
  --api-key-env      Prowler API key (preferred; a read-only role is enough)
  --email-env, --password-env   a Prowler user, exchanged for a JWT (alternative to the key)
  --token-env        deckard API token (not needed with --dry-run)

A run is posted complete (so that fixed findings can resolve) only when the provider is connected, its
latest scan is completed and newer than --max-scan-age, every page was read, nothing was unmappable
and the run fits in one request. Otherwise it is posted incomplete (nothing resolves) and the reason
is printed. Findings below --min-severity are not reported, so they are not part of a complete run.

  --dry-run          print the request of each provider (never a credential) to stdout and the
                     summary lines to stderr; post nothing
  --proxy-from-env   honour HTTP_PROXY/HTTPS_PROXY for the Prowler API (off by default)

Exit codes: 0 every provider posted complete (or the server replayed it), 1 usage, configuration or
credential error, 2 deckard rejected a request, 3 a service could not be reached, 4 something was posted
incomplete or could not be pulled because of a condition in Prowler (stale or failed scan, disconnected
provider, run over the cap, ...). With several providers the worst code wins (2 over 3 over 4).
One summary line per provider goes to stdout. See docs/ingest.md.
`

type prowlerAppFlags struct {
	apiURL, apiKeyEnv, emailEnv, passwordEnv string
	url, tokenEnv                            string
	providerTypes, providerUIDs              string
	minSeverity                              string
	maxScanAge, timeout                      time.Duration
	maxRequests                              int
	includeMuted, dryRun, proxyFromEnv       bool
	verbose                                  bool
}

func runIngestProwlerApp(args []string, stdout, stderr io.Writer) int {
	var f prowlerAppFlags
	fs := flag.NewFlagSet("ingest prowler-app", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.apiURL, "api-url", "", "Prowler App API base URL")
	fs.StringVar(&f.apiKeyEnv, "api-key-env", "", "environment variable holding the Prowler API key")
	fs.StringVar(&f.emailEnv, "email-env", "", "environment variable holding a Prowler user's email")
	fs.StringVar(&f.passwordEnv, "password-env", "", "environment variable holding that user's password")
	fs.StringVar(&f.url, "url", "", "deckard base URL")
	fs.StringVar(&f.tokenEnv, "token-env", "", "environment variable holding the deckard API token")
	fs.StringVar(&f.providerTypes, "provider-type", "", "only these provider types (comma separated: aws,gcp,azure,github,kubernetes,...)")
	fs.StringVar(&f.providerUIDs, "provider-uid", "", "only these provider uids (account ids, project ids, ...)")
	fs.StringVar(&f.minSeverity, "min-severity", "medium", "lowest severity to report: info, low, medium, high, critical")
	fs.DurationVar(&f.maxScanAge, "max-scan-age", 48*time.Hour, "a scan older than this never makes a complete run")
	fs.BoolVar(&f.includeMuted, "include-muted", false, "also report findings muted in Prowler")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print the requests instead of posting them")
	fs.DurationVar(&f.timeout, "timeout", 15*time.Minute, "overall time limit of the whole run")
	fs.IntVar(&f.maxRequests, "max-requests", prowlerapp.DefaultMaxRequests, "request budget against the Prowler API for the whole run")
	fs.BoolVar(&f.proxyFromEnv, "proxy-from-env", false, "use HTTP(S)_PROXY from the environment for the Prowler API")
	fs.BoolVar(&f.verbose, "v", false, "verbose progress on stderr")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(stdout, prowlerAppUsage)
			return ingestExitOK
		}
		_, _ = fmt.Fprintf(stderr, "deckard ingest prowler-app: %v\n\n%s", err, prowlerAppUsage)
		return ingestExitUsage
	}

	// Credentials are read once, only from the environment, and scrubbed from
	// everything this command prints.
	secrets := &secretScrubber{}
	read := func(name string) string {
		if name == "" {
			return ""
		}
		v := os.Getenv(name)
		secrets.add(v)
		return v
	}
	apiKey, email, password, token := read(f.apiKeyEnv), read(f.emailEnv), read(f.passwordEnv), read(f.tokenEnv)
	out := &scrubWriter{w: stdout, s: secrets}
	errw := &scrubWriter{w: stderr, s: secrets}
	fail := func(code int, format string, a ...any) int {
		_, _ = fmt.Fprintf(errw, "deckard ingest prowler-app: "+format+"\n", a...)
		return code
	}

	if fs.NArg() > 0 {
		return fail(ingestExitUsage, "unexpected argument %q\n\n%s", fs.Arg(0), prowlerAppUsage)
	}
	if strings.TrimSpace(f.apiURL) == "" {
		return fail(ingestExitUsage, "--api-url is required (the Prowler App API base URL)\n\n%s", prowlerAppUsage)
	}
	switch {
	case f.apiKeyEnv != "" && (f.emailEnv != "" || f.passwordEnv != ""):
		return fail(ingestExitUsage, "give either --api-key-env or --email-env with --password-env, not both")
	case f.apiKeyEnv != "":
		if apiKey == "" {
			return fail(ingestExitUsage, "environment variable %s is empty or unset", f.apiKeyEnv)
		}
	case f.emailEnv != "" && f.passwordEnv != "":
		if email == "" || password == "" {
			return fail(ingestExitUsage, "environment variables %s and %s must both be set", f.emailEnv, f.passwordEnv)
		}
	default:
		return fail(ingestExitUsage, "Prowler credentials are required: --api-key-env <VAR>, or --email-env <VAR> with --password-env <VAR> (the names of variables, never the secrets)")
	}
	floor, err := prowlerapp.ParseSeverityFloor(f.minSeverity)
	if err != nil {
		return fail(ingestExitUsage, "%v", err)
	}
	switch {
	case f.maxScanAge <= 0:
		return fail(ingestExitUsage, "--max-scan-age must be positive")
	case f.timeout <= 0:
		return fail(ingestExitUsage, "--timeout must be positive")
	case f.maxRequests <= 0:
		return fail(ingestExitUsage, "--max-requests must be positive")
	}
	var endpoint string
	if !f.dryRun {
		if endpoint, err = ingestEndpoint(f.url); err != nil {
			return fail(ingestExitUsage, "%v", err)
		}
		switch {
		case f.tokenEnv == "":
			return fail(ingestExitUsage, "--token-env is required (the name of the variable holding the deckard token, never the token)")
		case token == "":
			return fail(ingestExitUsage, "environment variable %s is empty or unset", f.tokenEnv)
		}
	}

	logf := func(string, ...any) {}
	if f.verbose {
		logf = func(format string, a ...any) {
			_, _ = fmt.Fprintf(errw, "deckard ingest prowler-app: "+format+"\n", a...)
		}
	}
	client, err := prowlerapp.NewClient(prowlerapp.Config{
		BaseURL: f.apiURL, APIKey: apiKey, Email: email, Password: password,
		UseEnvProxy: f.proxyFromEnv, MaxRequests: f.maxRequests,
		UserAgent: "deckard-ingest-prowler-app/" + version,
		Now:       prowlerAppNow, Sleep: prowlerAppSleep, Logf: logf,
	})
	if err != nil {
		return fail(ingestExitUsage, "%v", err)
	}
	col := prowlerapp.NewCollector(client, prowlerapp.Options{
		ProviderTypes: splitList(f.providerTypes, true), ProviderUIDs: splitList(f.providerUIDs, false),
		MinSeverity: floor, IncludeMuted: f.includeMuted, MaxScanAge: f.maxScanAge,
		Now: prowlerAppNow, Logf: logf,
	})

	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()
	providers, skipped, err := col.Providers(ctx)
	if err != nil {
		return fail(upstreamExit(err), "list providers: %v", err)
	}
	if len(providers) == 0 {
		return fail(ingestExitUsage, "no Prowler provider matches (--provider-type %q, --provider-uid %q)", f.providerTypes, f.providerUIDs)
	}

	// Summary lines go to stdout, except in a dry run where stdout carries the requests.
	summary := io.Writer(out)
	if f.dryRun {
		summary = errw
	}
	worst := ingestExitOK
	if skipped > 0 {
		_, _ = fmt.Fprintf(errw, "deckard ingest prowler-app: %d provider(s) listed by Prowler could not be decoded and were skipped\n", skipped)
		worst = ingestExitIncomplete
	}
	for _, p := range providers {
		run := col.Collect(ctx, p)
		if he := (*prowlerapp.HTTPError)(nil); errors.As(run.Err, &he) && he.Auth() {
			return fail(ingestExitUsage, "%s: the Prowler API refused the credentials (%v)", run.Scope, run.Err)
		}
		code := handleProwlerRun(ctx, run, endpoint, token, f, out, summary, errw)
		worst = worseExit(worst, code)
	}
	return worst
}

// handleProwlerRun reports, and unless this is a dry run posts, one provider's
// run, returning its exit code.
func handleProwlerRun(ctx context.Context, run *prowlerapp.Run, endpoint, token string, f prowlerAppFlags, out, summary, errw io.Writer) int {
	reasons := append([]string(nil), run.Reasons...)
	line := func(posted bool, extra string) {
		reason := ""
		if len(reasons) > 0 {
			reason = " reason=" + quoteReasons(reasons)
		}
		n := 0
		if run.Request != nil {
			n = len(run.Request.Findings)
		}
		_, _ = fmt.Fprintf(summary, "prowler-app: scope=%s scan=%s findings=%d complete=%v posted=%v%s%s\n",
			run.Scope, orDash(run.ScanID), n, run.Complete(), posted, extra, reason)
		for _, r := range reasons {
			_, _ = fmt.Fprintf(errw, "deckard ingest prowler-app: %s: %s\n", run.Scope, ingest.Line(r, 500))
		}
	}
	if run.Request == nil {
		reasons = append(reasons, ingest.Line(errString(run.Err), 500))
		line(false, "")
		return upstreamExit(run.Err)
	}
	body, err := json.Marshal(run.Request)
	if err != nil || len(body) > ingest.MaxBodyBytes {
		reasons = append(reasons, "the request could not be encoded within the size limit")
		line(false, "")
		return ingestExitIncomplete
	}
	code := ingestExitOK
	if !run.Complete() {
		code = ingestExitIncomplete
	}
	if f.dryRun {
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, body, "", "  ")
		pretty.WriteByte('\n')
		_, _ = out.Write(pretty.Bytes())
		line(false, "")
		return code
	}

	pctx, cancel := context.WithTimeout(ctx, ingestPostTimeout)
	defer cancel()
	status, respBody, netErr := postWithRetry(pctx, endpoint, token, body, ingestPostTimeout, f.verbose, errw)
	if netErr != nil {
		reasons = append(reasons, "could not reach deckard: "+ingest.Line(netErr.Error(), 300))
		line(false, "")
		return ingestExitNetwork
	}
	if status != 200 {
		var e ingest.ErrorResponse
		msg := strings.TrimSpace(string(respBody))
		if json.Unmarshal(respBody, &e) == nil && e.Error.Message != "" {
			msg = e.Error.Code + ": " + e.Error.Message
		}
		reasons = append(reasons, fmt.Sprintf("deckard answered HTTP %d: %s", status, ingest.Line(msg, 500)))
		for _, r := range e.Rejected {
			reasons = append(reasons, "rejected "+ingest.Line(r.String(), 300))
		}
		line(false, "")
		return ingestExitRejected
	}
	var r ingest.Response
	if err := json.Unmarshal(respBody, &r); err != nil {
		reasons = append(reasons, "unexpected response body from deckard")
		line(true, "")
		return ingestExitRejected
	}
	extra := fmt.Sprintf(" accepted=%d opened=%d reopened=%d refreshed=%d resolved_pending=%d resolved=%d applied_as_complete=%v replay=%v",
		r.Accepted, r.Opened, r.Reopened, r.Refreshed, r.ResolvedPending, r.Resolved, r.Complete, r.Replay)
	for _, rj := range r.Rejected {
		reasons = append(reasons, "rejected "+ingest.Line(rj.String(), 300))
	}
	switch {
	case len(r.Rejected) > 0:
		code = ingestExitRejected
	case run.Complete() && !r.Complete && !r.Replay:
		// Not newer than a run deckard already accepted for this scope (the same
		// scan, changed since): nothing resolves, which is harmless.
		reasons = append(reasons, "deckard did not apply absence: "+ingest.Line(r.Note, 300))
	}
	line(true, extra)
	return code
}

// upstreamExit classifies a failure to get a run out of Prowler.
func upstreamExit(err error) int {
	var te *prowlerapp.TransportError
	var he *prowlerapp.HTTPError
	switch {
	case errors.As(err, &he) && he.Auth():
		return ingestExitUsage
	case errors.As(err, &te):
		return ingestExitNetwork
	}
	return ingestExitIncomplete
}

// worseExit picks the more urgent of two exit codes: 2 (deckard rejected a
// request) over 3 (a service was unreachable) over 4 (posted incomplete) over
// 0. Usage errors end the run before any provider is handled.
func worseExit(a, b int) int {
	rank := map[int]int{ingestExitOK: 0, ingestExitIncomplete: 1, ingestExitNetwork: 2, ingestExitRejected: 3, ingestExitUsage: 4}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func splitList(s string, lower bool) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			if lower {
				v = strings.ToLower(v)
			}
			out = append(out, v)
		}
	}
	return out
}

func quoteReasons(rs []string) string {
	return fmt.Sprintf("%q", ingest.Line(strings.Join(rs, "; "), 800))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func errString(err error) string {
	if err == nil {
		return "no result"
	}
	return err.Error()
}

// secretScrubber is the set of credentials to keep out of every output.
type secretScrubber struct {
	mu   sync.Mutex
	list []string
}

func (s *secretScrubber) add(v string) {
	if v == "" {
		return
	}
	s.mu.Lock()
	s.list = append(s.list, v)
	s.mu.Unlock()
}

// scrubWriter replaces every known credential in what is written through it.
type scrubWriter struct {
	w io.Writer
	s *secretScrubber
}

func (w *scrubWriter) Write(p []byte) (int, error) {
	w.s.mu.Lock()
	secrets := append([]string(nil), w.s.list...)
	w.s.mu.Unlock()
	q := p
	for _, sec := range secrets {
		if bytes.Contains(q, []byte(sec)) {
			q = bytes.ReplaceAll(q, []byte(sec), []byte("[REDACTED]"))
		}
	}
	if _, err := w.w.Write(q); err != nil {
		return 0, err
	}
	return len(p), nil
}
