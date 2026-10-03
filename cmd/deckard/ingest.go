package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/gitleaks"
	"github.com/chainseer-xyz/deckard/internal/ingest/kubescape"
	"github.com/chainseer-xyz/deckard/internal/ingest/prowler"
	"github.com/chainseer-xyz/deckard/internal/ingest/s3scanner"
	"github.com/chainseer-xyz/deckard/internal/ingest/sarif"
	"github.com/chainseer-xyz/deckard/internal/ingest/trufflehog"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Exit codes of `deckard ingest`.
const (
	ingestExitOK       = 0 // posted (or dry run) and fully applied
	ingestExitUsage    = 1 // bad flags, unreadable or unparseable input, invalid request
	ingestExitRejected = 2 // the server refused the request or some of its items
	ingestExitNetwork  = 3 // the server could not be reached
	// ingestExitIncomplete is for prowler-app: a run was posted as incomplete
	// (or could not be built) because of an upstream condition in Prowler.
	ingestExitIncomplete = 4
)

// ingestParsers maps --format to a parser.
var ingestParsers = map[string]ingest.Parser{
	prowler.Tool:    prowler.Parse,
	kubescape.Tool:  kubescape.Parse,
	trufflehog.Tool: trufflehog.Parse,
	gitleaks.Tool:   gitleaks.Parse,
	s3scanner.Tool:  s3scanner.Parse,
	sarif.Tool:      sarif.Parse,
}

// stdin is the input when --file is absent (a variable for tests).
var stdin io.Reader = os.Stdin

// maxIngestInput bounds how much tool output is read.
const maxIngestInput = 1 << 30

const ingestUsage = `usage: deckard ingest --tool <name> --scope <scope> [--format <parser>] [--file <path> | stdin]
                      [--url <deckard base URL> --token-env <VAR>] [--incomplete] [--observed-at <RFC 3339>]
                      [--dry-run] [--timeout 2m] [-v]

Converts a scanner's native output into a POST /api/v1/ingest request and posts it.
Parsers (--format, default: the tool name): %s.

       deckard ingest prowler-app --api-url <Prowler API URL> --api-key-env <VAR> ...
pulls the latest scans from a running Prowler App instead; see deckard ingest prowler-app --help.

  --incomplete   the output is not everything the tool found in the scope: nothing will be resolved
  --dry-run      print the request (never the token) after validating it locally, post nothing

Exit codes: 0 posted and applied, 1 usage, input or validation error, 2 the server rejected the
request or some items (or did not apply it as complete), 3 network error. See docs/ingest.md.
`

type ingestFlags struct {
	tool, format, scope, file, url, tokenEnv, observedAt string
	incomplete, dryRun, verbose                          bool
	timeout                                              time.Duration
}

func runIngest(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "prowler-app" {
		return runIngestProwlerApp(args[1:], stdout, stderr)
	}
	var f ingestFlags
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.tool, "tool", "", "tool name: findings are stored under check ext.<tool>")
	fs.StringVar(&f.format, "format", "", "parser for the input (default: the tool name)")
	fs.StringVar(&f.scope, "scope", "", "what was scanned (aws:<account>:<region>, a cluster, a GitHub org)")
	fs.StringVar(&f.file, "file", "", "tool output to read (default: stdin)")
	fs.StringVar(&f.url, "url", "", "deckard base URL")
	fs.StringVar(&f.tokenEnv, "token-env", "", "environment variable holding the API token")
	fs.StringVar(&f.observedAt, "observed-at", "", "when the scan ran (RFC 3339; default now)")
	fs.BoolVar(&f.incomplete, "incomplete", false, "the output does not cover the whole scope: resolve nothing")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print the request instead of posting it")
	fs.BoolVar(&f.verbose, "v", false, "verbose progress on stderr")
	fs.DurationVar(&f.timeout, "timeout", 2*time.Minute, "overall time limit for posting, retries included")
	names := make([]string, 0, len(ingestParsers))
	for n := range ingestParsers {
		names = append(names, n)
	}
	sort.Strings(names)
	usage := fmt.Sprintf(ingestUsage, strings.Join(names, ", "))
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(stdout, usage)
			return ingestExitOK
		}
		_, _ = fmt.Fprintf(stderr, "deckard ingest: %v\n\n%s", err, usage)
		return ingestExitUsage
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "deckard ingest: unexpected argument %q\n\n%s", fs.Arg(0), usage)
		return ingestExitUsage
	}

	// The token is read once and scrubbed from everything this command prints.
	var token string
	if f.tokenEnv != "" {
		token = os.Getenv(f.tokenEnv)
	}
	out := &scrubber{w: stdout, secret: token}
	errw := &scrubber{w: stderr, secret: token}
	fail := func(code int, format string, a ...any) int {
		_, _ = fmt.Fprintf(errw, "deckard ingest: "+format+"\n", a...)
		return code
	}

	if f.format == "" {
		f.format = f.tool
	}
	parse, ok := ingestParsers[f.format]
	switch {
	case !model.ValidIngestTool(f.tool):
		return fail(ingestExitUsage, "--tool must match ^[a-z0-9][a-z0-9-]{1,31}$\n\n%s", usage)
	case !ok:
		return fail(ingestExitUsage, "unknown --format %q (known: %s)", f.format, strings.Join(names, ", "))
	case strings.TrimSpace(f.scope) == "":
		return fail(ingestExitUsage, "--scope is required\n\n%s", usage)
	}
	var endpoint string
	if !f.dryRun {
		var err error
		if endpoint, err = ingestEndpoint(f.url); err != nil {
			return fail(ingestExitUsage, "%v", err)
		}
		switch {
		case f.tokenEnv == "":
			return fail(ingestExitUsage, "--token-env is required (the name of the variable holding the token, never the token)")
		case token == "":
			return fail(ingestExitUsage, "environment variable %s is empty or unset", f.tokenEnv)
		}
	}
	observed := time.Now().UTC()
	if f.observedAt != "" {
		t, err := time.Parse(time.RFC3339Nano, f.observedAt)
		if err != nil {
			return fail(ingestExitUsage, "--observed-at must be RFC 3339 (2026-10-03T07:00:00Z)")
		}
		observed = t.UTC()
	}

	data, src, err := readIngestInput(f.file)
	if err != nil {
		return fail(ingestExitUsage, "%v", err)
	}
	findings, err := parse(data, ingest.ParseOptions{Scope: f.scope})
	if err != nil {
		return fail(ingestExitUsage, "parse %s as %s output: %v", src, f.format, err)
	}
	if findings == nil {
		findings = []ingest.Finding{}
	}
	req := &ingest.Request{Tool: f.tool, Scope: f.scope, Complete: !f.incomplete, ObservedAt: &observed, Findings: findings}
	if problems := ingest.Validate(req, ingest.Options{Now: time.Now()}); len(problems) > 0 {
		return fail(ingestExitUsage, "the request would be rejected: %s", ingest.Summary(problems))
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fail(ingestExitUsage, "encode request: %v", err)
	}
	if len(body) > ingest.MaxBodyBytes {
		return fail(ingestExitUsage, "the request is %.1f MiB, over the %d MiB limit: filter the tool output or split the scope",
			float64(len(body))/(1<<20), ingest.MaxBodyBytes>>20)
	}
	if f.verbose {
		_, _ = fmt.Fprintf(errw, "deckard ingest: %d findings from %s (%s parser), %d bytes, complete=%v, observed_at=%s\n",
			len(findings), src, f.format, len(body), req.Complete, observed.Format(time.RFC3339))
	}
	if f.dryRun {
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, body, "", "  ")
		pretty.WriteByte('\n')
		_, _ = out.Write(pretty.Bytes())
		return ingestExitOK
	}

	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()
	return postIngest(ctx, endpoint, token, body, f, out, errw)
}

// ingestEndpoint validates --url and returns the ingest endpoint.
func ingestEndpoint(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("--url is required (the deckard base URL), or use --dry-run")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("--url must be an absolute http(s) URL")
	}
	if u.User != nil {
		return "", errors.New("--url must not contain credentials; pass the token through --token-env")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("--url must not have a query or fragment")
	}
	return strings.TrimRight(u.String(), "/") + "/api/v1/ingest", nil
}

func readIngestInput(path string) ([]byte, string, error) {
	r := stdin
	src := "stdin"
	if path != "" && path != "-" {
		fh, err := os.Open(path) // #nosec G304 -- the operator names the file to read
		if err != nil {
			return nil, "", fmt.Errorf("open --file: %w", err)
		}
		defer func() { _ = fh.Close() }()
		r, src = fh, path
	}
	data, err := io.ReadAll(io.LimitReader(r, maxIngestInput+1))
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", src, err)
	}
	if len(data) > maxIngestInput {
		return nil, "", fmt.Errorf("%s is larger than %d MiB", src, maxIngestInput>>20)
	}
	return data, src, nil
}

// postIngest posts body, retrying network errors, 429 and 5xx (the server
// treats a repeated body as a no-op, so retries are safe).
func postIngest(ctx context.Context, endpoint, token string, body []byte, f ingestFlags, out, errw io.Writer) int {
	status, respBody, netErr := postWithRetry(ctx, endpoint, token, body, f.timeout, f.verbose, errw)
	if netErr != nil {
		if errors.Is(netErr, errBadRequest) {
			_, _ = fmt.Fprintf(errw, "deckard ingest: build request: %v\n", netErr)
			return ingestExitUsage
		}
		_, _ = fmt.Fprintf(errw, "deckard ingest: could not reach deckard: %v\n", netErr)
		return ingestExitNetwork
	}
	return ingestOutcome(status, respBody, f, out, errw)
}

// errBadRequest marks a request that could not even be built.
var errBadRequest = errors.New("bad request")

// postWithRetry is the transport half of postIngest: it returns the final HTTP
// status and body, or the last network error when no answer was ever received.
func postWithRetry(ctx context.Context, endpoint, token string, body []byte, timeout time.Duration, verbose bool, errw io.Writer) (int, []byte, error) {
	client := &http.Client{Timeout: timeout}
	const attempts = 4
	var lastNet error
	for attempt := 1; attempt <= attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return 0, nil, fmt.Errorf("%w: %w", errBadRequest, err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "deckard-ingest/"+version)
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			lastNet = err
			if verbose {
				_, _ = fmt.Fprintf(errw, "deckard ingest: attempt %d: %v\n", attempt, err)
			}
			if !sleepCtx(ctx, backoff(attempt, "")) {
				break
			}
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if verbose {
			_, _ = fmt.Fprintf(errw, "deckard ingest: attempt %d: HTTP %d in %s\n", attempt, resp.StatusCode, time.Since(start).Round(time.Millisecond))
		}
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		if retry && attempt < attempts && sleepCtx(ctx, backoff(attempt, resp.Header.Get("Retry-After"))) {
			continue
		}
		return resp.StatusCode, respBody, nil
	}
	return 0, nil, lastNet
}

func ingestOutcome(status int, body []byte, f ingestFlags, out, errw io.Writer) int {
	if status != http.StatusOK {
		var e ingest.ErrorResponse
		msg := strings.TrimSpace(string(body))
		if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
			msg = e.Error.Code + ": " + e.Error.Message
		}
		_, _ = fmt.Fprintf(errw, "deckard ingest: server answered HTTP %d: %s\n", status, ingest.Line(msg, 2000))
		for _, r := range e.Rejected {
			_, _ = fmt.Fprintf(errw, "  rejected %s\n", ingest.Line(r.String(), 500))
		}
		return ingestExitRejected
	}
	var r ingest.Response
	if err := json.Unmarshal(body, &r); err != nil {
		_, _ = fmt.Fprintf(errw, "deckard ingest: unexpected response body: %v\n", err)
		return ingestExitRejected
	}
	_, _ = fmt.Fprintf(out, "deckard ingest: tool=%s scope=%s accepted=%d opened=%d reopened=%d refreshed=%d resolved_pending=%d resolved=%d complete=%v replay=%v rejected=%d\n",
		f.tool, f.scope, r.Accepted, r.Opened, r.Reopened, r.Refreshed, r.ResolvedPending, r.Resolved, r.Complete, r.Replay, len(r.Rejected))
	if r.Note != "" {
		_, _ = fmt.Fprintf(errw, "deckard ingest: note: %s\n", ingest.Line(r.Note, 500))
	}
	for _, rj := range r.Rejected {
		_, _ = fmt.Fprintf(errw, "  rejected %s\n", ingest.Line(rj.String(), 500))
	}
	if len(r.Rejected) > 0 || (!f.incomplete && !r.Complete && !r.Replay) {
		return ingestExitRejected
	}
	return ingestExitOK
}

// backoffUnit scales retry delays (a variable for tests).
var backoffUnit = time.Second

// backoff is Retry-After (capped at a minute) or 1s, 2s, 4s.
func backoff(attempt int, retryAfter string) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && s > 0 {
		return min(time.Duration(s), 60) * backoffUnit
	}
	return time.Duration(1<<(attempt-1)) * backoffUnit
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// scrubber replaces the token in everything written through it, so no error
// (a server echoing a header, a URL in a transport error) can print it.
type scrubber struct {
	w      io.Writer
	secret string
}

func (s *scrubber) Write(p []byte) (int, error) {
	if s.secret != "" && bytes.Contains(p, []byte(s.secret)) {
		if _, err := s.w.Write(bytes.ReplaceAll(p, []byte(s.secret), []byte("[REDACTED]"))); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return s.w.Write(p)
}
