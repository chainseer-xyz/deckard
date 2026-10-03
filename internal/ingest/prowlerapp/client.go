package prowlerapp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
)

// Defaults of the client's limits.
const (
	DefaultTimeout        = 30 * time.Second // per request
	DefaultMaxResponse    = 16 << 20         // bytes of one response
	DefaultMaxRequests    = 1000             // requests per run, retries included
	DefaultPageSize       = 100
	maxAttempts           = 4
	maxRetryAfter         = 60 * time.Second
	mediaType             = "application/vnd.api+json"
	apiPath               = "/api/v1"
	maxRedirects          = 3
	maxPagesPerCollection = 2000
)

// Config configures a Client. The credentials are the API key, or the email
// and password of a user (a JWT is then fetched from /api/v1/tokens).
type Config struct {
	BaseURL  string
	APIKey   string
	Email    string
	Password string

	// UseEnvProxy lets HTTP(S)_PROXY from the environment apply. Off by default:
	// the credentials of an internal service should not travel via a proxy
	// nobody chose.
	UseEnvProxy bool
	Timeout     time.Duration // per request
	// MaxResponseBytes bounds one response body; a larger one is an error.
	MaxResponseBytes int64
	// MaxRequests bounds the requests of one run (retries count).
	MaxRequests int
	UserAgent   string

	// Transport replaces the default transport (tests).
	Transport http.RoundTripper
	// Now and Sleep are the clock and the sleeper (tests inject fakes).
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	// Logf receives one line per request (paths only, never credentials).
	Logf func(format string, args ...any)
}

// Client is a read-only client of the Prowler App API. It is not safe for
// concurrent use.
type Client struct {
	cfg     Config
	base    *url.URL
	root    string // path prefix of the API, e.g. /api/v1
	http    *http.Client
	auth    string // current Authorization header value
	secrets []string
	used    int
	relogin bool
}

// HTTPError is a non-2xx answer of the API.
type HTTPError struct {
	Status int
	Code   string
	Detail string
}

func (e *HTTPError) Error() string {
	s := fmt.Sprintf("prowler api answered HTTP %d", e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Auth reports an authentication or authorisation failure (a credentials
// problem, not an outage).
func (e *HTTPError) Auth() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
}

// TransportError is a failure to get any answer (connection, TLS, timeout).
type TransportError struct {
	msg string
	err error
}

func (e *TransportError) Error() string { return e.msg }
func (e *TransportError) Unwrap() error { return e.err }

// Sentinel errors of the client's safety limits.
var (
	ErrBudget   = errors.New("prowler api: request budget for this run exhausted")
	ErrTooLarge = errors.New("prowler api: response larger than the allowed size")
)

// NewClient validates cfg and builds a client. It makes no request.
func NewClient(cfg Config) (*Client, error) {
	base, err := ParseBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	switch {
	case cfg.APIKey != "" && (cfg.Email != "" || cfg.Password != ""):
		return nil, errors.New("give either an API key or an email and password, not both")
	case cfg.APIKey == "" && (cfg.Email == "" || cfg.Password == ""):
		return nil, errors.New("credentials are required: an API key, or an email and password")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = DefaultMaxResponse
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = DefaultMaxRequests
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "deckard-ingest-prowler-app"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleep
	}
	c := &Client{cfg: cfg, base: base, root: strings.TrimRight(base.Path, "/") + apiPath}
	for _, s := range []string{cfg.APIKey, cfg.Email, cfg.Password} {
		c.addSecret(s)
	}
	rt := cfg.Transport
	if rt == nil {
		rt = newTransport(cfg.UseEnvProxy)
	}
	c.http = &http.Client{Transport: rt, Timeout: cfg.Timeout, CheckRedirect: c.checkRedirect}
	if cfg.APIKey != "" {
		c.auth = "Api-Key " + cfg.APIKey
	} else {
		c.relogin = true
	}
	return c, nil
}

// ParseBaseURL validates the --api-url value: an absolute http(s) URL without
// credentials, query or fragment. A trailing /api/v1 is accepted and dropped.
func ParseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("the Prowler API URL must be an absolute http(s) URL")
	}
	if u.User != nil {
		return nil, errors.New("the Prowler API URL must not contain credentials; pass them through environment variables")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("the Prowler API URL must not have a query or fragment")
	}
	u.Path = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), apiPath)
	u.RawPath = ""
	return u, nil
}

// newTransport is a plain HTTPS-verifying transport; the environment's proxy
// is used only when asked for.
func newTransport(envProxy bool) *http.Transport {
	t := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if envProxy {
		t.Proxy = http.ProxyFromEnvironment
	}
	return t
}

// checkRedirect follows only same-origin redirects: the credentials must never
// reach another host or leave TLS.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != c.base.Scheme || req.URL.Host != c.base.Host {
		return errors.New("refusing to follow a redirect to another origin")
	}
	return nil
}

func (c *Client) addSecret(s string) {
	if s != "" {
		c.secrets = append(c.secrets, s)
	}
}

// redact removes every credential the client knows from s.
func (c *Client) redact(s string) string {
	for _, sec := range c.secrets {
		s = strings.ReplaceAll(s, sec, "[REDACTED]")
	}
	return s
}

// Requests is how many requests this client has made.
func (c *Client) Requests() int { return c.used }

func (c *Client) logf(format string, args ...any) {
	if c.cfg.Logf != nil {
		c.cfg.Logf(format, args...)
	}
}

// Login exchanges the email and password for a JWT. It is called lazily by the
// first request when no API key is configured.
func (c *Client) Login(ctx context.Context) error {
	body, err := json.Marshal(map[string]any{"data": map[string]any{
		"type":       "tokens",
		"attributes": map[string]string{"email": c.cfg.Email, "password": c.cfg.Password},
	}})
	if err != nil {
		return err
	}
	data, err := c.do(ctx, http.MethodPost, c.apiURL("/tokens", nil), body, false)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	var out struct {
		Data struct {
			Attributes struct {
				Access string `json:"access"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &out) != nil || out.Data.Attributes.Access == "" {
		return errors.New("login: the response carries no access token")
	}
	c.auth = "Bearer " + out.Data.Attributes.Access
	c.addSecret(out.Data.Attributes.Access)
	return nil
}

func (c *Client) apiURL(path string, q url.Values) *url.URL {
	u := *c.base
	u.Path = c.root + path
	u.RawPath = ""
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return &u
}

// get fetches and decodes one document.
func (c *Client) get(ctx context.Context, u *url.URL) (*Document, error) {
	data, err := c.do(ctx, http.MethodGet, u, nil, true)
	if err != nil {
		return nil, err
	}
	doc, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("prowler api: undecodable response for %s: %w", u.Path, err)
	}
	return doc, nil
}

// do performs one logical request: retries on network errors, 429 and 5xx
// (honouring Retry-After), one re-login on a 401 when using a JWT, and every
// attempt counts against the run's budget.
func (c *Client) do(ctx context.Context, method string, u *url.URL, body []byte, authed bool) ([]byte, error) {
	relogged := false
	for attempt := 1; ; attempt++ {
		if authed && c.auth == "" {
			if err := c.Login(ctx); err != nil {
				return nil, err
			}
		}
		if c.used >= c.cfg.MaxRequests {
			return nil, ErrBudget
		}
		c.used++
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("prowler api: build request: %s", c.redact(err.Error()))
		}
		req.Header.Set("Accept", mediaType)
		req.Header.Set("User-Agent", c.cfg.UserAgent)
		if body != nil {
			req.Header.Set("Content-Type", mediaType)
		}
		if authed {
			req.Header.Set("Authorization", c.auth)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("prowler api: %w", ctx.Err())
			}
			terr := &TransportError{msg: "prowler api: " + c.redact(err.Error()), err: err}
			c.logf("%s %s: attempt %d: %v", method, u.Path, attempt, terr)
			if attempt < maxAttempts && c.cfg.Sleep(ctx, backoff(attempt, "", c.cfg.Now())) == nil {
				continue
			}
			return nil, terr
		}
		data, tooLarge, rerr := readLimited(resp.Body, c.cfg.MaxResponseBytes)
		_ = resp.Body.Close()
		c.logf("%s %s: HTTP %d (attempt %d)", method, u.Path, resp.StatusCode, attempt)
		switch {
		case tooLarge:
			return nil, ErrTooLarge
		case rerr != nil:
			if ctx.Err() != nil {
				return nil, fmt.Errorf("prowler api: %w", ctx.Err())
			}
			return nil, &TransportError{msg: "prowler api: reading the response: " + c.redact(rerr.Error()), err: rerr}
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			if attempt < maxAttempts {
				if err := c.cfg.Sleep(ctx, backoff(attempt, resp.Header.Get("Retry-After"), c.cfg.Now())); err != nil {
					return nil, fmt.Errorf("prowler api: %w", err)
				}
				continue
			}
		case resp.StatusCode == http.StatusUnauthorized && authed && c.relogin && !relogged:
			relogged = true
			c.auth = ""
			attempt--
			continue
		}
		if resp.StatusCode >= 400 {
			return nil, c.httpError(resp.StatusCode, data)
		}
		return data, nil
	}
}

func (c *Client) httpError(status int, body []byte) error {
	e := &HTTPError{Status: status}
	if doc, err := Decode(body); err == nil && len(doc.Errors) > 0 {
		e.Code = ingest.Line(c.redact(doc.Errors[0].Code), 64)
		e.Detail = ingest.Line(c.redact(doc.Errors[0].Detail), 300)
	}
	return e
}

// readLimited reads at most max bytes; tooLarge is set when there is more.
func readLimited(r io.Reader, max int64) (data []byte, tooLarge bool, err error) {
	data, err = io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		return nil, true, nil
	}
	return data, false, nil
}

// backoff is Retry-After (seconds or an HTTP date, capped at a minute), else
// 1s, 2s, 4s.
func backoff(attempt int, retryAfter string, now time.Time) time.Duration {
	retryAfter = strings.TrimSpace(retryAfter)
	if s, err := strconv.Atoi(retryAfter); err == nil && s >= 0 {
		return min(time.Duration(s)*time.Second, maxRetryAfter)
	}
	if t, err := http.ParseTime(retryAfter); err == nil {
		return max(0, min(t.Sub(now), maxRetryAfter))
	}
	return time.Duration(1<<(attempt-1)) * time.Second
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// pages follows links.next from the first URL until exhausted, calling fn for
// every page. It stops with an error on a loop, a link that is not under the
// API root, an error of fn, or the page cap. Next links are re-rooted on the
// configured origin: a link naming another host is never contacted.
func (c *Client) pages(ctx context.Context, first *url.URL, fn func(*Document) (stop bool, err error)) error {
	seen := map[string]bool{}
	u := first
	for n := 0; ; n++ {
		if n >= maxPagesPerCollection {
			return errors.New("prowler api: too many pages")
		}
		key := u.RequestURI()
		if seen[key] {
			return errors.New("prowler api: pagination loops back to a page already fetched")
		}
		seen[key] = true
		doc, err := c.get(ctx, u)
		if err != nil {
			return err
		}
		stop, err := fn(doc)
		if err != nil {
			return err
		}
		if stop || doc.Links.Next == "" {
			return nil
		}
		if u, err = c.nextURL(doc.Links.Next); err != nil {
			return err
		}
	}
}

func (c *Client) nextURL(raw string) (*url.URL, error) {
	n, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(n.Path, c.root+"/") {
		return nil, errors.New("prowler api: links.next does not point into the API")
	}
	u := *c.base
	u.Path, u.RawPath, u.RawQuery = n.Path, "", n.RawQuery
	return &u, nil
}
