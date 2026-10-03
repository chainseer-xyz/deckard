package gcpdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/time/rate"
)

const (
	// DefaultBaseURL is the production Cloud DNS v1 API.
	DefaultBaseURL = "https://dns.googleapis.com/dns/v1"
	// Scope is the read-only Cloud DNS OAuth scope.
	Scope = "https://www.googleapis.com/auth/ndev.clouddns.readonly"

	defaultTimeout    = 30 * time.Second
	defaultMaxRetries = 4
	defaultBackoff    = 500 * time.Millisecond
	defaultMaxWait    = 30 * time.Second
	defaultRPS        = 5
	pageSize          = 500
	maxPages          = 10000
	maxBody           = 32 << 20
	maxMessage        = 300
)

// ManagedZone is the subset of a Cloud DNS managed zone the source reads.
type ManagedZone struct {
	Name         string        `json:"name"`
	DNSName      string        `json:"dnsName"`
	ID           json.Number   `json:"id"`
	Visibility   string        `json:"visibility"`
	DNSSECConfig *DNSSECConfig `json:"dnssecConfig"`
	// PeeringConfig is set on peering zones, which serve no records of their own.
	PeeringConfig json.RawMessage `json:"peeringConfig"`
}

// DNSSECConfig carries the zone's DNSSEC state ("on", "off", "transfer").
type DNSSECConfig struct {
	State string `json:"state"`
}

// RRSet is one resource record set.
type RRSet struct {
	Name          string         `json:"name"`
	Type          string         `json:"type"`
	TTL           int            `json:"ttl"`
	RRDatas       []string       `json:"rrdatas"`
	RoutingPolicy *RoutingPolicy `json:"routingPolicy"`
}

// RoutingPolicy is a weighted, geo or primary/backup policy. Every target of
// every branch is a possible answer, so all of them are discovered.
type RoutingPolicy struct {
	WRR           *WRRPolicy           `json:"wrr"`
	Geo           *GeoPolicy           `json:"geo"`
	PrimaryBackup *PrimaryBackupPolicy `json:"primaryBackup"`
}

// WRRPolicy is a weighted round robin policy.
type WRRPolicy struct {
	Items []PolicyItem `json:"items"`
}

// GeoPolicy is a geolocation policy.
type GeoPolicy struct {
	Items []PolicyItem `json:"items"`
}

// PrimaryBackupPolicy is a failover policy.
type PrimaryBackupPolicy struct {
	PrimaryTargets   *HealthCheckedTargets `json:"primaryTargets"`
	BackupGeoTargets *GeoPolicy            `json:"backupGeoTargets"`
}

// PolicyItem is one weighted or geo branch.
type PolicyItem struct {
	Location             string                `json:"location"`
	RRDatas              []string              `json:"rrdatas"`
	HealthCheckedTargets *HealthCheckedTargets `json:"healthCheckedTargets"`
}

// HealthCheckedTargets are load balancers or endpoints a policy answers with.
type HealthCheckedTargets struct {
	InternalLoadBalancers []InternalLoadBalancer `json:"internalLoadBalancers"`
	ExternalEndpoints     []string               `json:"externalEndpoints"`
}

// InternalLoadBalancer is a regional internal passthrough or proxy LB target.
type InternalLoadBalancer struct {
	IPAddress        string `json:"ipAddress"`
	IPProtocol       string `json:"ipProtocol"`
	Port             string `json:"port"`
	LoadBalancerType string `json:"loadBalancerType"`
	Project          string `json:"project"`
	Region           string `json:"region"`
}

// API is the subset of Cloud DNS the source uses. It is satisfied by *Client
// and by test fakes. Implementations return every page.
type API interface {
	ListManagedZones(ctx context.Context, project string) ([]ManagedZone, error)
	ListRRSets(ctx context.Context, project, zone string) ([]RRSet, error)
}

// APIError is a non-success HTTP response. It carries the status and Google's
// own message only: never the request URL's query or any credential.
type APIError struct {
	Status  int
	Op      string
	Message string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("gcpdns: %s: HTTP %d: %s", e.Op, e.Status, msg)
}

// CredentialsError means Application Default Credentials could not produce a
// token. The message is redacted.
type CredentialsError struct {
	Op      string
	Message string
}

func (e *CredentialsError) Error() string {
	return fmt.Sprintf("gcpdns: %s: obtain credentials: %s", e.Op, e.Message)
}

// Denied reports a status that means "this identity cannot see that resource".
func (e *APIError) Denied() bool {
	return e.Status == http.StatusForbidden || e.Status == http.StatusNotFound
}

// Client is a small typed Cloud DNS REST client.
type Client struct {
	base       string
	tokens     oauth2.TokenSource
	http       *http.Client
	limiter    *rate.Limiter
	maxRetries int
	backoff    time.Duration
	maxWait    time.Duration
}

// Option tweaks a Client (mainly for tests).
type Option func(*Client)

// WithBaseURL points the client at another API root (tests).
func WithBaseURL(u string) Option { return func(c *Client) { c.base = strings.TrimRight(u, "/") } }

// WithHTTPClient replaces the HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithRetry sets the retry count, base backoff and the cap on any wait,
// including a server-supplied Retry-After.
func WithRetry(max int, backoff, maxWait time.Duration) Option {
	return func(c *Client) { c.maxRetries, c.backoff, c.maxWait = max, backoff, maxWait }
}

// WithRateLimit sets the request-per-second ceiling (0 disables the limit).
func WithRateLimit(rps float64) Option {
	return func(c *Client) {
		if rps <= 0 {
			c.limiter = rate.NewLimiter(rate.Inf, 1)
			return
		}
		c.limiter = rate.NewLimiter(rate.Limit(rps), 1)
	}
}

// NewClient builds a client that authenticates with ts.
func NewClient(ts oauth2.TokenSource, opts ...Option) *Client {
	c := &Client{
		base: DefaultBaseURL, tokens: ts,
		http:       &http.Client{Timeout: defaultTimeout},
		limiter:    rate.NewLimiter(rate.Limit(defaultRPS), 1),
		maxRetries: defaultMaxRetries, backoff: defaultBackoff, maxWait: defaultMaxWait,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// ADCTokenSource returns a token source backed by Application Default
// Credentials (Workload Identity, GOOGLE_APPLICATION_CREDENTIALS or gcloud).
// Credential discovery is lazy and retried, so a deckard that starts before
// its credentials exist reports a sync error instead of failing to boot.
func ADCTokenSource() oauth2.TokenSource { return &lazyADC{} }

type lazyADC struct {
	mu sync.Mutex
	ts oauth2.TokenSource
}

func (l *lazyADC) Token() (*oauth2.Token, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ts == nil {
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Timeout: defaultTimeout})
		ts, err := google.DefaultTokenSource(ctx, Scope)
		if err != nil {
			return nil, err
		}
		l.ts = ts
	}
	return l.ts.Token()
}

var (
	bearerRE = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`)
	googTok  = regexp.MustCompile(`ya29\.[A-Za-z0-9._-]+`)
	// Service-account keys and refresh tokens must never reach a log line even
	// if an upstream error echoes them.
	secretFieldRE = regexp.MustCompile(`(?i)("?(?:private_key|refresh_token|client_secret|access_token)"?\s*[:=]\s*)"?[^",\s}]+"?`)
)

// redact removes anything credential-shaped from s, plus the live token.
func redact(s, token string) string {
	if token != "" {
		s = strings.ReplaceAll(s, token, "[REDACTED]")
	}
	s = bearerRE.ReplaceAllString(s, "Bearer [REDACTED]")
	s = googTok.ReplaceAllString(s, "[REDACTED]")
	return secretFieldRE.ReplaceAllString(s, "${1}[REDACTED]")
}

// message flattens an upstream string to one bounded, redacted line.
func message(s, token string) string {
	s = strings.Join(strings.Fields(redact(s, token)), " ")
	if len(s) > maxMessage {
		s = s[:maxMessage] + "..."
	}
	return s
}

// retryable wraps a failure worth another attempt with the server's wait hint.
type retryable struct {
	err  error
	wait time.Duration
}

func (r *retryable) Error() string { return r.err.Error() }
func (r *retryable) Unwrap() error { return r.err }

// get performs one GET with retry on 429, 5xx and transport failures.
func (c *Client) get(ctx context.Context, op, path string, q url.Values, out any) error {
	var last error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			wait := c.backoff << (attempt - 1)
			var r *retryable
			if errors.As(last, &r) && r.wait > 0 {
				wait = r.wait
			}
			wait = min(wait, c.maxWait)
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
		if err := c.limiter.Wait(ctx); err != nil {
			return err
		}
		err := c.do(ctx, op, path, q, out)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var r *retryable
		if !errors.As(err, &r) {
			return err
		}
		last = err
	}
	var r *retryable
	if errors.As(last, &r) {
		return r.err
	}
	return last
}

func (c *Client) do(ctx context.Context, op, path string, q url.Values, out any) error {
	tok, err := c.tokens.Token()
	if err != nil {
		// A credential failure is final: retrying cannot help and the cause is
		// the operator's configuration.
		return &CredentialsError{Op: op, Message: message(err.Error(), "")}
	}
	secret := tok.AccessToken
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("gcpdns: %s: build request: %s", op, message(err.Error(), secret))
	}
	req.Header.Set("Authorization", tok.Type()+" "+secret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "deckard")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// url.Error embeds the full URL including the query: report only the
		// underlying cause.
		var ue *url.Error
		cause := err.Error()
		if errors.As(err, &ue) {
			cause = ue.Err.Error()
		}
		return &retryable{err: fmt.Errorf("gcpdns: %s: request failed: %s", op, message(cause, secret))}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &retryable{err: fmt.Errorf("gcpdns: %s: read response: %s", op, message(err.Error(), secret))}
	}
	if len(body) > maxBody {
		return fmt.Errorf("gcpdns: %s: response exceeds %d bytes", op, maxBody)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("gcpdns: %s: decode response: %s", op, message(err.Error(), secret))
		}
		return nil
	}
	ae := &APIError{Status: resp.StatusCode, Op: op, Message: upstreamMessage(body, secret)}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return &retryable{err: ae, wait: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
	}
	return ae
}

// upstreamMessage extracts error.message from Google's error envelope.
func upstreamMessage(body []byte, token string) string {
	var env struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) != nil {
		return ""
	}
	m := env.Error.Message
	if env.Error.Status != "" {
		m = env.Error.Status + ": " + m
	}
	return message(m, token)
}

// parseRetryAfter understands delta-seconds and HTTP-date. Zero means no hint.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 {
			return 0
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// list follows nextPageToken until the collection is exhausted.
func list[P any](ctx context.Context, c *Client, op, path string, next func(*P) string) ([]*P, error) {
	var pages []*P
	token := ""
	seen := map[string]bool{}
	for range maxPages {
		q := url.Values{"maxResults": {strconv.Itoa(pageSize)}}
		if token != "" {
			q.Set("pageToken", token)
		}
		p := new(P)
		if err := c.get(ctx, op, path, q, p); err != nil {
			return nil, err
		}
		pages = append(pages, p)
		nt := next(p)
		if nt == "" {
			return pages, nil
		}
		if seen[nt] {
			return nil, fmt.Errorf("gcpdns: %s: pagination loop (repeated page token)", op)
		}
		seen[nt] = true
		token = nt
	}
	return nil, fmt.Errorf("gcpdns: %s: exceeded %d pages", op, maxPages)
}

type zonesPage struct {
	ManagedZones  []ManagedZone `json:"managedZones"`
	NextPageToken string        `json:"nextPageToken"`
}

type rrsetsPage struct {
	RRSets        []RRSet `json:"rrsets"`
	NextPageToken string  `json:"nextPageToken"`
}

// ListManagedZones returns every managed zone of project.
func (c *Client) ListManagedZones(ctx context.Context, project string) ([]ManagedZone, error) {
	op := "list managed zones"
	pages, err := list(ctx, c, op, "/projects/"+url.PathEscape(project)+"/managedZones",
		func(p *zonesPage) string { return p.NextPageToken })
	if err != nil {
		return nil, err
	}
	var out []ManagedZone
	for _, p := range pages {
		out = append(out, p.ManagedZones...)
	}
	return out, nil
}

// ListRRSets returns every record set of one managed zone.
func (c *Client) ListRRSets(ctx context.Context, project, zone string) ([]RRSet, error) {
	op := "list record sets"
	pages, err := list(ctx, c, op,
		"/projects/"+url.PathEscape(project)+"/managedZones/"+url.PathEscape(zone)+"/rrsets",
		func(p *rrsetsPage) string { return p.NextPageToken })
	if err != nil {
		return nil, err
	}
	var out []RRSet
	for _, p := range pages {
		out = append(out, p.RRSets...)
	}
	return out, nil
}
