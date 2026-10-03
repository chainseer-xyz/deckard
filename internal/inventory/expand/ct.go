// Package expand implements discovery expansion: finding hostnames under owned
// zones from Certificate Transparency logs and (opt-in) DNS wordlists, while
// filtering out wildcard-DNS phantoms. All network I/O goes through injected
// interfaces (an *http.Client for CT, a check.Resolver for DNS); the results
// are candidates only: the inventory service still classifies them and drops
// anything outside an owned zone.
package expand

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// DefaultCTURL is the crt.sh endpoint.
const DefaultCTURL = "https://crt.sh/"

const maxCTBody = 64 << 20 // crt.sh returns large JSON for big zones

// CT queries crt.sh for certificates covering an owned zone. The HTTP client
// is NOT scope-guarded: crt.sh is a public third-party index, not a probe
// target, and only the operator's own zone name is sent to it.
type CT struct {
	BaseURL   string        // default DefaultCTURL; overridable for tests
	HTTP      *http.Client  // default: client with Timeout
	UserAgent string        // default "deckard-ct/1"
	Timeout   time.Duration // per request, default 30s
	Retries   int           // extra attempts on 429/5xx/network errors, default 2
	Backoff   time.Duration // first retry delay, doubled each time, default 2s

	sleep func(ctx context.Context, d time.Duration) error // test hook
}

// CTOption configures a CT client.
type CTOption func(*CT)

// WithCTBaseURL overrides the crt.sh URL.
func WithCTBaseURL(u string) CTOption { return func(c *CT) { c.BaseURL = u } }

// WithCTHTTPClient injects the HTTP client.
func WithCTHTTPClient(h *http.Client) CTOption { return func(c *CT) { c.HTTP = h } }

// WithCTRetries sets the retry count and initial backoff.
func WithCTRetries(n int, backoff time.Duration) CTOption {
	return func(c *CT) { c.Retries, c.Backoff = n, backoff }
}

// WithCTTimeout sets the per-request timeout.
func WithCTTimeout(d time.Duration) CTOption { return func(c *CT) { c.Timeout = d } }

// WithCTUserAgent sets the User-Agent.
func WithCTUserAgent(ua string) CTOption { return func(c *CT) { c.UserAgent = ua } }

// NewCT builds a CT client with defaults.
func NewCT(opts ...CTOption) *CT {
	c := &CT{BaseURL: DefaultCTURL, UserAgent: "deckard-ct/1", Timeout: 30 * time.Second, Retries: 2, Backoff: 2 * time.Second}
	for _, o := range opts {
		o(c)
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: c.Timeout}
	}
	if c.sleep == nil {
		c.sleep = sleepCtx
	}
	return c
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type ctEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

// Names returns the distinct, lower-cased hostnames found in CT for zone,
// wildcard-stripped (*.example.com becomes example.com) and restricted to the
// zone itself and names beneath it. Anything else in a certificate's SAN list
// (other domains on a shared cert, e-mail addresses) is discarded.
func (c *CT) Names(ctx context.Context, zone string) ([]string, error) {
	zone = normName(zone)
	if zone == "" || !strings.Contains(zone, ".") {
		return nil, fmt.Errorf("ct: invalid zone %q", zone)
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("ct: base url: %w", err)
	}
	q := u.Query()
	q.Set("q", "%."+zone)
	q.Set("output", "json")
	u.RawQuery = q.Encode()

	body, err := c.fetch(ctx, u.String())
	if err != nil {
		return nil, err
	}
	var entries []ctEntry
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("ct: decode response: %w", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		for _, raw := range append(strings.Split(e.NameValue, "\n"), e.CommonName) {
			n := normName(strings.TrimPrefix(strings.TrimSpace(raw), "*."))
			if n == "" || !underZone(n, zone) || !validHostname(n) {
				continue
			}
			seen[n] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// UnavailableError is a transient failure of the CT source: a network error
// or timeout, a 429 or a 5xx, after the client's own retries. Asking again
// later may succeed; it says nothing about the zone.
type UnavailableError struct{ Err error }

func (e *UnavailableError) Error() string { return e.Err.Error() }
func (e *UnavailableError) Unwrap() error { return e.Err }

func (c *CT) fetch(ctx context.Context, u string) ([]byte, error) {
	var lastErr error
	delay := c.Backoff
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			if err := c.sleep(ctx, delay); err != nil {
				return nil, err
			}
			delay *= 2
		}
		body, retry, err := c.once(ctx, u)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func (c *CT) once(ctx context.Context, u string) (body []byte, retry bool, err error) {
	rctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, true, &UnavailableError{fmt.Errorf("ct: request: %w", err)}
	}
	defer func() { _ = resp.Body.Close() }()
	// crt.sh answers 200 with an empty list for a zone it has no certificates for;
	// in practice it also returns 404 and 408 when it is overloaded or its backend
	// is down, so those mean "try again later", not "this zone is unknown".
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusNotFound ||
		resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, true, &UnavailableError{fmt.Errorf("ct: status %d", resp.StatusCode)}
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, false, fmt.Errorf("ct: unexpected status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxCTBody+1))
	if err != nil {
		return nil, true, &UnavailableError{fmt.Errorf("ct: read body: %w", err)}
	}
	if len(b) > maxCTBody {
		return nil, false, errors.New("ct: response too large")
	}
	return b, false, nil
}

func normName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

func underZone(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// validHostname accepts LDH labels only; this rejects e-mail addresses,
// embedded wildcards and junk found in SAN lists.
func validHostname(n string) bool {
	if len(n) == 0 || len(n) > 253 {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if !validLabel(l) {
			return false
		}
	}
	return true
}

func validLabel(l string) bool {
	if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		ch := l[i]
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' && ch != '_' {
			return false
		}
	}
	return true
}
