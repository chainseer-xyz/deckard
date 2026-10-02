// Package refdata keeps deckard's embedded reference datasets (takeover
// fingerprints, shared-infrastructure ranges) fresh without a release.
//
// Every dataset has an embedded fallback that is always available. A refresh
// downloads the published sources over HTTPS, validates the result (it must
// parse, meet a minimum size and must not shrink suspiciously) and only then
// swaps it in atomically and persists it so a restart does not need the
// network. A bad download never replaces good data.
package refdata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Errors returned by the fetcher.
var (
	ErrNotHTTPS = errors.New("refdata: only https URLs are allowed")
	ErrTooLarge = errors.New("refdata: response exceeds size limit")
)

// DefaultMaxBytes caps one response body.
const DefaultMaxBytes = 10 << 20

const maxRedirects = 5

// Validators carry the conditional-request state of one URL.
type Validators struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// Fetched is the outcome of one conditional GET.
type Fetched struct {
	Body        []byte
	NotModified bool
	Validators  Validators
}

// Fetcher performs bounded, HTTPS-only, credential-free downloads.
type Fetcher struct {
	// Client is the transport; nil uses a fresh client. Its redirect policy
	// is always replaced by the https-only one.
	Client    *http.Client
	UserAgent string
	MaxBytes  int64
	// Timeout bounds each attempt (default 30s).
	Timeout time.Duration
	// Attempts is the number of tries per URL (default 3).
	Attempts int
	// Backoff is the base delay, doubled per retry (default 1s).
	Backoff time.Duration
}

func (f *Fetcher) client() *http.Client {
	var c http.Client
	if f.Client != nil {
		c = *f.Client
	}
	c.Jar = nil
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("%w: redirect to %s", ErrNotHTTPS, req.URL.Redacted())
		}
		if len(via) >= maxRedirects {
			return errors.New("refdata: too many redirects")
		}
		return nil
	}
	return &c
}

// Get fetches rawURL, sending If-None-Match / If-Modified-Since when v has
// them. Transient failures (network errors, 429, 5xx) are retried with
// exponential backoff.
func (f *Fetcher) Get(ctx context.Context, rawURL string, v Validators) (Fetched, error) {
	u, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return Fetched{}, fmt.Errorf("%w: %q", ErrNotHTTPS, rawURL)
	}
	attempts := f.Attempts
	if attempts < 1 {
		attempts = 3
	}
	backoff := f.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	c := f.client()
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			t := time.NewTimer(backoff << (i - 1))
			select {
			case <-ctx.Done():
				t.Stop()
				return Fetched{}, ctx.Err()
			case <-t.C:
			}
		}
		res, retry, err := f.once(ctx, c, u.String(), v)
		if err == nil {
			return res, nil
		}
		last = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	return Fetched{}, last
}

func (f *Fetcher) once(ctx context.Context, c *http.Client, rawURL string, v Validators) (Fetched, bool, error) {
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Fetched{}, false, err
	}
	ua := f.UserAgent
	if ua == "" {
		ua = "deckard-refdata"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if v.ETag != "" {
		req.Header.Set("If-None-Match", v.ETag)
	}
	if v.LastModified != "" {
		req.Header.Set("If-Modified-Since", v.LastModified)
	}
	resp, err := c.Do(req) // #nosec G107 G704 -- URL is a fixed https-only dataset source; redirects are https-only
	if err != nil {
		return Fetched{}, !errors.Is(err, ErrNotHTTPS), err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return Fetched{NotModified: true, Validators: v}, false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return Fetched{}, true, fmt.Errorf("refdata: %s: HTTP %d", redact(rawURL), resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return Fetched{}, false, fmt.Errorf("refdata: %s: HTTP %d", redact(rawURL), resp.StatusCode)
	}
	max := f.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if resp.ContentLength > max {
		return Fetched{}, false, fmt.Errorf("%w (%d > %d)", ErrTooLarge, resp.ContentLength, max)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return Fetched{}, true, fmt.Errorf("refdata: read %s: %w", redact(rawURL), err)
	}
	if int64(len(body)) > max {
		return Fetched{}, false, fmt.Errorf("%w (> %d bytes)", ErrTooLarge, max)
	}
	return Fetched{Body: body, Validators: Validators{
		ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"),
	}}, false, nil
}

func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<url>"
	}
	return u.Redacted()
}
