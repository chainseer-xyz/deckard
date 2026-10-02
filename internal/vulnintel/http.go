package vulnintel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const defaultUserAgent = "deckard-vulnintel (defensive attack-surface monitor; +https://github.com/chainseer-xyz/deckard)"

// errTooLarge is returned when a feed body exceeds its size cap.
var errTooLarge = errors.New("response exceeds size cap")

// httpDoer is the subset of *http.Client the clients use.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// fetcher performs capped, retried GETs.
type fetcher struct {
	client    httpDoer
	userAgent string
	maxBytes  int64
	attempts  int
	backoff   time.Duration
	sleep     func(ctx context.Context, d time.Duration) error
}

func (f *fetcher) defaults() {
	if f.userAgent == "" {
		f.userAgent = defaultUserAgent
	}
	if f.attempts < 1 {
		f.attempts = 3
	}
	if f.backoff <= 0 {
		f.backoff = 2 * time.Second
	}
	if f.sleep == nil {
		f.sleep = sleepCtx
	}
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

// httpsOnly rejects non-https URLs.
func httpsOnly(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-https url %q", u.Redacted())
	}
	return nil
}

// secureClient copies c so redirects to non-https are refused.
func secureClient(c *http.Client) *http.Client {
	cp := *c
	prev := c.CheckRedirect
	cp.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("refusing redirect to non-https url")
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if prev != nil {
			return prev(req, via)
		}
		return nil
	}
	return &cp
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// get GETs rawURL with extra request headers. 2xx and 304 return a response;
// 429/5xx and transport errors are retried with exponential backoff
// (honouring Retry-After, capped); other statuses fail immediately.
func (f *fetcher) get(ctx context.Context, rawURL string, hdr map[string]string) (*response, error) {
	f.defaults()
	var lastErr error
	delay := f.backoff
	for attempt := 1; attempt <= f.attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", f.userAgent)
		req.Header.Set("Accept", "application/json")
		for k, v := range hdr {
			if v != "" {
				req.Header.Set(k, v)
			}
		}
		var retryAfter time.Duration
		resp, err := f.client.Do(req) // #nosec G704 -- URL is a fixed https feed endpoint validated by httpsOnly
		if err != nil {
			lastErr = err
		} else {
			body, rerr := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
			_ = resp.Body.Close()
			switch {
			case rerr != nil:
				lastErr = rerr
			case int64(len(body)) > f.maxBytes:
				return nil, errTooLarge
			case resp.StatusCode == http.StatusNotModified || (resp.StatusCode >= 200 && resp.StatusCode < 300):
				return &response{status: resp.StatusCode, header: resp.Header, body: body}, nil
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
				lastErr = fmt.Errorf("http %d", resp.StatusCode)
				if s, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && s > 0 {
					retryAfter = time.Duration(s) * time.Second
				}
			default:
				return nil, fmt.Errorf("http %d", resp.StatusCode)
			}
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt == f.attempts {
			break
		}
		wait := max(delay, retryAfter)
		if wait > time.Minute {
			wait = time.Minute
		}
		if err := f.sleep(ctx, wait); err != nil {
			return nil, err
		}
		delay *= 2
	}
	return nil, fmt.Errorf("after %d attempts: %w", f.attempts, lastErr)
}
