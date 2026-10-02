package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the production Cloudflare v4 API.
	DefaultBaseURL = "https://api.cloudflare.com/client/v4"

	defaultTimeout    = 30 * time.Second
	defaultMaxRetries = 4
	defaultBackoff    = 500 * time.Millisecond
	maxRetryWait      = 30 * time.Second
	perPage           = 50
	maxPages          = 10000
	maxBody           = 32 << 20
)

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []apiMessage    `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *resultInfo     `json:"result_info"`
}

type apiMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

// apiError is a non-success response from the API. It never contains the
// request token: only the status and Cloudflare's own error messages.
type apiError struct {
	Status   int
	Path     string
	Messages []string
}

func (e *apiError) Error() string {
	msg := strings.Join(e.Messages, "; ")
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("cloudflare: GET %s: status %d: %s", e.Path, e.Status, msg)
}

// notAvailable reports whether the error means the feature is not usable with
// this token or plan (as opposed to a transient or server failure).
func (e *apiError) notAvailable() bool {
	switch e.Status {
	case http.StatusForbidden, http.StatusNotFound:
		return true
	case http.StatusBadRequest:
		m := strings.ToLower(strings.Join(e.Messages, " "))
		return strings.Contains(m, "not enabled") || strings.Contains(m, "not entitled") ||
			strings.Contains(m, "not available") || strings.Contains(m, "not subscribed")
	}
	return false
}

type client struct {
	base       string
	token      string
	http       *http.Client
	log        *slog.Logger
	maxRetries int
	backoff    time.Duration
}

func (c *client) redact(s string) string {
	if c.token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.token, "[REDACTED]")
}

// get performs one GET with retry on 429/5xx/network errors and returns the
// decoded envelope.
func (c *client) get(ctx context.Context, path string, q url.Values) (*envelope, error) {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			wait := c.backoff << (attempt - 1)
			var ra *retryAfterError
			if errors.As(lastErr, &ra) && ra.wait > 0 {
				wait = ra.wait
			}
			if wait > maxRetryWait {
				wait = maxRetryWait
			}
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}
		env, err := c.do(ctx, u, path)
		if err == nil {
			return env, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var ra *retryAfterError
		if errors.As(err, &ra) {
			lastErr = ra
			continue
		}
		return nil, err
	}
	var ra *retryAfterError
	if errors.As(lastErr, &ra) {
		return nil, ra.err
	}
	return nil, lastErr
}

// retryAfterError wraps a retryable failure with the server's wait hint.
type retryAfterError struct {
	err  error
	wait time.Duration
}

func (r *retryAfterError) Error() string { return r.err.Error() }
func (r *retryAfterError) Unwrap() error { return r.err }

func (c *client) do(ctx context.Context, u, path string) (*envelope, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: build request %s: %s", path, c.redact(err.Error()))
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "deckard")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Transport errors are retryable; strip the URL-bearing wrapper text of
		// anything token-like.
		return nil, &retryAfterError{err: fmt.Errorf("cloudflare: GET %s: %s", path, c.redact(err.Error()))}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &retryAfterError{err: fmt.Errorf("cloudflare: read %s: %s", path, c.redact(err.Error()))}
	}
	var env envelope
	jerr := json.Unmarshal(body, &env)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if jerr != nil {
			return nil, fmt.Errorf("cloudflare: decode %s: %w", path, jerr)
		}
		if !env.Success {
			return nil, &apiError{Status: resp.StatusCode, Path: path, Messages: c.messages(env.Errors)}
		}
		return &env, nil
	}
	ae := &apiError{Status: resp.StatusCode, Path: path}
	if jerr == nil {
		ae.Messages = c.messages(env.Errors)
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return nil, &retryAfterError{err: ae, wait: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
	}
	return nil, ae
}

func (c *client) messages(in []apiMessage) []string {
	out := make([]string, 0, len(in))
	for _, m := range in {
		out = append(out, c.redact(fmt.Sprintf("%s (code %d)", m.Message, m.Code)))
	}
	return out
}

// parseRetryAfter understands both delta-seconds and HTTP-date forms. Zero
// means "no usable hint".
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

// listAll fetches every page of a list endpoint and decodes the results.
func listAll[T any](ctx context.Context, c *client, path string, q url.Values, pageSize int) ([]T, error) {
	var out []T
	for page := 1; page <= maxPages; page++ {
		qq := url.Values{}
		for k, v := range q {
			qq[k] = v
		}
		qq.Set("page", strconv.Itoa(page))
		qq.Set("per_page", strconv.Itoa(pageSize))
		env, err := c.get(ctx, path, qq)
		if err != nil {
			return nil, err
		}
		var items []T
		if len(env.Result) > 0 && string(env.Result) != "null" {
			if err := json.Unmarshal(env.Result, &items); err != nil {
				return nil, fmt.Errorf("cloudflare: decode %s page %d: %w", path, page, err)
			}
		}
		out = append(out, items...)
		if env.ResultInfo == nil || page >= env.ResultInfo.TotalPages || len(items) == 0 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("cloudflare: %s: exceeded %d pages", path, maxPages)
}
