package alertmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/notify"
)

const (
	batchSize        = 100
	defaultResend    = 5 * time.Minute
	defaultTimeout   = 10 * time.Second
	defaultAttempts  = 4
	defaultBackoff   = 500 * time.Millisecond
	maxBackoff       = 10 * time.Second
	maxErrBodyBytes  = 256
	alertsPathSuffix = "/api/v2/alerts"
)

var _ notify.Notifier = (*Notifier)(nil)

// Notifier posts findings to one or more Alertmanager instances.
type Notifier struct {
	endpoints []string // full POST URLs
	display   []string // redacted URLs, safe to log
	resend    time.Duration
	timeout   time.Duration
	user      string
	pass      string
	baseURL   string
	client    *http.Client
	now       func() time.Time
	attempts  int
	backoff   time.Duration
	log       *slog.Logger
}

// Option customises a Notifier.
type Option func(*Notifier)

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(c *http.Client) Option { return func(n *Notifier) { n.client = c } }

// WithClock overrides the time source.
func WithClock(now func() time.Time) Option { return func(n *Notifier) { n.now = now } }

// WithBaseURL sets deckard's public base URL used for the "url" annotation.
func WithBaseURL(u string) Option { return func(n *Notifier) { n.baseURL = u } }

// WithRetry sets the max attempts per request and the initial backoff.
func WithRetry(attempts int, base time.Duration) Option {
	return func(n *Notifier) {
		if attempts > 0 {
			n.attempts = attempts
		}
		if base > 0 {
			n.backoff = base
		}
	}
}

// New builds a Notifier. The basic-auth password is read from the
// environment variable named by cfg.PasswordEnv and never logged.
func New(cfg config.AlertmanagerConfig, getenv func(string) string, log *slog.Logger, opts ...Option) (*Notifier, error) {
	if len(cfg.URLs) == 0 {
		return nil, errors.New("alertmanager: no urls configured")
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	n := &Notifier{
		resend: cfg.Resend, timeout: cfg.Timeout, user: cfg.Username,
		client: &http.Client{}, now: time.Now,
		attempts: defaultAttempts, backoff: defaultBackoff, log: log,
	}
	if n.resend <= 0 {
		n.resend = defaultResend
	}
	if n.timeout <= 0 {
		n.timeout = defaultTimeout
	}
	for _, raw := range cfg.URLs {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("alertmanager: invalid url %q", redactRaw(raw))
		}
		n.display = append(n.display, u.Redacted())
		n.endpoints = append(n.endpoints, strings.TrimRight(u.String(), "/")+alertsPathSuffix)
	}
	if cfg.PasswordEnv != "" {
		if getenv == nil {
			return nil, errors.New("alertmanager: getenv is nil")
		}
		n.pass = getenv(cfg.PasswordEnv)
		if n.pass == "" {
			return nil, fmt.Errorf("alertmanager: env %s (password_env) is empty", cfg.PasswordEnv)
		}
	}
	for _, o := range opts {
		o(n)
	}
	return n, nil
}

func redactRaw(s string) string {
	if u, err := url.Parse(s); err == nil {
		return u.Redacted()
	}
	return "<unparseable>"
}

// Name implements notify.Notifier.
func (n *Notifier) Name() string { return "alertmanager" }

// Notify re-asserts every open finding and reports the resolved ones. It is
// idempotent: each call is a full re-assert. Findings not in StatusOpen are
// never sent as open. It succeeds if every batch was accepted by at least
// one Alertmanager.
func (n *Notifier) Notify(ctx context.Context, open []model.Finding, resolved []model.Finding) error {
	alerts := buildPayload(open, resolved, n.now(), n.resend, n.baseURL)
	var errs []error
	for start := 0; start < len(alerts); start += batchSize {
		end := min(start+batchSize, len(alerts))
		if err := n.sendBatch(ctx, alerts[start:end]); err != nil {
			errs = append(errs, err)
			if ctx.Err() != nil {
				break
			}
		}
	}
	return errors.Join(errs...)
}

// sendBatch posts to all Alertmanagers concurrently.
func (n *Notifier) sendBatch(ctx context.Context, batch []postableAlert) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("alertmanager: marshal: %w", err)
	}
	errs := make([]error, len(n.endpoints))
	var wg sync.WaitGroup
	for i := range n.endpoints {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = n.postWithRetry(ctx, n.endpoints[i], body)
			if errs[i] != nil {
				n.log.Warn("alertmanager push failed", "url", n.display[i], "alerts", len(batch), "error", errs[i])
			}
		}()
	}
	wg.Wait()
	for _, e := range errs {
		if e == nil {
			return nil
		}
	}
	return fmt.Errorf("alertmanager: all %d endpoints failed: %w", len(errs), errors.Join(errs...))
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string { return fmt.Sprintf("status %d: %s", e.code, e.body) }

func retryable(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.code >= 500 || se.code == http.StatusTooManyRequests
	}
	return true // network error / timeout
}

func (n *Notifier) postWithRetry(ctx context.Context, endpoint string, body []byte) error {
	var err error
	for attempt := 0; attempt < n.attempts; attempt++ {
		if attempt > 0 {
			d := n.backoff << (attempt - 1)
			if d > maxBackoff || d <= 0 {
				d = maxBackoff
			}
			d = d/2 + time.Duration(rand.Int64N(int64(d/2)+1)) // #nosec G404 -- retry jitter, not security sensitive
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return fmt.Errorf("%w (last error: %v)", ctx.Err(), err)
			case <-t.C:
			}
		}
		if err = n.post(ctx, endpoint, body); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("%w (last error: %v)", ctx.Err(), err)
		}
		if !retryable(err) {
			return err
		}
	}
	return fmt.Errorf("after %d attempts: %w", n.attempts, err)
}

func (n *Notifier) post(ctx context.Context, endpoint string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return &statusError{code: 400, body: "bad request: " + err.Error()} // not retryable
	}
	req.Header.Set("Content-Type", "application/json")
	if n.user != "" || n.pass != "" {
		req.SetBasicAuth(n.user, n.pass)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		// url.Error embeds the URL; strip userinfo defensively.
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("%s %s: %w", ue.Op, redactRaw(ue.URL), ue.Err)
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBodyBytes))
	return &statusError{code: resp.StatusCode, body: strings.TrimSpace(string(b))}
}
