// Package heartbeat pings an external dead-man's switch (healthchecks.io,
// a PagerDuty heartbeat, Cronitor, ...) while deckard is healthy. Prometheus
// and Alertmanager usually run next to deckard, so an outage of the whole
// cluster silences every alert; a monitor outside it notices the pings stop.
//
// Pings are sent only while healthy: the database answers AND a check run
// completed without error within the last two intervals. A wedged scheduler
// or worker therefore stops the pings, which is the point.
package heartbeat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
)

// Results of one beat, as counted in deckard_heartbeat_total{result}.
const (
	ResultOK        = "ok"        // healthy and the ping was accepted
	ResultError     = "error"     // healthy, but the ping failed
	ResultUnhealthy = "unhealthy" // not pinged: deckard is not healthy
)

// Health is what the heartbeat checks before pinging (*postgres.Store).
type Health interface {
	Ping(ctx context.Context) error
	// LastCleanScan is when the latest check run that completed without
	// error finished (zero if none).
	LastCleanScan(ctx context.Context) (time.Time, error)
}

// Pinger sends the heartbeat. Build it with New and call Run.
type Pinger struct {
	url      string // secret: never logged
	display  string // scheme://host, safe to log
	method   string
	interval time.Duration
	timeout  time.Duration
	health   Health
	client   *http.Client
	log      *slog.Logger
	now      func() time.Time
	record   func(result string)
	ua       string
}

// Option customises a Pinger.
type Option func(*Pinger)

// WithHTTPClient replaces the HTTP client (tests).
func WithHTTPClient(c *http.Client) Option { return func(p *Pinger) { p.client = c } }

// WithClock replaces the time source (tests).
func WithClock(now func() time.Time) Option { return func(p *Pinger) { p.now = now } }

// WithRecorder receives the result of every beat (the metrics counter).
func WithRecorder(f func(result string)) Option { return func(p *Pinger) { p.record = f } }

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option { return func(p *Pinger) { p.ua = ua } }

// New builds a Pinger from a validated config. Errors never contain the URL.
func New(cfg config.HeartbeatConfig, h Health, log *slog.Logger, opts ...Option) (*Pinger, error) {
	if h == nil {
		return nil, errors.New("heartbeat: no health source")
	}
	u, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("heartbeat: url must be an absolute http(s) URL")
	}
	method := strings.ToUpper(strings.TrimSpace(cfg.Method))
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost {
		return nil, fmt.Errorf("heartbeat: method %q must be GET or POST", cfg.Method)
	}
	if cfg.Interval <= 0 || cfg.Timeout <= 0 {
		return nil, errors.New("heartbeat: interval and timeout must be > 0")
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	p := &Pinger{
		url: u.String(), display: Redact(u), method: method,
		interval: cfg.Interval, timeout: cfg.Timeout, health: h,
		client: &http.Client{}, log: log, now: time.Now, record: func(string) {}, ua: "deckard",
	}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Redact reduces a heartbeat URL to scheme://host. Userinfo and the query
// string are secrets, and services like healthchecks.io put the token in the
// path, so only the host is ever logged.
func Redact(u *url.URL) string {
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}

// Run beats once immediately and then every interval until ctx is done.
func (p *Pinger) Run(ctx context.Context) {
	p.log.Info("heartbeat enabled", "url", p.display, "method", p.method, "interval", p.interval)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		p.Beat(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Beat checks health and, if healthy, pings once. It returns the result.
func (p *Pinger) Beat(ctx context.Context) string {
	if ctx.Err() != nil {
		return ""
	}
	if why := p.unhealthy(ctx); why != "" {
		if ctx.Err() != nil { // shutting down: say nothing
			return ""
		}
		p.log.Warn("heartbeat withheld: deckard is not healthy", "reason", why, "url", p.display)
		p.record(ResultUnhealthy)
		return ResultUnhealthy
	}
	if err := p.ping(ctx); err != nil {
		if ctx.Err() != nil {
			return ""
		}
		p.log.Warn("heartbeat ping failed", "url", p.display, "error", err)
		p.record(ResultError)
		return ResultError
	}
	p.record(ResultOK)
	return ResultOK
}

// unhealthy returns why deckard should not vouch for itself, or "".
func (p *Pinger) unhealthy(ctx context.Context) string {
	hctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	if err := p.health.Ping(hctx); err != nil {
		return "database unreachable: " + err.Error()
	}
	last, err := p.health.LastCleanScan(hctx)
	if err != nil {
		return "database query failed: " + err.Error()
	}
	window := 2 * p.interval
	if last.IsZero() {
		return "no check has completed yet"
	}
	if age := p.now().Sub(last); age > window {
		return fmt.Sprintf("no check completed in the last %s (latest %s ago)", window, age.Round(time.Second))
	}
	return ""
}

// ping sends one request. Errors are scrubbed of the URL.
func (p *Pinger) ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	var body io.Reader
	if p.method == http.MethodPost {
		body = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, p.method, p.url, body)
	if err != nil {
		return errors.New("build request failed")
	}
	req.Header.Set("User-Agent", p.ua)
	resp, err := p.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			// url.Error embeds the full URL (token included): keep only the
			// operation and the cause.
			return fmt.Errorf("%s: %w", ue.Op, ue.Err)
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
