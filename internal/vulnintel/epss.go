package vulnintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultEPSSURL is FIRST's EPSS API endpoint.
const DefaultEPSSURL = "https://api.first.org/data/v1/epss"

const (
	epssBatchSize       = 100
	defaultEPSSMaxBytes = 5 << 20
)

// EPSSScore is one CVE's exploit-prediction score.
type EPSSScore struct {
	Score      float64
	Percentile float64
}

type epssResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Data       []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// ParseEPSS parses an EPSS API response. Entries with malformed ids or scores
// outside [0,1] are dropped.
func ParseEPSS(body []byte) (map[string]EPSSScore, error) {
	var r epssResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("epss: invalid json: %w", err)
	}
	if r.Status != "" && !strings.EqualFold(r.Status, "OK") {
		return nil, fmt.Errorf("epss: status %q", r.Status)
	}
	if r.Status == "" && r.StatusCode == 0 && r.Data == nil {
		return nil, errors.New("epss: unrecognised response")
	}
	out := make(map[string]EPSSScore, len(r.Data))
	for _, d := range r.Data {
		id, ok := NormalizeCVE(d.CVE)
		if !ok {
			continue
		}
		s, e1 := strconv.ParseFloat(d.EPSS, 64)
		p, e2 := strconv.ParseFloat(d.Percentile, 64)
		if e1 != nil || e2 != nil || s < 0 || s > 1 || p < 0 || p > 1 {
			continue
		}
		out[id] = EPSSScore{Score: s, Percentile: p}
	}
	return out, nil
}

// EPSSClient queries the EPSS API.
type EPSSClient struct {
	url     string
	f       fetcher
	minGap  time.Duration
	batch   int
	lastReq time.Time
	sleep   func(context.Context, time.Duration) error
}

// NewEPSSClient builds a client for url (https only; "" = DefaultEPSSURL).
func NewEPSSClient(rawURL string, opts ...ClientOption) (*EPSSClient, error) {
	if rawURL == "" {
		rawURL = DefaultEPSSURL
	}
	if err := httpsOnly(rawURL); err != nil {
		return nil, err
	}
	o := buildClientOpts(opts, defaultEPSSMaxBytes)
	c := &EPSSClient{url: rawURL, minGap: o.minGap, batch: o.batchSize, sleep: o.sleep,
		f: fetcher{client: o.httpClient, userAgent: o.userAgent, maxBytes: o.maxBytes, attempts: o.attempts, backoff: o.backoff, sleep: o.sleep}}
	if c.sleep == nil {
		c.sleep = sleepCtx
	}
	return c, nil
}

// Lookup fetches scores for cves in batches of at most 100, pausing minGap
// between requests. It returns the scores for every CVE the API knows and the
// ids whose batch succeeded (answered); an answered CVE absent from scores is
// unknown to EPSS. Failed batches are skipped and reported in the joined error
// while other results are still returned.
// Not safe for concurrent use.
func (c *EPSSClient) Lookup(ctx context.Context, cves []string) (scores map[string]EPSSScore, answered []string, err error) {
	ids := make([]string, 0, len(cves))
	seen := map[string]bool{}
	for _, id := range cves {
		if n, ok := NormalizeCVE(id); ok && !seen[n] {
			seen[n] = true
			ids = append(ids, n)
		}
	}
	out := map[string]EPSSScore{}
	var errs []error
	var done []string
	for start := 0; start < len(ids); start += c.batch {
		end := min(start+c.batch, len(ids))
		if !c.lastReq.IsZero() && c.minGap > 0 {
			if wait := c.minGap - time.Since(c.lastReq); wait > 0 {
				if err := c.sleep(ctx, wait); err != nil {
					return out, done, errors.Join(append(errs, err)...)
				}
			}
		}
		c.lastReq = time.Now()
		// ids are validated CVE ids, so the comma-joined list is URL-safe.
		resp, err := c.f.get(ctx, c.url+"?cve="+url.QueryEscape(strings.Join(ids[start:end], ",")), nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("epss batch: %w", err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		got, err := ParseEPSS(resp.body)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for k, v := range got {
			out[k] = v
		}
		done = append(done, ids[start:end]...)
	}
	return out, done, errors.Join(errs...)
}
