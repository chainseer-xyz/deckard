package vulnintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DefaultKEVURL is CISA's KEV JSON feed.
const DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

const (
	defaultKEVMaxBytes = 20 << 20
	// minKEVRatio is the smallest fraction of the previous good catalog a new
	// download may have; anything smaller is treated as truncated/corrupt.
	minKEVRatio = 0.5
)

// KEVEntry is one catalog record.
type KEVEntry struct {
	CVE            string `json:"cve"`
	VendorProject  string `json:"vendor_project,omitempty"`
	Product        string `json:"product,omitempty"`
	DateAdded      string `json:"date_added,omitempty"` // YYYY-MM-DD
	DueDate        string `json:"due_date,omitempty"`
	RequiredAction string `json:"required_action,omitempty"`
	Ransomware     bool   `json:"ransomware"`
}

type kevFile struct {
	Title           string `json:"title"`
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Count           *int   `json:"count"`
	Vulnerabilities []struct {
		CVEID          string `json:"cveID"`
		VendorProject  string `json:"vendorProject"`
		Product        string `json:"product"`
		DateAdded      string `json:"dateAdded"`
		RequiredAction string `json:"requiredAction"`
		DueDate        string `json:"dueDate"`
		Ransomware     string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// ParseKEV parses and validates a KEV catalog body. It rejects invalid JSON,
// an empty catalog, a declared count that disagrees with the entries
// (truncation) and catalogs where more than 10% of entries are malformed.
// Malformed entries are dropped. Entries are sorted by CVE id.
func ParseKEV(body []byte) ([]KEVEntry, error) {
	var f kevFile
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("kev: invalid json: %w", err)
	}
	if len(f.Vulnerabilities) == 0 {
		return nil, errors.New("kev: catalog has no vulnerabilities")
	}
	if f.Count != nil && *f.Count != len(f.Vulnerabilities) {
		return nil, fmt.Errorf("kev: declared count %d != %d entries", *f.Count, len(f.Vulnerabilities))
	}
	seen := map[string]bool{}
	out := make([]KEVEntry, 0, len(f.Vulnerabilities))
	bad := 0
	for _, v := range f.Vulnerabilities {
		id, ok := NormalizeCVE(v.CVEID)
		if !ok {
			bad++
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, KEVEntry{
			CVE: id, VendorProject: v.VendorProject, Product: v.Product,
			DateAdded: v.DateAdded, DueDate: v.DueDate, RequiredAction: v.RequiredAction,
			Ransomware: strings.EqualFold(strings.TrimSpace(v.Ransomware), "known"),
		})
	}
	if bad*10 > len(f.Vulnerabilities) || len(out) == 0 {
		return nil, fmt.Errorf("kev: %d of %d entries malformed", bad, len(f.Vulnerabilities))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVE < out[j].CVE })
	return out, nil
}

// ValidateShrink rejects a catalog that shrank by more than half against the
// last good one (prevCount 0 = no previous copy, always fine).
func ValidateShrink(prevCount, newCount int) error {
	if prevCount > 0 && float64(newCount) < float64(prevCount)*minKEVRatio {
		return fmt.Errorf("kev: catalog shrank from %d to %d entries (>50%%), rejecting", prevCount, newCount)
	}
	return nil
}

// KEVClient downloads the KEV catalog.
type KEVClient struct {
	url string
	f   fetcher
}

// ClientOption tunes a KEVClient or EPSSClient.
type ClientOption func(*clientOpts)

type clientOpts struct {
	httpClient *http.Client
	userAgent  string
	maxBytes   int64
	attempts   int
	backoff    time.Duration
	sleep      func(context.Context, time.Duration) error
	minGap     time.Duration
	batchSize  int
}

// WithHTTPClient sets the HTTP client (redirects to non-https stay refused).
func WithHTTPClient(c *http.Client) ClientOption { return func(o *clientOpts) { o.httpClient = c } }

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) ClientOption { return func(o *clientOpts) { o.userAgent = ua } }

// WithMaxBytes caps the accepted response size.
func WithMaxBytes(n int64) ClientOption { return func(o *clientOpts) { o.maxBytes = n } }

// WithRetry sets the attempt count and initial backoff; sleep may be nil.
func WithRetry(attempts int, backoff time.Duration, sleep func(context.Context, time.Duration) error) ClientOption {
	return func(o *clientOpts) { o.attempts, o.backoff, o.sleep = attempts, backoff, sleep }
}

// WithMinGap sets the minimum pause between EPSS batch requests.
func WithMinGap(d time.Duration) ClientOption { return func(o *clientOpts) { o.minGap = d } }

func buildClientOpts(opts []ClientOption, defMax int64) clientOpts {
	o := clientOpts{maxBytes: defMax, minGap: time.Second, batchSize: epssBatchSize}
	for _, f := range opts {
		f(&o)
	}
	if o.httpClient == nil {
		o.httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	o.httpClient = secureClient(o.httpClient)
	return o
}

// NewKEVClient builds a client for url (https only; "" = DefaultKEVURL).
func NewKEVClient(url string, opts ...ClientOption) (*KEVClient, error) {
	if url == "" {
		url = DefaultKEVURL
	}
	if err := httpsOnly(url); err != nil {
		return nil, err
	}
	o := buildClientOpts(opts, defaultKEVMaxBytes)
	return &KEVClient{url: url, f: fetcher{client: o.httpClient, userAgent: o.userAgent, maxBytes: o.maxBytes, attempts: o.attempts, backoff: o.backoff, sleep: o.sleep}}, nil
}

// KEVFetch is the result of a catalog download.
type KEVFetch struct {
	NotModified  bool
	Body         []byte // raw validated body (empty when NotModified)
	Entries      []KEVEntry
	ETag         string
	LastModified string
}

// Fetch downloads the catalog, sending If-None-Match/If-Modified-Since when
// given. A 304 yields NotModified. The body is parsed and validated.
func (c *KEVClient) Fetch(ctx context.Context, etag, lastModified string) (KEVFetch, error) {
	resp, err := c.f.get(ctx, c.url, map[string]string{"If-None-Match": etag, "If-Modified-Since": lastModified})
	if err != nil {
		return KEVFetch{}, fmt.Errorf("kev fetch: %w", err)
	}
	if resp.status == http.StatusNotModified {
		return KEVFetch{NotModified: true, ETag: etag, LastModified: lastModified}, nil
	}
	entries, err := ParseKEV(resp.body)
	if err != nil {
		return KEVFetch{}, err
	}
	return KEVFetch{Body: resp.body, Entries: entries, ETag: resp.header.Get("ETag"), LastModified: resp.header.Get("Last-Modified")}, nil
}
