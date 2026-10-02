package checkutil

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

// DefaultMaxBody caps how much of a response body any check reads.
const DefaultMaxBody int64 = 1 << 20 // 1 MiB

// UserAgent identifies deckard to the operator's own servers.
const UserAgent = "deckard/1.0 (defensive attack-surface monitor)"

// Hop is one request/response in a redirect chain.
type Hop struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
}

// Response is a fetched page with its redirect chain.
type Response struct {
	Hops      []Hop
	FinalURL  string
	Status    int
	Header    http.Header
	Body      []byte
	Truncated bool
	TLS       bool
}

// FetchOpts tunes Fetch.
type FetchOpts struct {
	Header  http.Header
	MaxBody int64
	Timeout time.Duration
}

type recorder struct {
	inner http.RoundTripper
	hops  *[]Hop
}

func (r recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.inner.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	*r.hops = append(*r.hops, Hop{URL: req.URL.String(), Status: resp.StatusCode, Location: resp.Header.Get("Location")})
	return resp, nil
}

// Fetch GETs rawURL with the supplied (scope-guarded) client. The client is
// shallow-copied with a recording transport wrapper so its redirect policy and
// guard stay intact while every hop is observed. The body is capped.
func Fetch(ctx context.Context, client *http.Client, rawURL string, o FetchOpts) (*Response, error) {
	if client == nil {
		return nil, errors.New("no http client in target")
	}
	if o.MaxBody <= 0 {
		o.MaxBody = DefaultMaxBody
	}
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	var hops []Hop
	inner := client.Transport
	if inner == nil {
		inner = http.DefaultTransport
	}
	c := *client
	c.Transport = recorder{inner: inner, hops: &hops}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	for k, v := range o.Header {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, o.MaxBody+1))
	if err != nil && len(body) == 0 {
		return nil, err
	}
	trunc := int64(len(body)) > o.MaxBody
	if trunc {
		body = body[:o.MaxBody]
	}
	return &Response{
		Hops: hops, FinalURL: resp.Request.URL.String(), Status: resp.StatusCode,
		Header: resp.Header, Body: body, Truncated: trunc, TLS: resp.TLS != nil,
	}, nil
}
