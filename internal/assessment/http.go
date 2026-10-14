package assessment

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
)

// Do executes a bounded HTTP request through the active-tier owned dialer.
// It never uses environment proxies, transparent CONNECT tunnels, streaming
// protocols or caller-supplied transports. Returned bodies are already bounded
// and buffered; the caller must close them as with ordinary HTTP responses.
func (p *Policy) Do(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, p.fail("missing HTTP request")
	}
	// Serialize buffered requests so concurrent scanner callers cannot multiply
	// the bounded body buffers or oversubscribe the shared session byte budget.
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-p.ctx.Done():
		return nil, p.fail("assessment session ended")
	case <-request.Context().Done():
		return nil, p.fail("HTTP request context canceled")
	}
	response, err := p.client.Do(request) // #nosec G704 -- private transport authorizes exact origins and dials only live owned IPs
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, p.fail("HTTP request did not complete")
	}
	return response, nil
}

type policyTransport struct {
	policy *Policy
	base   http.RoundTripper
}

func (t *policyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	p := t.policy
	if request.Method == http.MethodConnect || request.Header.Get("Upgrade") != "" ||
		request.Header.Get("Proxy-Authorization") != "" || request.Header.Get("Host") != "" {
		return nil, p.fail("unsupported HTTP tunnel or authority override")
	}
	u, err := p.AuthorizeURL(request.Context(), request.URL.String())
	if err != nil {
		return nil, err
	}
	if request.Host != "" {
		_, requestedOrigin, err := normalizeURL(u.Scheme + "://" + request.Host)
		if err != nil || requestedOrigin != u.Scheme+"://"+u.Host {
			return nil, p.fail("HTTP Host override is not permitted")
		}
	}
	ctx, cancel := context.WithCancel(p.ctx)
	stop := context.AfterFunc(request.Context(), cancel)
	defer func() { stop(); cancel() }()
	cloned := request.Clone(ctx)
	cloned.URL = u
	cloned.Host = ""
	var headerBytes int64
	for name, values := range cloned.Header {
		for _, value := range values {
			headerBytes += int64(len(name) + len(value) + 4)
		}
	}
	headerBytes += int64(len(cloned.Method) + len(u.RequestURI()) + len(u.Host))
	p.mu.Lock()
	remaining := p.limits.MaxRequestBytes - p.requestBytes - headerBytes
	if p.err != nil || p.requests >= p.limits.MaxRequests || remaining < 0 {
		p.mu.Unlock()
		return nil, p.fail("request budget exceeded")
	}
	p.requests++
	p.requestBytes += headerBytes
	p.mu.Unlock()
	var body []byte
	if request.Body != nil {
		stopBody := context.AfterFunc(ctx, func() { _ = request.Body.Close() })
		body, err = io.ReadAll(io.LimitReader(request.Body, remaining+1))
		stopBody()
		_ = request.Body.Close()
		if err != nil || int64(len(body)) > remaining {
			return nil, p.fail("request body budget exceeded")
		}
		cloned.Body = io.NopCloser(bytes.NewReader(body))
		cloned.ContentLength = int64(len(body))
		cloned.GetBody = nil
	}
	p.mu.Lock()
	p.requestBytes += int64(len(body))
	over := p.requestBytes > p.limits.MaxRequestBytes || p.err != nil
	p.mu.Unlock()
	if over {
		return nil, p.fail("request budget exceeded")
	}
	response, err := t.base.RoundTrip(cloned)
	if err != nil {
		return nil, p.fail("owned HTTP connection failed")
	}
	originalBody := response.Body
	defer func() { _ = originalBody.Close() }()
	if response.StatusCode == http.StatusSwitchingProtocols || strings.Contains(strings.ToLower(response.Header.Get("Connection")), "upgrade") {
		return nil, p.fail("protocol upgrade is not permitted")
	}
	p.mu.Lock()
	headerBytes = 0
	for name, values := range response.Header {
		for _, value := range values {
			headerBytes += int64(len(name) + len(value) + 4)
		}
	}
	p.responseBytes += headerBytes
	remaining = p.limits.MaxResponseBytes - p.responseBytes
	p.mu.Unlock()
	if remaining < 0 {
		return nil, p.fail("response header budget exceeded")
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, remaining+1))
	if err != nil || int64(len(body)) > remaining {
		return nil, p.fail("response body budget exceeded")
	}
	p.mu.Lock()
	p.responseBytes += int64(len(body))
	over = p.responseBytes > p.limits.MaxResponseBytes || p.err != nil
	p.mu.Unlock()
	if over {
		return nil, p.fail("response budget exceeded")
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}
