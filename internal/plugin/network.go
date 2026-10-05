package plugin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
)

const (
	maxNetworkRequest = 256 << 10
	maxNetworkBody    = 4 << 20
	maxNetworkCalls   = 1000
)

type networkChannel struct {
	RequestFD  int `json:"request_fd"`
	ResponseFD int `json:"response_fd"`
}

type networkRequest struct {
	Operation string            `json:"operation"`
	URL       string            `json:"url,omitempty"`
	Method    string            `json:"method,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      []byte            `json:"body,omitempty"`
	Address   string            `json:"address,omitempty"`
	TLS       bool              `json:"tls,omitempty"`
	ReadLimit int               `json:"read_limit,omitempty"`
	Name      string            `json:"name,omitempty"`
	Record    string            `json:"record,omitempty"`
}

type networkResponse struct {
	Status  int         `json:"status,omitempty"`
	Headers http.Header `json:"headers,omitempty"`
	Body    []byte      `json:"body,omitempty"`
	Answers []string    `json:"answers,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type broker struct {
	plugin                        *pluginCheck
	target                        check.Target
	requestsRead, requestsWrite   *os.File
	responsesRead, responsesWrite *os.File
}

func newBroker(plugin *pluginCheck, target check.Target) (*broker, error) {
	b := &broker{plugin: plugin, target: target}
	var err error
	b.requestsRead, b.requestsWrite, err = os.Pipe()
	if err != nil {
		return nil, err
	}
	b.responsesRead, b.responsesWrite, err = os.Pipe()
	if err != nil {
		b.close()
		return nil, err
	}
	return b, nil
}

func (b *broker) close() {
	for _, file := range []*os.File{b.requestsRead, b.requestsWrite, b.responsesRead, b.responsesWrite} {
		if file != nil {
			_ = file.Close()
		}
	}
}

func (b *broker) serve(ctx context.Context) error {
	scanner := bufio.NewScanner(b.requestsRead)
	scanner.Buffer(make([]byte, 4096), maxNetworkRequest)
	encoder := json.NewEncoder(b.responsesWrite)
	var firstErr error
	for count := 0; scanner.Scan(); count++ {
		if count >= maxNetworkCalls {
			return fmt.Errorf("network request limit exceeded")
		}
		var req networkRequest
		response := networkResponse{}
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			response.Error = "invalid network request JSON"
		} else {
			response = b.exchange(ctx, req)
		}
		if response.Error != "" && firstErr == nil {
			firstErr = errors.New(response.Error)
		}
		if err := encoder.Encode(response); err != nil {
			return errors.Join(firstErr, err)
		}
	}
	err := scanner.Err()
	if errors.Is(err, os.ErrClosed) {
		err = nil // Parent closes the reader after child exit.
	}
	return errors.Join(firstErr, err)
}

func (b *broker) exchange(ctx context.Context, req networkRequest) networkResponse {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var resp networkResponse
	var err error
	switch req.Operation {
	case "http":
		resp, err = b.http(ctx, req)
	case "tcp":
		resp, err = b.tcp(ctx, req)
	case "dns":
		resp, err = b.dns(ctx, req)
	default:
		err = fmt.Errorf("unknown network operation %q", req.Operation)
	}
	if err != nil {
		resp.Error = err.Error()
	}
	return resp
}

func (b *broker) allowed(ctx context.Context, host string) error {
	known := strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(assetHost(b.target.Asset), "."))
	for _, neighbour := range b.target.Neighbours {
		known = known || strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(assetHost(neighbour.Asset), "."))
	}
	if !known || b.plugin.verify == nil || !b.plugin.verify(ctx, host) {
		return fmt.Errorf("network destination %q is not an owned target or neighbour", host)
	}
	return nil
}

func (b *broker) http(ctx context.Context, req networkRequest) (networkResponse, error) {
	u, err := url.Parse(req.URL)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return networkResponse{}, fmt.Errorf("invalid HTTP URL")
	}
	if err := b.allowed(ctx, u.Hostname()); err != nil {
		return networkResponse{}, err
	}
	if b.target.HTTP == nil {
		return networkResponse{}, fmt.Errorf("guarded HTTP client is unavailable")
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(ctx, method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return networkResponse{}, err
	}
	for name, value := range req.Headers {
		if strings.EqualFold(name, "Host") || strings.EqualFold(name, "Proxy-Authorization") {
			return networkResponse{}, fmt.Errorf("HTTP header %q is not permitted", name)
		}
		request.Header.Set(name, value)
	}
	response, err := b.target.HTTP.Do(request)
	if err != nil {
		return networkResponse{}, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxNetworkBody+1))
	if len(body) > maxNetworkBody {
		return networkResponse{}, fmt.Errorf("HTTP response exceeds %d bytes", maxNetworkBody)
	}
	return networkResponse{Status: response.StatusCode, Headers: response.Header, Body: body}, err
}

func (b *broker) tcp(ctx context.Context, req networkRequest) (networkResponse, error) {
	host, _, err := net.SplitHostPort(req.Address)
	if err != nil {
		return networkResponse{}, fmt.Errorf("TCP address must contain host and port")
	}
	if err := b.allowed(ctx, host); err != nil {
		return networkResponse{}, err
	}
	if b.target.Dialer == nil {
		return networkResponse{}, fmt.Errorf("guarded dialer is unavailable")
	}
	conn, err := b.target.Dialer.DialContext(ctx, "tcp", req.Address)
	if err != nil {
		return networkResponse{}, err
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return networkResponse{}, err
	}
	if req.TLS {
		secured := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := secured.HandshakeContext(ctx); err != nil {
			return networkResponse{}, err
		}
		conn = secured
	}
	if _, err := io.Copy(conn, bytes.NewReader(req.Body)); err != nil {
		return networkResponse{}, err
	}
	limit := req.ReadLimit
	if limit <= 0 || limit > maxNetworkBody {
		limit = 64 << 10
	}
	body := make([]byte, limit)
	n, err := conn.Read(body)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return networkResponse{Body: body[:n]}, err
}

func (b *broker) dns(ctx context.Context, req networkRequest) (networkResponse, error) {
	if err := b.allowed(ctx, req.Name); err != nil {
		return networkResponse{}, err
	}
	if b.target.Resolver == nil {
		return networkResponse{}, fmt.Errorf("guarded resolver is unavailable")
	}
	var answers []string
	var err error
	switch req.Record {
	case "A", "AAAA", "":
		answers, err = b.target.Resolver.LookupHost(ctx, req.Name)
	case "TXT":
		answers, err = b.target.Resolver.LookupTXT(ctx, req.Name)
	case "NS":
		answers, err = b.target.Resolver.LookupNS(ctx, req.Name)
	case "CNAME":
		var answer string
		answer, err = b.target.Resolver.LookupCNAME(ctx, req.Name)
		if answer != "" {
			answers = []string{answer}
		}
	default:
		err = fmt.Errorf("unsupported DNS record %q", req.Record)
	}
	return networkResponse{Answers: answers}, err
}
