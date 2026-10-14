package assessment

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Proxy is a per-session authenticated assessment proxy. Its in-memory CA is
// public; its signing key never leaves the broker. It is not a kernel egress
// boundary: runner Jobs must deny all direct egress, including DNS.
type Proxy struct {
	policy         *Policy
	token          string
	caPEM          []byte
	ca             *x509.Certificate
	key            *ecdsa.PrivateKey
	tunnels        chan struct{}
	mu             sync.Mutex
	closed         bool
	handlers       sync.WaitGroup
	activeHandlers int
	connections    map[net.Conn]struct{}
	finishOnce     sync.Once
	finished       chan struct{}
	finishErr      error
}

// NewProxy creates an ephemeral CA and binds a caller-generated high-entropy
// opaque token to one policy. The token must contain at least 32 bytes.
// Configure the outer HTTP server with bounded headers and read/write timeouts.
func NewProxy(policy *Policy, token string) (*Proxy, error) {
	if policy == nil || len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, "\r\n\t :") {
		return nil, fmt.Errorf("%w: invalid proxy policy or session token", ErrDenied)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("assessment proxy: generate CA: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("assessment proxy: CA serial: %w", err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Deckard assessment session"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("assessment proxy: sign CA: %w", err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("assessment proxy: parse CA: %w", err)
	}
	return &Proxy{policy: policy, token: token, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca: ca, key: key, tunnels: make(chan struct{}, 4), connections: make(map[net.Conn]struct{}), finished: make(chan struct{})}, nil
}

// CAPEM returns a copy of this session's public trust anchor, never its key.
func (p *Proxy) CAPEM() []byte { return append([]byte(nil), p.caPEM...) }

// ServeHTTP authorizes every decrypted request through Policy.Do. The proxy
// supports HTTP/1.1 only; protocol upgrades and transparent tunnels are refused.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		http.Error(w, "assessment session ended", http.StatusGone)
		return
	}
	if p.activeHandlers >= 8 {
		p.mu.Unlock()
		_ = p.policy.fail("proxy request admission limit exceeded")
		http.Error(w, "assessment request capacity exhausted", http.StatusTooManyRequests)
		return
	}
	p.activeHandlers++
	p.handlers.Add(1)
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.activeHandlers--
		p.mu.Unlock()
		p.handlers.Done()
	}()
	if !p.authenticated(r) {
		_ = p.policy.fail("proxy authentication failed")
		w.Header().Set("Proxy-Authenticate", `Basic realm="Deckard assessment"`)
		http.Error(w, "assessment proxy authorization required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if r.Header.Get("Upgrade") != "" {
		_ = p.policy.fail("HTTP upgrade is not permitted")
		http.Error(w, "assessment upgrade refused", http.StatusForbidden)
		return
	}
	p.forward(w, r)
}

// Finish stops admission, closes CONNECT streams and waits for admitted
// requests before deciding completeness. Use its result before reconciling a
// report; checking Err before an asynchronous tunnel closes can miss refusal.
// It closes the policy only after taking the final completeness snapshot.
func (p *Proxy) Finish(ctx context.Context) error {
	p.finishOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		connections := make([]net.Conn, 0, len(p.connections))
		for conn := range p.connections {
			connections = append(connections, conn)
		}
		p.mu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		go func() {
			p.handlers.Wait()
			p.finishErr = p.policy.Err()
			p.policy.Close()
			close(p.finished)
		}()
	})
	select {
	case <-p.finished:
		return p.finishErr
	case <-ctx.Done():
		p.policy.Close()
		return ctx.Err()
	}
}

func (p *Proxy) authenticated(r *http.Request) bool {
	values := r.Header.Values("Proxy-Authorization")
	if len(values) != 1 {
		return false
	}
	scheme, encoded, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	if len(encoded) > 512 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	expected := "deckard:" + p.token
	return subtle.ConstantTimeCompare(decoded, []byte(expected)) == 1
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	cloned := r.Clone(r.Context())
	cloned.RequestURI = ""
	stripHopHeaders(cloned.Header)
	response, err := p.policy.Do(cloned)
	if err != nil {
		http.Error(w, "assessment request refused or incomplete", http.StatusForbidden)
		return
	}
	defer func() { _ = response.Body.Close() }()
	stripHopHeaders(response.Header)
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, response.Body); err != nil {
		_ = p.policy.fail("scanner response did not complete")
	}
}

func stripHopHeaders(headers http.Header) {
	for _, value := range headers.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			headers.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		headers.Del(name)
	}
}
