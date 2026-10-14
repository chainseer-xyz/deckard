package assessment_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessment"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

const proxyToken = "local-fixture-token-with-at-least-32-bytes"

func proxyFixture(t *testing.T, p *assessment.Policy, token string) (*http.Client, *assessment.Proxy, <-chan struct{}) {
	t.Helper()
	proxy, err := assessment.NewProxy(p, proxyToken)
	if err != nil {
		t.Fatal(err)
	}
	returned := make(chan struct{}, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
		select {
		case returned <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		endpoint.User = url.UserPassword("deckard", token)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(proxy.CAPEM()) {
		t.Fatal("invalid generated CA")
	}
	transport := &http.Transport{Proxy: http.ProxyURL(endpoint), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}, proxy, returned
}

func proxyClient(t *testing.T, p *assessment.Policy, token string) (*http.Client, *assessment.Proxy) {
	t.Helper()
	client, proxy, _ := proxyFixture(t, p, token)
	return client, proxy
}

func TestProxyBoundsPlainHTTPAdmissionWhileUpstreamIsBlocked(t *testing.T) {
	entered := make(chan struct{})
	p, _ := fixturePolicy(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}), &resolver{addresses: []string{"10.20.30.40"}}, limits())
	defer p.Close()
	proxy, err := assessment.NewProxy(p, proxyToken)
	if err != nil {
		t.Fatal(err)
	}
	returned := make(chan int, 9)
	send := func() {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://app.example.com/", nil)
		r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("deckard:"+proxyToken)))
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, r)
		returned <- w.Code
	}
	go send()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first upstream request never blocked")
	}
	for range 8 {
		go send()
	}
	refused := false
	for range 9 {
		select {
		case code := <-returned:
			refused = refused || code == http.StatusTooManyRequests
		case <-time.After(2 * time.Second):
			t.Fatal("proxy allowed unbounded admission behind a blocked upstream request")
		}
	}
	if !refused || p.Err() == nil {
		t.Fatal("admission overflow must refuse without queuing and mark incomplete")
	}
}

func fixtureCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"example.com"}, IPAddresses: []net.IP{net.ParseIP("10.20.30.40")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tlsFixturePolicy(t *testing.T, handler http.Handler, bound assessment.Limits) (*assessment.Policy, *fixtureDialer) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{fixtureCertificate(t)}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	if err := server.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dialer := &fixtureDialer{address: server.Listener.Addr().String()}
	g, err := scope.NewGuard(config.ScopeConfig{Include: []string{"example.com", "10.20.30.40/32"}}, scope.WithResolver(&resolver{addresses: []string{"10.20.30.40"}}), scope.WithDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	p, err := assessment.NewPolicy(context.Background(), g, []string{"https://example.com"}, bound, assessment.WithRootCAs(roots))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p, dialer
}

func TestPolicyUsesHTTP1ForStrictRequestAccounting(t *testing.T) {
	p, _ := tlsFixturePolicy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Errorf("HTTP/2 transparent retries bypass strict request accounting: got %s", r.Proto)
		}
		_, _ = io.WriteString(w, "ok")
	}), limits())
	response, err := p.Do(request(t, http.MethodGet, "https://example.com/", ""))
	if response != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestProxyIPLiteralHTTPSOmitsSNIAndVerifiesIPSAN(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "IP fixture") }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{fixtureCertificate(t)}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dialer := &fixtureDialer{address: server.Listener.Addr().String()}
	g, err := scope.NewGuard(config.ScopeConfig{Include: []string{"10.20.30.40/32"}}, scope.WithDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	p, err := assessment.NewPolicy(context.Background(), g, []string{"https://10.20.30.40"}, limits(), assessment.WithRootCAs(roots))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	client, _ := proxyClient(t, p, proxyToken)
	response, err := client.Do(request(t, http.MethodGet, "https://10.20.30.40/", ""))
	if response != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err != nil || p.Err() != nil {
		t.Fatalf("IP-literal TLS must verify without SNI: request=%v policy=%v", err, p.Err())
	}
}

func TestProxyCancelAndDisconnectFinishCONNECTHandler(t *testing.T) {
	for _, cancelSession := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelSession), func(t *testing.T) {
			p, _ := tlsFixturePolicy(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("empty CONNECT should not reach target") }), limits())
			client, proxy, returned := proxyFixture(t, p, proxyToken)
			conn, err := connectTLS(t, client, proxy, "example.com:443", "example.com")
			if err != nil {
				t.Fatal(err)
			}
			if cancelSession {
				p.Close()
			} else {
				_ = conn.Close()
			}
			select {
			case <-returned:
			case <-time.After(2 * time.Second):
				t.Fatal("CONNECT handler leaked after cancellation/disconnect")
			}
			if p.Err() == nil {
				t.Fatal("empty CONNECT is not a complete observation")
			}
		})
	}
}

func TestProxyHTTPSBodyLimitsAreEnforced(t *testing.T) {
	for _, responseOver := range []bool{false, true} {
		t.Run(fmt.Sprint(responseOver), func(t *testing.T) {
			bound := limits()
			if responseOver {
				bound.MaxResponseBytes = 512
			} else {
				bound.MaxRequestBytes = 512
			}
			p, dialer := tlsFixturePolicy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if !responseOver {
					t.Error("over-budget request body reached target")
				}
				_, _ = io.WriteString(w, strings.Repeat("x", 1024))
			}), bound)
			client, _ := proxyClient(t, p, proxyToken)
			body := ""
			if !responseOver {
				body = strings.Repeat("x", 1024)
			}
			response, err := client.Do(request(t, http.MethodPost, "https://example.com/", body))
			if response != nil {
				_ = response.Body.Close()
			}
			if err == nil && response.StatusCode < 400 {
				t.Fatal("body limit was bypassed")
			}
			if p.Err() == nil {
				t.Fatal("body exhaustion must be incomplete")
			}
			if !responseOver && len(dialer.destinations) != 0 {
				t.Fatal("over-budget body must be refused before dialing target")
			}
		})
	}
}

func TestProxyInspectsRealHTTPSUsingPerSessionCA(t *testing.T) {
	p, dialer := tlsFixturePolicy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com:443" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("unexpected HTTPS authority or leaked proxy credential")
		}
		_, _ = io.WriteString(w, "inspected HTTPS fixture")
	}), limits())
	client, _ := proxyClient(t, p, proxyToken)
	response, err := client.Do(request(t, http.MethodGet, "https://example.com/private?not-logged=value", ""))
	if response != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "inspected HTTPS fixture" {
		t.Fatalf("body=%q error=%v", body, err)
	}
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	if len(dialer.destinations) != 1 || dialer.destinations[0] != "10.20.30.40:443" {
		t.Fatalf("unexpected HTTPS destinations %v", dialer.destinations)
	}
}

func TestProxyHTTPSRequestsConsumeSharedBudget(t *testing.T) {
	bound := limits()
	bound.MaxRequests = 1
	p, dialer := tlsFixturePolicy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), bound)
	client, _ := proxyClient(t, p, proxyToken)
	response, err := client.Do(request(t, http.MethodGet, "https://example.com/first", ""))
	if response != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	response, err = client.Do(request(t, http.MethodGet, "https://example.com/second", ""))
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil && response.StatusCode < 400 {
		t.Fatal("second HTTPS request bypassed budget")
	}
	if p.Err() == nil || len(dialer.destinations) != 1 {
		t.Fatal("HTTPS budget exhaustion must prevent target dial and mark session incomplete")
	}
}

func connectTLS(t *testing.T, client *http.Client, proxy *assessment.Proxy, authority, sni string) (*tls.Conn, error) {
	t.Helper()
	transport := client.Transport.(*http.Transport)
	endpoint, err := transport.Proxy(request(t, http.MethodGet, "https://example.com/", ""))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", endpoint.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte("deckard:" + proxyToken))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", authority, authority, auth); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		t.Fatalf("CONNECT status %d", response.StatusCode)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(proxy.CAPEM())
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: sni, MinVersion: tls.VersionTLS12})
	return tlsConn, tlsConn.HandshakeContext(context.Background())
}

func TestProxyRejectsTLSSNIPivotAndMissingDNSSNI(t *testing.T) {
	for _, sni := range []string{"other.example.com", "10.20.30.40"} {
		t.Run(sni, func(t *testing.T) {
			p, dialer := tlsFixturePolicy(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("SNI pivot reached target") }), limits())
			client, proxy := proxyClient(t, p, proxyToken)
			conn, err := connectTLS(t, client, proxy, "example.com:443", sni)
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil || p.Err() == nil || !strings.Contains(p.Err().Error(), "SNI differs") || len(dialer.destinations) != 0 {
				t.Fatalf("SNI mismatch must be refused by proxy: tls=%v policy=%v", err, p.Err())
			}
		})
	}
}

func TestProxyRejectsHTTPSHostPortAndAbsoluteURLPivots(t *testing.T) {
	for _, line := range []string{
		"GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n",
		"GET https://other.example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
	} {
		t.Run(line, func(t *testing.T) {
			p, dialer := tlsFixturePolicy(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("authority pivot reached target") }), limits())
			client, proxy := proxyClient(t, p, proxyToken)
			conn, err := connectTLS(t, client, proxy, "example.com:443", "example.com")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_, _ = io.WriteString(conn, line)
			response, _ := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
			if response != nil {
				_ = response.Body.Close()
			}
			if p.Err() == nil || len(dialer.destinations) != 0 {
				t.Fatal("HTTPS authority pivot must be terminal before target I/O")
			}
		})
	}
}

func TestProxyMalformedHTTPSIsIncomplete(t *testing.T) {
	p, _ := tlsFixturePolicy(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("malformed request reached target") }), limits())
	client, proxy, returned := proxyFixture(t, p, proxyToken)
	conn, err := connectTLS(t, client, proxy, "example.com:443", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nBroken Header\r\n\r\n")
	_, _ = io.ReadAll(conn)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("malformed CONNECT handler did not finish")
	}
	if p.Err() == nil {
		t.Fatal("malformed decrypted request must not look like a clean assessment")
	}
}

func TestProxyForwardsAuthenticatedHTTPWithoutProxyCredentials(t *testing.T) {
	p, _ := fixturePolicy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop-Secret") != "" {
			t.Error("proxy credentials or hop header reached target")
		}
		_, _ = io.WriteString(w, "proxied fixture")
	}), &resolver{addresses: []string{"10.20.30.40"}}, limits())
	client, _ := proxyClient(t, p, proxyToken)
	req := request(t, http.MethodGet, "http://app.example.com/", "")
	req.Header.Set("Connection", "X-Hop-Secret")
	req.Header.Set("X-Hop-Secret", "private-hop-value")
	response, err := client.Do(req)
	if response != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "proxied fixture" {
		t.Fatalf("unexpected response %q, error %v", body, err)
	}
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
}

func TestProxyRefusesUnauthenticatedHTTPAndCONNECT(t *testing.T) {
	for _, target := range []string{"http://app.example.com/", "https://app.example.com/"} {
		t.Run(target, func(t *testing.T) {
			p, dialer := fixturePolicy(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unauthenticated request reached target") }), &resolver{addresses: []string{"10.20.30.40"}}, limits())
			client, _ := proxyClient(t, p, "")
			response, err := client.Do(request(t, http.MethodGet, target, ""))
			if response != nil {
				defer func() { _ = response.Body.Close() }()
			}
			if err == nil && response.StatusCode != http.StatusProxyAuthRequired {
				t.Fatalf("unauthenticated request was accepted: %v", response.StatusCode)
			}
			if p.Err() == nil || len(dialer.destinations) != 0 {
				t.Fatal("unauthenticated proxy traffic must be refused before any target dial")
			}
		})
	}
}

func TestProxyRefusesCONNECTOutsideExplicitOrigins(t *testing.T) {
	p, dialer := fixturePolicy(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("out-of-target CONNECT reached server") }), &resolver{addresses: []string{"10.20.30.40"}}, limits())
	client, _ := proxyClient(t, p, proxyToken)
	response, err := client.Do(request(t, http.MethodGet, "https://not-authorized.example.org/", ""))
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || p.Err() == nil || len(dialer.destinations) != 0 {
		t.Fatal("CONNECT refusal must mark session incomplete without a target dial")
	}
}

func TestProxyFinishDrainsIdleTLSBeforeCompletenessSnapshot(t *testing.T) {
	p, _ := tlsFixturePolicy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), limits())
	client, proxy := proxyClient(t, p, proxyToken)
	response, err := client.Do(request(t, http.MethodGet, "https://example.com/", ""))
	if response != nil {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := proxy.Finish(ctx); err != nil {
		t.Fatalf("complete request must survive idle tunnel cleanup: %v", err)
	}
	if err := proxy.Finish(ctx); err != nil {
		t.Fatalf("repeated finish must preserve original result: %v", err)
	}
	response, err = client.Do(request(t, http.MethodGet, "https://example.com/after-finish", ""))
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil && response.StatusCode != http.StatusGone {
		t.Fatal("finished session accepted a new request")
	}
}

func TestProxyFinishCannotHideMalformedHTTPS(t *testing.T) {
	p, _ := tlsFixturePolicy(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("malformed request reached target") }), limits())
	client, proxy := proxyClient(t, p, proxyToken)
	conn, err := connectTLS(t, client, proxy, "example.com:443", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nBroken Header\r\n\r\n")
	_, _ = io.ReadAll(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := proxy.Finish(ctx); err == nil {
		t.Fatal("finish raced past malformed request accounting")
	}
}
