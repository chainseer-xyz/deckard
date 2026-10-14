package assessment

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	if _, _, err := net.SplitHostPort(r.Host); err != nil {
		p.denyCONNECT(w, "invalid CONNECT authority")
		return
	}
	u, err := p.policy.AuthorizeURL(r.Context(), "https://"+r.Host)
	if err != nil {
		http.Error(w, "assessment CONNECT refused", http.StatusForbidden)
		return
	}
	select {
	case p.tunnels <- struct{}{}:
		defer func() { <-p.tunnels }()
	default:
		p.denyCONNECT(w, "concurrent CONNECT limit exceeded")
		return
	}
	certificate, err := p.leafCertificate(u.Hostname())
	if err != nil {
		p.denyCONNECT(w, "session certificate unavailable")
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.denyCONNECT(w, "CONNECT requires HTTP/1.1")
		return
	}
	conn, buffer, err := hijacker.Hijack()
	if err != nil {
		_ = p.policy.fail("CONNECT handshake failed")
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		_ = p.policy.fail("CONNECT admission ended")
		return
	}
	p.connections[conn] = struct{}{}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.connections, conn); p.mu.Unlock() }()
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(p.policy.ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := p.policy.ctx.Deadline()
	if err := conn.SetDeadline(minTime(deadline, time.Now().Add(10*time.Second))); err != nil {
		_ = p.policy.fail("CONNECT deadline unavailable")
		return
	}
	if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = p.policy.fail("CONNECT response failed")
		return
	}
	if err := buffer.Flush(); err != nil {
		_ = p.policy.fail("CONNECT response failed")
		return
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}}
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		sni := strings.TrimSuffix(strings.ToLower(hello.ServerName), ".")
		address, ipErr := netip.ParseAddr(u.Hostname())
		allowMissingIPName := ipErr == nil && address.IsValid() && sni == ""
		if sni != u.Hostname() && !allowMissingIPName {
			return nil, p.policy.fail("TLS SNI differs from CONNECT target")
		}
		return nil, nil
	}
	tlsConn := tls.Server(&bufferedConn{Conn: conn, reader: buffer.Reader}, config)
	if err := tlsConn.HandshakeContext(p.policy.ctx); err != nil {
		_ = p.policy.fail("scanner TLS handshake failed")
		return
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = p.policy.fail("CONNECT deadline unavailable")
		return
	}
	listener := &singleConnListener{conn: tlsConn, done: make(chan struct{})}
	active, handled, observed := false, false, false
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			handled, observed = true, true
			_, origin, err := normalizeURL("https://" + request.Host)
			if err != nil || origin != u.Scheme+"://"+u.Host || request.URL.IsAbs() || request.URL.Host != "" || request.Method == http.MethodConnect || request.Header.Get("Upgrade") != "" {
				_ = p.policy.fail("HTTPS request authority differs from CONNECT target")
				http.Error(w, "assessment HTTPS authority refused", http.StatusForbidden)
				return
			}
			cloned := request.Clone(request.Context())
			cloned.URL.Scheme, cloned.URL.Host = "https", u.Host
			p.forward(w, cloned)
		}),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: min(p.policy.limits.Timeout, 30*time.Second),
		WriteTimeout: min(p.policy.limits.Timeout, 30*time.Second), IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog:    log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return p.policy.ctx },
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateActive:
				active, handled = true, false
			case http.StateIdle:
				active = false
			case http.StateClosed:
				if !observed || (active && !handled) {
					_ = p.policy.fail("HTTPS request did not parse or complete")
				}
				_ = listener.Close()
			}
		},
	}
	if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		_ = p.policy.fail("HTTPS proxy serving failed")
	}
}

func (p *Proxy) denyCONNECT(w http.ResponseWriter, reason string) {
	_ = p.policy.fail(reason)
	http.Error(w, "assessment CONNECT refused", http.StatusForbidden)
}

func (p *Proxy) leafCertificate(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Deckard assessment endpoint"}, NotBefore: p.ca.NotBefore, NotAfter: p.ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if address, err := netip.ParseAddr(host); err == nil {
		certificate.IPAddresses = []net.IP{net.IP(address.AsSlice())}
	} else {
		certificate.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, p.ca, &key.PublicKey, p.key)
	return tls.Certificate{Certificate: [][]byte{der, p.ca.Raw}, PrivateKey: key}, err
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(buffer []byte) (int, error) { return c.reader.Read(buffer) }

type singleConnListener struct {
	conn     net.Conn
	done     chan struct{}
	accepted bool
	once     sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return &listenerConn{Conn: l.conn, listener: l}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.conn.Close()
}

type listenerConn struct {
	net.Conn
	listener *singleConnListener
}

func (c *listenerConn) Close() error { return c.Conn.Close() }
