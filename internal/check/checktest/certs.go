package checktest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func tlsInsecure() *tls.Config { return &tls.Config{InsecureSkipVerify: true} } // #nosec G402 -- test helper

// CA is a throwaway certificate authority for tests.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	Pool *x509.CertPool
}

// CertSpec describes a leaf certificate.
type CertSpec struct {
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
	RSABits   int // 0 = ECDSA P-256
	SigAlg    x509.SignatureAlgorithm
	SelfSign  bool // sign with its own key instead of the CA
}

// NewCA creates a test CA.
func NewCA(t testing.TB) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, Key: key, Pool: pool}
}

// Issue creates a leaf certificate per spec. Returns the tls.Certificate
// (leaf only) and the parsed leaf.
func (ca *CA) Issue(t testing.TB, s CertSpec) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	var key crypto.Signer
	var err error
	if s.RSABits > 0 {
		key, err = rsa.GenerateKey(rand.Reader, s.RSABits)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	cn := "leaf"
	if len(s.DNSNames) > 0 {
		cn = s.DNSNames[0]
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		DNSNames: s.DNSNames, NotBefore: s.NotBefore, NotAfter: s.NotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if s.SigAlg != 0 {
		tpl.SignatureAlgorithm = s.SigAlg
	}
	parent, signer := ca.Cert, ca.Key
	if s.SelfSign {
		parent, signer = tpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// ServeTLS starts a TLS listener on 127.0.0.1 presenting cert, accepting and
// closing connections after the handshake. Returns its address; closed on
// test cleanup.
func ServeTLS(t testing.TB, cert tls.Certificate) string {
	t.Helper()
	// #nosec G402 -- test server deliberately allows the client's offered TLS version, including weak ones under test
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.(*tls.Conn).Handshake()
			}(c)
		}
	}()
	return ln.Addr().String()
}
