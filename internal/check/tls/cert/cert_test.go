package cert

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func days(n int) time.Time { return now.Add(time.Duration(n) * 24 * time.Hour) }

func keyset(fs []model.FindingInput) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range fs {
		m[f.Key] = f.Severity
	}
	return m
}

func TestAssess(t *testing.T) {
	ca := checktest.NewCA(t)
	opts := Options{Now: now, WarnDays: 21, CritDays: 7, Host: "app.example.com", Port: 443, Roots: ca.Pool}
	good := []string{"app.example.com"}

	cases := []struct {
		name string
		spec checktest.CertSpec
		want map[string]model.Severity
	}{
		{"healthy", checktest.CertSpec{DNSNames: good, NotBefore: days(-30), NotAfter: days(90)}, map[string]model.Severity{}},
		{"expired", checktest.CertSpec{DNSNames: good, NotBefore: days(-100), NotAfter: days(-1)},
			map[string]model.Severity{"443:expired": model.SeverityCritical}},
		{"expiring crit", checktest.CertSpec{DNSNames: good, NotBefore: days(-80), NotAfter: days(5)},
			map[string]model.Severity{"443:expiring": model.SeverityHigh}},
		{"expiring warn", checktest.CertSpec{DNSNames: good, NotBefore: days(-80), NotAfter: days(15)},
			map[string]model.Severity{"443:expiring": model.SeverityMedium}},
		{"boundary warn day", checktest.CertSpec{DNSNames: good, NotBefore: days(-80), NotAfter: days(21).Add(time.Hour)},
			map[string]model.Severity{"443:expiring": model.SeverityMedium}},
		{"just outside warn", checktest.CertSpec{DNSNames: good, NotBefore: days(-80), NotAfter: days(23)}, map[string]model.Severity{}},
		{"hostname mismatch", checktest.CertSpec{DNSNames: []string{"other.example.com"}, NotBefore: days(-30), NotAfter: days(90)},
			map[string]model.Severity{"443:hostname-mismatch": model.SeverityHigh}},
		{"wildcard covers", checktest.CertSpec{DNSNames: []string{"*.example.com"}, NotBefore: days(-30), NotAfter: days(90)}, map[string]model.Severity{}},
		{"self-signed", checktest.CertSpec{DNSNames: good, NotBefore: days(-30), NotAfter: days(90), SelfSign: true},
			map[string]model.Severity{"443:self-signed": model.SeverityMedium}},
		{"weak rsa", checktest.CertSpec{DNSNames: good, NotBefore: days(-30), NotAfter: days(90), RSABits: 1024},
			map[string]model.Severity{"443:weak-key": model.SeverityMedium}},
		{"sha1 self-signed rsa", checktest.CertSpec{DNSNames: good, NotBefore: days(-30), NotAfter: days(90), RSABits: 2048, SelfSign: true, SigAlg: x509.SHA1WithRSA},
			map[string]model.Severity{"443:self-signed": model.SeverityMedium, "443:weak-signature-0": model.SeverityMedium}},
	}
	for _, c := range cases {
		_, leaf := ca.Issue(t, c.spec)
		got := keyset(Assess([]*x509.Certificate{leaf}, opts))
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: %s = %q want %q (all %v)", c.name, k, got[k], v, got)
			}
		}
		for k := range got {
			if _, ok := c.want[k]; !ok {
				// SHA-1 chains may or may not also report trust failures depending on the Go version.
				if c.name == "sha1 self-signed rsa" {
					continue
				}
				t.Errorf("%s: unexpected finding %s", c.name, k)
			}
		}
	}
}

func TestAssessFindingsCarryRemediationAndEvidence(t *testing.T) {
	ca := checktest.NewCA(t)
	_, leaf := ca.Issue(t, checktest.CertSpec{DNSNames: []string{"app.example.com"}, NotBefore: days(-100), NotAfter: days(-1)})
	fs := Assess([]*x509.Certificate{leaf}, Options{Now: now, WarnDays: 21, CritDays: 7, Host: "app.example.com", Port: 443, Roots: ca.Pool})
	if len(fs) != 1 {
		t.Fatalf("%+v", fs)
	}
	f := fs[0]
	if f.Remediation == "" || f.Title == "" || f.Evidence["fingerprint_sha256"] == "" || f.Evidence["port"] != 443 {
		t.Errorf("finding incomplete: %+v", f)
	}
}

func newCheck(ca *checktest.CA) *Check {
	c := New(nil)
	c.now = func() time.Time { return now }
	c.roots = ca.Pool
	return c
}

func TestRunObservationAndSANDiscovery(t *testing.T) {
	ca := checktest.NewCA(t)
	cert, leaf := ca.Issue(t, checktest.CertSpec{
		DNSNames:  []string{"app.example.com", "api.example.com", "*.wild.example.com", "partner.example.net", "api.example.com"},
		NotBefore: days(-30), NotAfter: days(10),
	})
	addr := checktest.ServeTLS(t, cert)
	d := &checktest.Dialer{Routes: map[string]string{"app.example.com:443": addr}}
	tg := checktest.NewTarget(checktest.Hostname("app.example.com", "example.com"), checktest.WithDialer(d))

	res, err := newCheck(ca).Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	obs := res.Observations[0].Data
	if obs["fingerprint_sha256"] != Fingerprint(leaf) {
		t.Errorf("fingerprint: %v", obs["fingerprint_sha256"])
	}
	if got := keyset(res.Findings); got["443:expiring"] != model.SeverityMedium || len(got) != 1 {
		t.Errorf("findings: %v", got)
	}
	if len(res.Discovered) != 1 || res.Discovered[0].Key != "api.example.com" || res.Discovered[0].Kind != model.KindHostname {
		t.Errorf("discovered (owned, non-wildcard, deduped, not self): %+v", res.Discovered)
	}
}

func TestRunHandshakeFailure(t *testing.T) {
	// A plaintext listener that is expected to speak TLS.
	plain := checktest.ServePlain(t, "HTTP/1.1 400 Bad Request\r\n\r\n")
	d := &checktest.Dialer{Routes: map[string]string{"app.example.com:443": plain}}
	ca := checktest.NewCA(t)

	a := checktest.Hostname("app.example.com", "example.com")
	// Not marked as TLS: observation only.
	res, _ := newCheck(ca).Run(context.Background(), checktest.NewTarget(a, checktest.WithDialer(d)))
	if len(res.Findings) != 0 {
		t.Errorf("unmarked hostname must not produce finding: %+v", res.Findings)
	}
	// Marked as TLS: info finding.
	a.Attrs = map[string]any{"tls": true}
	res, _ = newCheck(ca).Run(context.Background(), checktest.NewTarget(a, checktest.WithDialer(d)))
	if got := keyset(res.Findings); got["443:handshake-failed"] != model.SeverityInfo {
		t.Errorf("findings: %v", got)
	}
}

func TestRunConnectRefusedIsQuiet(t *testing.T) {
	ca := checktest.NewCA(t)
	res, err := newCheck(ca).Run(context.Background(),
		checktest.NewTarget(checktest.Hostname("app.example.com", "example.com"), checktest.WithDialer(&checktest.Dialer{})))
	if err != nil || len(res.Findings) != 0 {
		t.Errorf("%+v %v", res, err)
	}
}

func TestServiceAsset(t *testing.T) {
	ca := checktest.NewCA(t)
	cert, _ := ca.Issue(t, checktest.CertSpec{DNSNames: []string{"app.example.com"}, NotBefore: days(-30), NotAfter: days(90)})
	addr := checktest.ServeTLS(t, cert)
	d := &checktest.Dialer{Routes: map[string]string{"192.0.2.10:8443": addr}}
	svc := model.Asset{Kind: model.KindService, Key: "192.0.2.10:8443/tcp", Scope: model.ScopeOwned, Zone: "example.com"}
	// SNI comes from a neighbouring hostname.
	tg := checktest.NewTarget(svc, checktest.WithDialer(d))
	tg.Neighbours = nil
	res, _ := newCheck(ca).Run(context.Background(), tg)
	if len(res.Findings) != 0 {
		t.Errorf("no SNI -> no hostname check: %+v", res.Findings)
	}
	if res.Observations[0].Data["fingerprint_sha256"] == nil {
		t.Error("expected observation")
	}
}

func TestApplies(t *testing.T) {
	c := New(nil)
	tr, fl := true, false
	cases := []struct {
		a    model.Asset
		want bool
	}{
		{model.Asset{Kind: model.KindHostname, Scope: model.ScopeOwned}, true},
		{model.Asset{Kind: model.KindHostname, Scope: model.ScopeOwned, Attrs: map[string]any{"tls": fl}}, false},
		{model.Asset{Kind: model.KindHostname, Scope: model.ScopeExternal}, false},
		{model.Asset{Kind: model.KindService, Key: "192.0.2.1:443/tcp", Scope: model.ScopeOwned}, true},
		{model.Asset{Kind: model.KindService, Key: "192.0.2.1:22/tcp", Scope: model.ScopeOwned}, false},
		{model.Asset{Kind: model.KindService, Key: "192.0.2.1:9999/tcp", Scope: model.ScopeOwned, Attrs: map[string]any{"tls": tr}}, true},
		{model.Asset{Kind: model.KindIP, Scope: model.ScopeOwned}, false},
	}
	for i, tc := range cases {
		if got := c.Applies(tc.a); got != tc.want {
			t.Errorf("case %d: %v", i, got)
		}
	}
}
