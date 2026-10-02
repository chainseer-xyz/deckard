package cert

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestAssessThirdPartyServed(t *testing.T) {
	ca := checktest.NewCA(t)
	opts := Options{Now: now, WarnDays: 21, CritDays: 7, Host: "click.example.com", Port: 443, Roots: ca.Pool, ServedBy: "track.esp.example.net"}
	cases := []struct {
		name string
		spec checktest.CertSpec
		key  string
		want model.Severity
	}{
		{"mismatch", checktest.CertSpec{DNSNames: []string{"other.example.net"}, NotBefore: days(-30), NotAfter: days(90)}, "443:hostname-mismatch", model.SeverityLow},
		{"self-signed", checktest.CertSpec{DNSNames: []string{"click.example.com"}, NotBefore: days(-30), NotAfter: days(90), SelfSign: true}, "443:self-signed", model.SeverityLow},
		{"untrusted", checktest.CertSpec{DNSNames: []string{"click.example.com"}, NotBefore: days(-30), NotAfter: days(90)}, "443:untrusted-chain", model.SeverityLow},
		{"expired", checktest.CertSpec{DNSNames: []string{"click.example.com"}, NotBefore: days(-100), NotAfter: days(-1)}, "443:expired", model.SeverityHigh},
		{"expiring", checktest.CertSpec{DNSNames: []string{"click.example.com"}, NotBefore: days(-80), NotAfter: days(5)}, "443:expiring", model.SeverityHigh},
	}
	for _, c := range cases {
		o := opts
		if c.name == "untrusted" {
			o.Roots = checktest.NewCA(t).Pool // chain does not lead to a trusted root
		}
		_, leaf := ca.Issue(t, c.spec)
		var found bool
		for _, f := range Assess([]*x509.Certificate{leaf}, o) {
			if f.Key != c.key {
				continue
			}
			found = true
			if f.Severity != c.want {
				t.Errorf("%s: severity %s want %s", c.name, f.Severity, c.want)
			}
			if f.Evidence["served_by"] != "track.esp.example.net" {
				t.Errorf("%s: evidence %+v", c.name, f.Evidence)
			}
			if c.want == model.SeverityLow && !strings.Contains(f.Remediation, "custom-domain TLS") {
				t.Errorf("%s: remediation %q", c.name, f.Remediation)
			}
		}
		if !found {
			t.Errorf("%s: finding %s missing", c.name, c.key)
		}
	}
}

func TestRunThirdPartyNeighbourDowngrades(t *testing.T) {
	ca := checktest.NewCA(t)
	cert, _ := ca.Issue(t, checktest.CertSpec{DNSNames: []string{"other.example.net"}, NotBefore: days(-30), NotAfter: days(90)})
	addr := checktest.ServeTLS(t, cert)
	d := &checktest.Dialer{Routes: map[string]string{"click.example.com:443": addr}}
	ext := check.Neighbour{Asset: model.Asset{Kind: model.KindHostname, Key: "track.esp.example.net", Scope: model.ScopeExternal}, Relation: model.RelCNAMETo, Outbound: true}
	owned := check.Neighbour{Asset: model.Asset{Kind: model.KindHostname, Key: "lb.example.com", Scope: model.ScopeOwned}, Relation: model.RelCNAMETo, Outbound: true}
	inbound := check.Neighbour{Asset: model.Asset{Kind: model.KindHostname, Key: "x.example.net", Scope: model.ScopeExternal}, Relation: model.RelCNAMETo, Outbound: false}

	run := func(n ...check.Neighbour) model.Severity {
		tg := checktest.NewTarget(checktest.Hostname("click.example.com", "example.com"), checktest.WithDialer(d), checktest.WithNeighbours(n...))
		res, _ := newCheck(ca).Run(context.Background(), tg)
		return keyset(res.Findings)["443:hostname-mismatch"]
	}
	if got := run(ext); got != model.SeverityLow {
		t.Errorf("external cname target: %s", got)
	}
	if got := run(owned, inbound); got != model.SeverityHigh {
		t.Errorf("owned/inbound neighbours must not downgrade: %s", got)
	}
	if got := run(); got != model.SeverityHigh {
		t.Errorf("no neighbours: %s", got)
	}
}
