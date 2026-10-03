// Package takeover implements dns.takeover: detect owned hostnames whose
// external CNAME points at an unclaimed resource on a third-party provider.
//
// Safety: only the OWNED hostname is ever requested (over HTTP(S) through the
// scope-guarded client). The provider's own endpoint is never connected to,
// scanned or probed; its name is only resolved via DNS.
//
// Config keys:
//
//	owned_zones  []string  zones treated as internal (their CNAME targets are
//	                       not third-party); default is the asset's zone
//	timeout_seconds int    per-request timeout (default 10)
package takeover

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "dns.takeover"

//go:embed fingerprints.yaml
var embedded []byte

// Fingerprint is one provider signature.
type Fingerprint struct {
	Provider    string   `yaml:"provider"`
	CNAME       []string `yaml:"cname"`
	Fingerprint []string `yaml:"fingerprint,omitempty"`
	NXDomain    bool     `yaml:"nxdomain,omitempty"`
	Status      string   `yaml:"status"`
	// DefaultCert lists bare domains (no wildcard) under which the provider's
	// DEFAULT certificate is issued, e.g. cloudfront.net for *.cloudfront.net.
	// Optional; without it a provider default certificate is never recognised.
	DefaultCert []string `yaml:"default_cert,omitempty"`

	res []*regexp.Regexp
}

// Load parses and validates a fingerprint YAML document.
func Load(data []byte) ([]Fingerprint, error) {
	var fps []Fingerprint
	if err := yaml.Unmarshal(data, &fps); err != nil {
		return nil, fmt.Errorf("takeover: parse fingerprints: %w", err)
	}
	for i := range fps {
		if err := fps[i].compile(); err != nil {
			return nil, fmt.Errorf("takeover: %s: %w", fps[i].Provider, err)
		}
	}
	return fps, nil
}

// compile validates one entry and compiles its cname patterns.
func (f *Fingerprint) compile() error {
	if f.Provider == "" || len(f.CNAME) == 0 {
		return errors.New("needs provider and cname")
	}
	if f.Status != "vulnerable" && f.Status != "edge-case" {
		return fmt.Errorf("bad status %q", f.Status)
	}
	if !f.NXDomain && len(f.Fingerprint) == 0 {
		return errors.New("needs a body fingerprint or nxdomain:true")
	}
	f.res = f.res[:0]
	for _, p := range f.CNAME {
		re, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		f.res = append(f.res, re)
	}
	return nil
}

// MatchCNAME returns the fingerprint whose cname pattern matches target.
func MatchCNAME(fps []Fingerprint, target string) *Fingerprint {
	target = checkutil.Norm(target)
	for i := range fps {
		for _, re := range fps[i].res {
			if re.MatchString(target) {
				return &fps[i]
			}
		}
	}
	return nil
}

// MatchBody reports which fingerprint string appears in body ("" if none).
func (f *Fingerprint) MatchBody(body []byte) string {
	for _, s := range f.Fingerprint {
		if bytes.Contains(body, []byte(s)) {
			return s
		}
	}
	return ""
}

// Severity maps provider status to the maximum finding severity (the value
// for a confirmed match).
func (f *Fingerprint) Severity() model.Severity {
	if f.Status == "vulnerable" {
		return model.SeverityCritical
	}
	return model.SeverityHigh
}

// IsDefaultCert reports whether every DNS name on leaf lies under one of the
// provider's default-certificate domains, i.e. the certificate is the
// provider's shared default and proves nothing about the owned hostname.
func (f *Fingerprint) IsDefaultCert(leaf *x509.Certificate) bool {
	if len(f.DefaultCert) == 0 || len(leaf.DNSNames) == 0 {
		return false
	}
	for _, san := range leaf.DNSNames {
		san = strings.TrimPrefix(checkutil.Norm(san), "*.")
		ok := false
		for _, d := range f.DefaultCert {
			d = checkutil.Norm(d)
			if san == d || strings.HasSuffix(san, "."+d) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// HTTPS certificate classification recorded as evidence "https_cert".
const (
	certValidForHost    = "valid_for_host"
	certProviderDefault = "provider_default"
	certInvalidForHost  = "invalid_for_host"
	certUnavailable     = "unavailable"
)

func certConfirms(state string) bool {
	return state == certProviderDefault || state == certInvalidForHost
}

func slug(s string) string {
	return strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(s), "-"), "-")
}

// BuildFinding creates the takeover finding.
func BuildFinding(host, cname string, f *Fingerprint, reason string, evidence map[string]any) model.FindingInput {
	ev := map[string]any{"host": host, "cname": cname, "provider": f.Provider, "status": f.Status, "reason": reason}
	for k, v := range evidence {
		ev[k] = v
	}
	sev, note := f.Severity(), ""
	// Edge-case providers are only claimable under some conditions, so they
	// need the HTTPS certificate confirmation to stay at high severity.
	if st, ok := ev["https_cert"].(string); f.Status != "vulnerable" && (!ok || !certConfirms(st)) {
		sev = model.SeverityMedium
		note = " The match is unconfirmed: HTTPS did not show the provider's default certificate."
	}
	return model.FindingInput{
		Check: Name, Key: "takeover:" + slug(f.Provider), Severity: sev,
		Title:       "possible subdomain takeover via " + f.Provider,
		Description: fmt.Sprintf("%s is a CNAME to %s (%s) and the provider reports the target resource as unclaimed (%s). An attacker could register that resource with the provider and serve content, steal cookies scoped to the parent domain, or phish under your name.%s", host, cname, f.Provider, reason, note),
		Remediation: fmt.Sprintf("Remove the CNAME for %s if it is unused, or re-create and claim the resource at %s that it points to. Prefer deleting the DNS record before decommissioning the provider resource.", host, f.Provider),
		Evidence:    ev, Tags: []string{"dns", "takeover", slug(f.Provider)},
	}
}

// Check is the dns.takeover check.
type Check struct {
	base  map[string]any
	fps   []Fingerprint  // nil: read the live database (see Fingerprints)
	roots *x509.CertPool // nil = system roots; tests inject a CA
}

// New builds the check on the live fingerprint database: the embedded data
// until SetFingerprints installs a refreshed one, which takes effect on the
// next Run without a restart.
func New(cfg map[string]any) *Check { return &Check{base: cfg} }

// NewWithFingerprints builds the check with a fixed custom DB (tests).
func NewWithFingerprints(cfg map[string]any, fps []Fingerprint) *Check {
	return &Check{base: cfg, fps: fps}
}

// Checks is the wiring constructor.
func Checks(cfg map[string]map[string]any) []check.Check { return []check.Check{New(cfg[Name])} }

func (c *Check) db() []Fingerprint {
	if c.fps != nil {
		return c.fps
	}
	return Fingerprints()
}

func (*Check) Name() string     { return Name }
func (*Check) Tier() model.Tier { return model.TierPassive }

// Applies matches owned hostnames; whether the CNAME is external is only known
// after resolving, so Run filters further.
func (*Check) Applies(a model.Asset) bool {
	return a.Kind == model.KindHostname && a.Scope == model.ScopeOwned
}

// Run resolves the CNAME and, for a known provider, confirms via the owned name.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	t.Config = cfg
	host := checkutil.Norm(t.Asset.Key)
	res := &check.Result{}
	obs := map[string]any{"host": host}
	defer func() { res.Observations = append(res.Observations, model.ObservationInput{Check: Name, Data: obs}) }()

	// SERVFAIL, timeouts and unreachable hosts are unknown, not clean: such a
	// run is partial so it cannot count a miss against an open finding.
	cname, err := t.Resolver.LookupCNAME(ctx, host)
	if err != nil {
		if !checkutil.IsNotFound(err) {
			obs["cname_error"] = err.Error()
			res.Partial = true
		}
		return res, nil
	}
	final := checkutil.Norm(cname)
	if final == host {
		return res, nil
	}
	obs["cname"] = final
	if checkutil.ZoneOf(final, checkutil.OwnedZones(t)) != "" {
		obs["external"] = false
		return res, nil
	}
	obs["external"] = true
	fp := MatchCNAME(c.db(), final)
	if fp == nil {
		return res, nil
	}
	obs["provider"] = fp.Provider

	timeout := time.Duration(checkutil.Int(cfg, "timeout_seconds", 10)) * time.Second

	if fp.NXDomain {
		_, err := t.Resolver.LookupHost(ctx, final)
		obs["target_nxdomain"] = checkutil.IsNotFound(err)
		if err != nil && !checkutil.IsNotFound(err) {
			obs["target_error"] = err.Error()
			res.Partial = true
		}
		if checkutil.IsNotFound(err) {
			state := c.probeCert(ctx, t, host, fp, timeout, obs)
			if state == certValidForHost {
				obs["takeover_suppressed"] = "valid_cert_for_host"
				return res, nil
			}
			res.Findings = append(res.Findings, BuildFinding(host, final, fp, "CNAME target does not exist (NXDOMAIN)", map[string]any{"https_cert": state}))
		}
		return res, nil
	}

	// A certificate that verifies for the owned hostname and is not the
	// provider's shared default means someone who controls a certificate for
	// it serves the host: the provider has the alias, so it is not dangling.
	state := c.probeCert(ctx, t, host, fp, timeout, obs)
	if state == certValidForHost {
		obs["takeover_suppressed"] = "valid_cert_for_host"
		return res, nil
	}
	var errs []string
	for _, scheme := range []string{"https", "http"} {
		resp, err := checkutil.Fetch(ctx, t.HTTP, scheme+"://"+host+"/", checkutil.FetchOpts{Timeout: timeout})
		if err != nil {
			errs = append(errs, scheme+": "+err.Error())
			continue
		}
		obs[scheme+"_status"] = resp.Status
		if m := fp.MatchBody(resp.Body); m != "" {
			obs["matched_fingerprint"] = m
			res.Findings = append(res.Findings, BuildFinding(host, final, fp,
				"provider error page served for this hostname",
				map[string]any{"url": scheme + "://" + host + "/", "http_status": resp.Status, "matched": m, "https_cert": state}))
			break
		}
	}
	if len(errs) > 0 {
		obs["fetch_errors"] = errs
		if len(res.Findings) == 0 && len(errs) == 2 {
			res.Partial = true // neither scheme answered: nothing was checked
		}
	}
	return res, nil
}

// probeCert handshakes with the owned hostname (SNI=host) through the scope
// guarded dialer and classifies the presented certificate. Verification is
// explicit (x509 Verify against the roots with DNSName=host) so each outcome
// can be classified; the handshake itself accepts any certificate.
func (c *Check) probeCert(ctx context.Context, t check.Target, host string, fp *Fingerprint, timeout time.Duration, obs map[string]any) string {
	if t.Dialer == nil {
		obs["https_cert"] = certUnavailable
		return certUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := t.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		obs["https_cert"], obs["https_cert_error"] = certUnavailable, "connect: "+err.Error()
		return certUnavailable
	}
	defer func() { _ = conn.Close() }()
	tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) // #nosec G402 -- chain is verified explicitly below to classify the outcome
	if err := tc.HandshakeContext(ctx); err != nil {
		obs["https_cert"], obs["https_cert_error"] = certUnavailable, "handshake: "+err.Error()
		return certUnavailable
	}
	chain := tc.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		obs["https_cert"] = certUnavailable
		return certUnavailable
	}
	leaf := chain[0]
	obs["https_cert_sans"] = leaf.DNSNames
	state := certInvalidForHost
	switch {
	case fp.IsDefaultCert(leaf):
		state = certProviderDefault
	case verifiesFor(chain, host, c.roots):
		state = certValidForHost
	}
	obs["https_cert"] = state
	return state
}

func verifiesFor(chain []*x509.Certificate, host string, roots *x509.CertPool) bool {
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter})
	return err == nil
}
