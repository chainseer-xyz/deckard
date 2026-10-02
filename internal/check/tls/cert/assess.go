package cert

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// Options drive the pure certificate assessment.
type Options struct {
	Now      time.Time
	WarnDays int
	CritDays int
	// Host is the name the client expects the certificate to cover; empty skips
	// the hostname check.
	Host string
	// Port prefixes finding keys so each endpoint is tracked separately.
	Port int
	// Roots overrides the system trust store (tests).
	Roots *x509.CertPool
	// ServedBy is the external CNAME target when a third party serves the
	// host. The operator cannot fix that party's certificate, so trust and
	// coverage findings are reported at low severity and expiry is capped at
	// high.
	ServedBy string
}

// Fingerprint is the SHA-256 of the DER certificate, hex encoded.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// DaysRemaining is whole days until expiry (negative once expired).
func DaysRemaining(c *x509.Certificate, now time.Time) int {
	return int(c.NotAfter.Sub(now).Hours() / 24)
}

func selfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawSubject, c.RawIssuer) {
		return false
	}
	// Check against its own key directly: CheckSignatureFrom would also demand
	// CA constraints, which a self-signed leaf does not carry.
	err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
	var insecure x509.InsecureAlgorithmError
	return err == nil || errors.As(err, &insecure)
}

func weakSigAlg(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

func keyBits(c *x509.Certificate) (kind string, bits int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	default:
		return c.PublicKeyAlgorithm.String(), 0
	}
}

func f(o Options, key string, sev model.Severity, title, desc, rem string, ev map[string]any) model.FindingInput {
	if ev == nil {
		ev = map[string]any{}
	}
	ev["port"] = o.Port
	return model.FindingInput{
		Check: Name, Key: fmt.Sprintf("%d:%s", o.Port, key), Severity: sev,
		Title: title, Description: desc, Remediation: rem, Evidence: ev,
		Tags: []string{"tls", "certificate"},
	}
}

// Assess classifies a presented chain (leaf first). It performs no I/O.
func Assess(chain []*x509.Certificate, o Options) []model.FindingInput {
	out := assess(chain, o)
	if o.ServedBy == "" {
		return out
	}
	for i := range out {
		fi := &out[i]
		fi.Evidence["served_by"] = o.ServedBy
		switch {
		case strings.HasSuffix(fi.Key, ":hostname-mismatch"), strings.HasSuffix(fi.Key, ":self-signed"), strings.HasSuffix(fi.Key, ":untrusted-chain"):
			fi.Severity = model.SeverityLow
			fi.Remediation = fmt.Sprintf("This host is served by a third party (CNAME to %s), so its certificate is not under your control. Configure custom-domain TLS with the provider so it presents a certificate for %s, or remove the DNS record if the service is no longer used.", o.ServedBy, firstNonEmpty(o.Host, "this host"))
		case strings.HasSuffix(fi.Key, ":expired") && fi.Severity == model.SeverityCritical:
			fi.Severity = model.SeverityHigh
		}
	}
	return out
}

func assess(chain []*x509.Certificate, o Options) []model.FindingInput {
	if len(chain) == 0 {
		return nil
	}
	leaf := chain[0]
	subject := leaf.Subject.CommonName
	if subject == "" && len(leaf.DNSNames) > 0 {
		subject = leaf.DNSNames[0]
	}
	where := fmt.Sprintf("%s:%d", firstNonEmpty(o.Host, subject), o.Port)
	fp := Fingerprint(leaf)
	base := func() map[string]any {
		return map[string]any{"fingerprint_sha256": fp, "subject": leaf.Subject.String(), "issuer": leaf.Issuer.String(),
			"not_after": leaf.NotAfter.UTC().Format(time.RFC3339)}
	}
	var out []model.FindingInput

	// Validity window.
	days := DaysRemaining(leaf, o.Now)
	switch {
	case o.Now.After(leaf.NotAfter):
		ev := base()
		ev["days_remaining"] = days
		out = append(out, f(o, "expired", model.SeverityCritical,
			fmt.Sprintf("TLS certificate on %s has expired", where),
			fmt.Sprintf("The certificate expired on %s. Clients will reject the connection or show security warnings.", leaf.NotAfter.UTC().Format("2006-01-02")),
			"Renew and deploy a new certificate immediately; check why automated renewal (ACME/cert-manager) did not run.", ev))
	case o.Now.Before(leaf.NotBefore):
		out = append(out, f(o, "not-yet-valid", model.SeverityHigh,
			fmt.Sprintf("TLS certificate on %s is not yet valid", where),
			fmt.Sprintf("The certificate becomes valid on %s; clients with correct clocks reject it.", leaf.NotBefore.UTC().Format(time.RFC3339)),
			"Deploy a certificate whose validity period has started, and verify server clock/issuance time.", base()))
	case days <= o.CritDays:
		ev := base()
		ev["days_remaining"] = days
		out = append(out, f(o, "expiring", model.SeverityHigh,
			fmt.Sprintf("TLS certificate on %s expires in %d days", where, days),
			fmt.Sprintf("The certificate expires on %s, within the critical threshold of %d days.", leaf.NotAfter.UTC().Format("2006-01-02"), o.CritDays),
			"Renew the certificate now and verify the automated renewal pipeline.", ev))
	case days <= o.WarnDays:
		ev := base()
		ev["days_remaining"] = days
		out = append(out, f(o, "expiring", model.SeverityMedium,
			fmt.Sprintf("TLS certificate on %s expires in %d days", where, days),
			fmt.Sprintf("The certificate expires on %s, within the warning threshold of %d days.", leaf.NotAfter.UTC().Format("2006-01-02"), o.WarnDays),
			"Renew the certificate and confirm automated renewal is working.", ev))
	}

	// Hostname coverage.
	if o.Host != "" {
		if err := leaf.VerifyHostname(o.Host); err != nil {
			ev := base()
			ev["expected_host"] = o.Host
			ev["sans"] = leaf.DNSNames
			out = append(out, f(o, "hostname-mismatch", model.SeverityHigh,
				fmt.Sprintf("TLS certificate on %s does not cover %s", where, o.Host),
				"The certificate's names do not include the hostname clients use, so browsers and API clients will fail validation.",
				"Issue a certificate that includes "+o.Host+" in its SANs, or serve the correct certificate for this SNI name.", ev))
		}
	}

	out = append(out, assessTrust(chain, o, where, base)...)

	// Key and signature strength.
	if kind, bits := keyBits(leaf); kind == "RSA" && bits < 2048 {
		ev := base()
		ev["key_type"], ev["key_bits"] = kind, bits
		out = append(out, f(o, "weak-key", model.SeverityMedium,
			fmt.Sprintf("TLS certificate on %s uses a weak %d-bit RSA key", where, bits),
			"RSA keys below 2048 bits can be factored with feasible resources and are rejected by modern clients.",
			"Re-issue the certificate with an RSA key of at least 2048 bits (3072 recommended) or an ECDSA P-256 key.", ev))
	}
	for i, c := range chain {
		if i == len(chain)-1 && i > 0 && selfSigned(c) {
			continue // root signatures are not validated by clients
		}
		if weakSigAlg(c.SignatureAlgorithm) {
			ev := base()
			ev["signature_algorithm"] = c.SignatureAlgorithm.String()
			ev["chain_index"] = i
			out = append(out, f(o, fmt.Sprintf("weak-signature-%d", i), model.SeverityMedium,
				fmt.Sprintf("TLS certificate on %s in the chain is signed with %s", where, c.SignatureAlgorithm),
				"SHA-1 and MD5 signatures are collision-prone and rejected by modern clients.",
				"Re-issue the affected certificate with a SHA-256 (or stronger) signature.", ev))
		}
	}
	return out
}

func assessTrust(chain []*x509.Certificate, o Options, where string, base func() map[string]any) []model.FindingInput {
	leaf := chain[0]
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	// Verify at a moment inside the validity window so expiry is reported once,
	// by the dedicated expiry finding, rather than as an "untrusted" chain.
	at := o.Now
	if at.After(leaf.NotAfter) || at.Before(leaf.NotBefore) {
		at = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: o.Roots, Intermediates: inter, CurrentTime: at})
	if err == nil {
		return nil
	}
	var insecure x509.InsecureAlgorithmError
	if errors.As(err, &insecure) {
		return nil // reported as weak-signature
	}
	var unknown x509.UnknownAuthorityError
	ev := base()
	ev["verify_error"] = err.Error()
	if errors.As(err, &unknown) {
		if len(chain) == 1 && selfSigned(leaf) {
			return []model.FindingInput{f(o, "self-signed", model.SeverityMedium,
				fmt.Sprintf("TLS certificate on %s is self-signed", where),
				"The certificate is signed by its own key and is not trusted by clients.",
				"Replace it with a certificate issued by a trusted CA (e.g. ACME/Let's Encrypt), or by your internal CA distributed to clients.", ev)}
		}
		return []model.FindingInput{f(o, "untrusted-chain", model.SeverityMedium,
			fmt.Sprintf("TLS certificate chain on %s is not trusted", where),
			"The chain does not lead to a trusted root. The server may be missing intermediate certificates, or the issuer is not publicly trusted.",
			"Serve the full chain including intermediates, or use a certificate from a publicly trusted CA.", ev)}
	}
	return []model.FindingInput{f(o, "untrusted-chain", model.SeverityMedium,
		fmt.Sprintf("TLS certificate chain on %s failed validation", where),
		"Chain validation failed: "+err.Error(),
		"Fix the certificate chain so it validates against the public trust store.", ev)}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
