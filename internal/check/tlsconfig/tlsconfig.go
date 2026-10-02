// Package tlsconfig implements tls.config: an active enumeration of the TLS
// protocol versions and cipher suites a listener accepts, over the
// scope-guarded Target.Dialer. SSLv3 is not supported by Go and is skipped.
package tlsconfig

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

const checkName = "tls.config"

// Checks returns the tls.config check. defaults is the global per-check
// config map; Target.Config overlays it at run time.
func Checks(defaults map[string]map[string]any) []check.Check {
	return []check.Check{&configCheck{defaults: defaults[checkName]}}
}

type configCheck struct{ defaults map[string]any }

func (*configCheck) Name() string     { return checkName }
func (*configCheck) Tier() model.Tier { return model.TierActive }

var tlsPorts = map[int]bool{443: true, 8443: true, 993: true, 995: true, 465: true, 636: true, 9443: true}

func (*configCheck) Applies(a model.Asset) bool {
	if a.Scope == model.ScopeExcluded || a.Scope == model.ScopeExternal || a.Scope == model.ScopeShared {
		return false
	}
	switch a.Kind {
	case model.KindService:
		if a.Attrs["tls"] == true {
			return true
		}
		_, port, err := serviceAddr(a)
		return err == nil && tlsPorts[port]
	case model.KindHostname:
		return a.Attrs["tls"] == true || a.Attrs["https"] == true
	}
	return false
}

func serviceAddr(a model.Asset) (host string, port int, err error) {
	if ip, ok := a.Attrs["ip"].(string); ok && ip != "" {
		if p := attrInt(a.Attrs["port"]); p > 0 {
			return ip, p, nil
		}
	}
	h, ps, err := net.SplitHostPort(strings.TrimSuffix(a.Key, "/tcp"))
	if err != nil {
		return "", 0, fmt.Errorf("service key %q is not ip:port/tcp", a.Key)
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("service key %q has invalid port", a.Key)
	}
	return h, p, nil
}

func attrInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

// endpoint returns the dial address and SNI for the asset.
func endpoint(a model.Asset) (addr, sni string, err error) {
	switch a.Kind {
	case model.KindHostname:
		port := 443
		if p := attrInt(a.Attrs["port"]); p > 0 {
			port = p
		}
		return net.JoinHostPort(a.Key, strconv.Itoa(port)), a.Key, nil
	case model.KindService:
		h, p, err := serviceAddr(a)
		if err != nil {
			return "", "", err
		}
		for _, k := range []string{"sni", "hostname"} {
			if s, ok := a.Attrs[k].(string); ok && s != "" {
				sni = s
				break
			}
		}
		return net.JoinHostPort(h, strconv.Itoa(p)), sni, nil
	}
	return "", "", fmt.Errorf("tls.config: unsupported asset kind %s", a.Kind)
}

func timeoutOf(m map[string]any, def time.Duration) time.Duration {
	switch v := m["timeout"].(type) {
	case time.Duration:
		return v
	case string:
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	case int:
		return time.Duration(v) * time.Second
	case float64:
		return time.Duration(v * float64(time.Second))
	}
	return def
}

type prober struct {
	d       check.Dialer
	addr    string
	sni     string
	timeout time.Duration
}

// handshake attempts one handshake with cfg and returns the negotiated state.
func (p *prober) handshake(ctx context.Context, cfg *tls.Config) (*tls.ConnectionState, error) {
	cctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	conn, err := p.d.DialContext(cctx, "tcp", p.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	cfg.ServerName = p.sni
	cfg.InsecureSkipVerify = true //nolint:gosec // enumeration only; certificate validity is tls.cert's job
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(cctx); err != nil {
		return nil, err
	}
	st := tc.ConnectionState()
	return &st, nil
}

var allVersions = []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}

// legacySuites returns every suite usable below TLS 1.3, secure or not.
func legacySuites() []*tls.CipherSuite {
	var out []*tls.CipherSuite
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		for _, v := range s.SupportedVersions {
			if v <= tls.VersionTLS12 {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

func (c *configCheck) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	if t.Dialer == nil {
		return nil, fmt.Errorf("tls.config: no dialer in target")
	}
	addr, sni, err := endpoint(t.Asset)
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	for k, v := range c.defaults {
		cfg[k] = v
	}
	for k, v := range t.Config {
		cfg[k] = v
	}
	p := &prober{d: t.Dialer, addr: addr, sni: sni, timeout: timeoutOf(cfg, 5*time.Second)}

	// Offer every legacy suite (Go's defaults omit RSA key exchange and 3DES),
	// otherwise servers that only speak those would look like non-TLS.
	var offer []uint16
	for _, s := range legacySuites() {
		offer = append(offer, s.ID)
	}
	var versions []uint16
	for _, v := range allVersions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := p.handshake(ctx, &tls.Config{MinVersion: v, MaxVersion: v, CipherSuites: offer}); err == nil {
			versions = append(versions, v)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var suites []*tls.CipherSuite
	if hi := highestLegacy(versions); hi != 0 {
		if suites, err = c.enumerateSuites(ctx, p, hi); err != nil {
			return nil, err
		}
	}
	return buildResult(addr, versions, suites), nil
}

func highestLegacy(vs []uint16) uint16 {
	var hi uint16
	for _, v := range vs {
		if v <= tls.VersionTLS12 && v > hi {
			hi = v
		}
	}
	return hi
}

func (c *configCheck) enumerateSuites(ctx context.Context, p *prober, maxV uint16) ([]*tls.CipherSuite, error) {
	var accepted []*tls.CipherSuite
	for _, s := range legacySuites() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !supportsUpTo(s, maxV) {
			continue
		}
		st, err := p.handshake(ctx, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: maxV, CipherSuites: []uint16{s.ID}}) // #nosec G402 -- protocol/cipher enumeration must accept any certificate
		if err == nil && st.CipherSuite == s.ID {
			accepted = append(accepted, s)
		}
	}
	return accepted, nil
}

func supportsUpTo(s *tls.CipherSuite, maxV uint16) bool {
	for _, v := range s.SupportedVersions {
		if v <= maxV {
			return true
		}
	}
	return false
}

type weakness struct {
	label    string
	severity model.Severity
}

// classifySuite reports a weakness for a suite name, if any.
func classifySuite(name string) (weakness, bool) {
	up := strings.ToUpper(name)
	switch {
	case strings.Contains(up, "EXPORT"):
		return weakness{"export-grade", model.SeverityHigh}, true
	case strings.Contains(up, "_NULL_"):
		return weakness{"null encryption", model.SeverityHigh}, true
	case strings.Contains(up, "_ANON_") || strings.Contains(up, "_DH_ANON") || strings.Contains(up, "ANON"):
		return weakness{"anonymous key exchange", model.SeverityHigh}, true
	case strings.Contains(up, "RC4"):
		return weakness{"RC4", model.SeverityHigh}, true
	case strings.Contains(up, "3DES"):
		return weakness{"3DES (Sweet32)", model.SeverityMedium}, true
	case strings.Contains(up, "_DES_") || strings.Contains(up, "_RC2_"):
		return weakness{"single DES/RC2", model.SeverityHigh}, true
	}
	return weakness{}, false
}

func forwardSecret(name string) bool {
	return strings.HasPrefix(name, "TLS_ECDHE_") || strings.HasPrefix(name, "TLS_DHE_") || strings.HasPrefix(name, "TLS_AES_") || strings.HasPrefix(name, "TLS_CHACHA20_")
}

func buildResult(addr string, versions []uint16, suites []*tls.CipherSuite) *check.Result {
	vnames := make([]string, 0, len(versions))
	for _, v := range versions {
		vnames = append(vnames, tls.VersionName(v))
	}
	snames := make([]string, 0, len(suites))
	for _, s := range suites {
		snames = append(snames, s.Name)
	}
	res := &check.Result{Observations: []model.ObservationInput{{Check: checkName, Data: map[string]any{
		"tls": len(versions) > 0, "versions": vnames, "cipher_suites": snames,
	}}}}
	if len(versions) == 0 {
		return res
	}
	has := map[uint16]bool{}
	for _, v := range versions {
		has[v] = true
	}
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if has[v] {
			name := tls.VersionName(v)
			res.Findings = append(res.Findings, finding("proto/"+strings.ReplaceAll(strings.ToLower(name), " ", ""),
				model.SeverityMedium, name+" enabled",
				fmt.Sprintf("%s accepted a %s handshake. TLS 1.0 and 1.1 are deprecated (RFC 8996) and lack modern protections.", addr, name),
				map[string]any{"version": name},
				"Disable TLS 1.0 and 1.1 and require TLS 1.2 or newer.", "protocol"))
		}
	}
	if !has[tls.VersionTLS13] {
		res.Findings = append(res.Findings, finding("proto/no-tls1.3", model.SeverityInfo, "TLS 1.3 not supported",
			addr+" did not negotiate TLS 1.3.", map[string]any{"versions": vnames},
			"Enable TLS 1.3 where the server software supports it.", "protocol"))
	}
	res.Findings = append(res.Findings, cipherFindings(addr, suites, has[tls.VersionTLS13])...)
	return res
}

func cipherFindings(addr string, suites []*tls.CipherSuite, tls13 bool) []model.FindingInput {
	var out []model.FindingInput
	var noFS []string
	for _, s := range suites {
		if w, bad := classifySuite(s.Name); bad {
			out = append(out, finding("cipher/"+s.Name, w.severity, fmt.Sprintf("Weak cipher suite accepted: %s", s.Name),
				fmt.Sprintf("%s accepts %s, which uses %s.", addr, s.Name, w.label),
				map[string]any{"cipher_suite": s.Name, "weakness": w.label},
				"Remove the cipher suite from the server configuration.", "cipher"))
		}
		if !forwardSecret(s.Name) {
			noFS = append(noFS, s.Name)
		}
	}
	if len(noFS) > 0 {
		out = append(out, finding("cipher/no-forward-secrecy", model.SeverityLow, "Cipher suites without forward secrecy accepted",
			fmt.Sprintf("%s accepts suites that use static RSA key exchange, so recorded traffic can be decrypted if the server key is ever compromised.", addr),
			map[string]any{"cipher_suites": noFS, "tls13": tls13},
			"Prefer ECDHE/DHE suites and remove TLS_RSA_* suites.", "cipher"))
	}
	return out
}

func finding(key string, sev model.Severity, title, desc string, ev map[string]any, fix string, tag string) model.FindingInput {
	return model.FindingInput{Check: checkName, Key: key, Severity: sev, Title: title, Description: desc,
		Evidence: ev, Remediation: fix, Tags: []string{"tls", tag}}
}
