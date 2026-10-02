// Package cert implements tls.cert: certificate expiry, hostname coverage,
// trust, key/signature strength, plus SAN-based hostname discovery.
//
// Applies to hostname assets (not marked tls=false) and to service assets on
// TLS ports. A handshake failure is only a finding when TLS was expected
// (hostname attrs tls=true / tls_ports set, or a service asset).
//
// Config keys:
//
//	warn_days        int       medium severity within this many days (default 21)
//	crit_days        int       high severity within this many days (default 7)
//	ports            []int     ports to check on hostnames (default [443])
//	owned_zones      []string  zones whose SAN names are emitted as discovered
//	timeout_seconds  int       dial+handshake timeout (default 10)
//
// Asset attrs read: tls (bool), tls_ports ([]int), sni (string, services).
package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Name is the check's registry name.
const Name = "tls.cert"

// tlsPorts are well-known TLS service ports used to decide whether a service
// asset is TLS when attrs.tls is not set.
var tlsPorts = map[int]bool{443: true, 465: true, 636: true, 853: true, 989: true, 990: true, 993: true, 995: true, 5061: true, 8443: true, 9443: true}

// Check is the tls.cert check.
type Check struct {
	base  map[string]any
	now   func() time.Time
	roots *x509.CertPool
}

// New builds the check.
func New(cfg map[string]any) *Check { return &Check{base: cfg, now: time.Now} }

// Checks is the wiring constructor.
func Checks(cfg map[string]map[string]any) []check.Check { return []check.Check{New(cfg[Name])} }

func (*Check) Name() string     { return Name }
func (*Check) Tier() model.Tier { return model.TierPassive }

func attrBool(a model.Asset, k string) (val, set bool) {
	v, ok := a.Attrs[k].(bool)
	return v, ok
}

func servicePort(a model.Asset) (host string, port int, ok bool) {
	key := strings.TrimSuffix(a.Key, "/tcp")
	h, p, err := net.SplitHostPort(key)
	if err != nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(p)
	return h, n, err == nil
}

// Applies matches owned hostnames and TLS service assets.
func (*Check) Applies(a model.Asset) bool {
	if a.Scope != model.ScopeOwned {
		return false
	}
	switch a.Kind {
	case model.KindHostname:
		v, set := attrBool(a, "tls")
		return !set || v
	case model.KindService:
		_, port, ok := servicePort(a)
		if !ok {
			return false
		}
		if v, set := attrBool(a, "tls"); set {
			return v
		}
		return tlsPorts[port]
	}
	return false
}

type endpoint struct {
	dialHost  string
	port      int
	sni       string
	expectTLS bool
}

func endpoints(t check.Target, cfg map[string]any) []endpoint {
	a := t.Asset
	if a.Kind == model.KindService {
		h, p, _ := servicePort(a)
		sni, _ := a.Attrs["sni"].(string)
		if sni == "" {
			for _, n := range t.Neighbours {
				if n.Asset.Kind == model.KindHostname {
					sni = n.Asset.Key
					break
				}
			}
		}
		return []endpoint{{dialHost: h, port: p, sni: sni, expectTLS: true}}
	}
	host := checkutil.Norm(a.Key)
	ports := checkutil.Ints(cfg, "ports", []int{443})
	expect, _ := attrBool(a, "tls")
	if tp := checkutil.Ints(a.Attrs, "tls_ports", nil); len(tp) > 0 {
		ports, expect = tp, true
	}
	var eps []endpoint
	for _, p := range ports {
		eps = append(eps, endpoint{dialHost: host, port: p, sni: host, expectTLS: expect})
	}
	return eps
}

func (c *Check) handshake(ctx context.Context, t check.Target, ep endpoint, timeout time.Duration) (*tls.ConnectionState, error, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := t.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(ep.dialHost, strconv.Itoa(ep.port)))
	if err != nil {
		return nil, err, nil
	}
	defer func() { _ = conn.Close() }()
	// Verification is done by Assess so each failure mode gets its own finding;
	// the handshake itself must therefore accept any certificate.
	tc := tls.Client(conn, &tls.Config{ServerName: ep.sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) // #nosec G402 -- certificate checker must classify invalid chains itself
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	st := tc.ConnectionState()
	return &st, nil, nil
}

// servedBy returns the external CNAME target a hostname asset points at ("" if
// none): such hosts are served by a third party whose certificate the
// operator cannot change.
func servedBy(t check.Target) string {
	if t.Asset.Kind != model.KindHostname {
		return ""
	}
	for _, n := range t.Neighbours {
		if n.Outbound && n.Relation == model.RelCNAMETo && n.Asset.Scope == model.ScopeExternal {
			return checkutil.Norm(n.Asset.Key)
		}
	}
	return ""
}

// Run connects to each endpoint and assesses the presented chain.
func (c *Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := checkutil.Merge(c.base, t.Config)
	t.Config = cfg
	timeout := time.Duration(checkutil.Int(cfg, "timeout_seconds", 10)) * time.Second
	zones := checkutil.OwnedZones(t)
	res := &check.Result{}
	var eps []map[string]any
	seenSAN := map[string]bool{}
	host := checkutil.Norm(t.Asset.Key)

	for _, ep := range endpoints(t, cfg) {
		e := map[string]any{"port": ep.port, "sni": ep.sni}
		st, dialErr, hsErr := c.handshake(ctx, t, ep, timeout)
		switch {
		case dialErr != nil:
			e["error"] = "connect: " + dialErr.Error()
		case hsErr != nil:
			e["error"] = "handshake: " + hsErr.Error()
			if ep.expectTLS {
				res.Findings = append(res.Findings, model.FindingInput{
					Check: Name, Key: strconv.Itoa(ep.port) + ":handshake-failed", Severity: model.SeverityInfo,
					Title:       "TLS handshake failed on " + net.JoinHostPort(ep.dialHost, strconv.Itoa(ep.port)),
					Description: "The port accepted a connection but did not complete a TLS handshake, although TLS is expected here: " + hsErr.Error(),
					Remediation: "Verify the service is configured for TLS on this port, or update the asset's tls attributes if it is plaintext by design.",
					Evidence:    map[string]any{"port": ep.port, "sni": ep.sni, "error": hsErr.Error()},
					Tags:        []string{"tls"},
				})
			}
		default:
			chain := st.PeerCertificates
			if len(chain) == 0 {
				e["error"] = "no peer certificates"
				break
			}
			leaf := chain[0]
			kind, bits := keyBits(leaf)
			e["fingerprint_sha256"] = Fingerprint(leaf)
			e["subject"], e["issuer"], e["serial"] = leaf.Subject.String(), leaf.Issuer.String(), leaf.SerialNumber.String()
			e["not_before"], e["not_after"] = leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339)
			e["days_remaining"] = DaysRemaining(leaf, c.now())
			e["sans"] = leaf.DNSNames
			e["key_type"], e["key_bits"] = kind, bits
			e["signature_algorithm"] = leaf.SignatureAlgorithm.String()
			e["tls_version"] = tls.VersionName(st.Version)
			e["chain_length"] = len(chain)
			res.Findings = append(res.Findings, Assess(chain, Options{
				Now: c.now(), WarnDays: checkutil.Int(cfg, "warn_days", 21), CritDays: checkutil.Int(cfg, "crit_days", 7),
				Host: ep.sni, Port: ep.port, Roots: c.roots, ServedBy: servedBy(t),
			})...)
			for _, san := range leaf.DNSNames {
				san = checkutil.Norm(san)
				z := checkutil.ZoneOf(san, zones)
				if strings.Contains(san, "*") || z == "" || san == host || seenSAN[san] {
					continue
				}
				seenSAN[san] = true
				res.Discovered = append(res.Discovered, model.AssetInput{
					Kind: model.KindHostname, Key: san, Source: checkutil.Source(Name), Zone: z,
				})
			}
		}
		eps = append(eps, e)
	}
	obs := map[string]any{"endpoints": eps}
	for _, e := range eps { // top-level summary from the first endpoint that produced a cert
		if _, ok := e["fingerprint_sha256"]; ok {
			for _, k := range []string{"fingerprint_sha256", "issuer", "not_after", "sans"} {
				obs[k] = e[k]
			}
			break
		}
	}
	res.Observations = append(res.Observations, model.ObservationInput{Check: Name, Data: obs})
	return res, nil
}
