package netcheck

import (
	"bufio"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

//go:embed versions.yaml
var versionsYAML []byte

type versionRule struct {
	ID       string `yaml:"id"`
	Match    string `yaml:"match"`
	Severity string `yaml:"severity"`
	Advisory string `yaml:"advisory"`
	re       *regexp.Regexp
}

var (
	rulesOnce sync.Once
	rules     []versionRule
	rulesErr  error
)

func loadRules() ([]versionRule, error) {
	rulesOnce.Do(func() {
		if rulesErr = yaml.Unmarshal(versionsYAML, &rules); rulesErr != nil {
			return
		}
		for i := range rules {
			if rules[i].re, rulesErr = regexp.Compile(rules[i].Match); rulesErr != nil {
				return
			}
		}
	})
	return rules, rulesErr
}

type servicesCheck struct{ defaults map[string]any }

func (*servicesCheck) Name() string     { return "net.services" }
func (*servicesCheck) Tier() model.Tier { return model.TierActive }
func (*servicesCheck) Applies(a model.Asset) bool {
	return a.Kind == model.KindService && a.Scope != model.ScopeExcluded && a.Scope != model.ScopeExternal && a.Scope != model.ScopeShared
}

// svcInfo is what a probe learned about the listener.
type svcInfo struct {
	service    string // ssh, ftp, smtp, http, redis, memcached, elasticsearch, mongodb, tls, ...
	banner     string
	server     string
	version    string
	tls        bool
	tlsVersion string
	auth       string // "none", "required", "" (unknown)
}

func (s svcInfo) identified() bool { return s.service != "" }

type prober struct {
	d       check.Dialer
	host    string
	port    int
	timeout time.Duration
	wait    time.Duration
}

func serviceAddr(a model.Asset) (string, int, error) {
	if ip, ok := a.Attrs["ip"].(string); ok && ip != "" {
		if p := cfgInt(a.Attrs, "port", 0); p > 0 {
			return ip, p, nil
		}
	}
	k := strings.TrimSuffix(a.Key, "/tcp")
	h, ps, err := net.SplitHostPort(k)
	if err != nil {
		return "", 0, fmt.Errorf("service key %q is not ip:port/tcp", a.Key)
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("service key %q has invalid port", a.Key)
	}
	return h, p, nil
}

func (c *servicesCheck) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	if t.Dialer == nil {
		return nil, fmt.Errorf("net.services: no dialer in target")
	}
	cfg := merge(c.defaults, t.Config)
	host, port, err := serviceAddr(t.Asset)
	if err != nil {
		return nil, err
	}
	p := &prober{d: t.Dialer, host: host, port: port,
		timeout: cfgDuration(cfg, "timeout", 5*time.Second),
		wait:    cfgDuration(cfg, "banner_wait", 1500*time.Millisecond)}
	info := p.identify(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return buildServicesResult(t.Asset, info)
}

var tlsPorts = map[int]bool{443: true, 8443: true, 993: true, 995: true, 465: true, 636: true, 9443: true, 853: true}
var bannerPorts = map[int]bool{21: true, 22: true, 25: true, 110: true, 143: true, 587: true, 2121: true}
var httpPorts = map[int]bool{80: true, 8000: true, 8008: true, 8080: true, 8081: true, 8888: true, 3000: true, 9000: true, 9090: true}

func (p *prober) identify(ctx context.Context) svcInfo {
	var order []func(context.Context) svcInfo
	switch {
	case p.port == 6379:
		order = append(order, p.redis)
	case p.port == 11211:
		order = append(order, p.memcached)
	case p.port == 27017:
		order = append(order, p.mongo)
	case p.port == 9200:
		order = append(order, p.http, p.httpsProbe)
	case tlsPorts[p.port]:
		order = append(order, p.httpsProbe)
	case bannerPorts[p.port]:
		order = append(order, p.banner)
	case httpPorts[p.port]:
		order = append(order, p.http, p.httpsProbe)
	}
	order = append(order, p.banner, p.httpsProbe, p.http)
	for _, f := range order {
		if ctx.Err() != nil {
			break
		}
		if info := f(ctx); info.identified() {
			return info
		}
	}
	return svcInfo{}
}

func (p *prober) dial(ctx context.Context) (net.Conn, error) {
	cctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	conn, err := p.d.DialContext(cctx, "tcp", net.JoinHostPort(p.host, strconv.Itoa(p.port)))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(p.timeout))
	return conn, nil
}

func sanitize(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
		if b.Len() >= max {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// banner waits briefly for a server-first greeting.
func (p *prober) banner(ctx context.Context) svcInfo {
	conn, err := p.dial(ctx)
	if err != nil {
		return svcInfo{}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(p.wait))
	line, _ := bufio.NewReaderSize(io.LimitReader(conn, 1024), 1024).ReadString('\n')
	return classifyBanner(sanitize(line, 200))
}

func classifyBanner(b string) svcInfo {
	info := svcInfo{banner: b}
	switch {
	case b == "":
		return svcInfo{}
	case strings.HasPrefix(b, "SSH-"):
		info.service = "ssh"
		if parts := strings.SplitN(b, "-", 3); len(parts) == 3 {
			info.version = strings.Fields(parts[2])[0]
		}
	case strings.HasPrefix(b, "220") && strings.Contains(strings.ToUpper(b), "SMTP"):
		info.service = "smtp"
	case strings.HasPrefix(b, "220"):
		info.service = "ftp"
	case strings.HasPrefix(b, "+OK"):
		info.service = "pop3"
	case strings.HasPrefix(b, "* OK"):
		info.service = "imap"
	case strings.HasPrefix(b, "HTTP/"):
		info.service = "http"
	default:
		return svcInfo{}
	}
	return info
}

func (p *prober) redis(ctx context.Context) svcInfo {
	conn, err := p.dial(ctx)
	if err != nil {
		return svcInfo{}
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return svcInfo{}
	}
	line, _ := bufio.NewReader(io.LimitReader(conn, 512)).ReadString('\n')
	line = sanitize(line, 120)
	switch {
	case strings.HasPrefix(line, "+PONG"):
		return svcInfo{service: "redis", banner: line, auth: "none"}
	case strings.HasPrefix(line, "-NOAUTH"), strings.HasPrefix(line, "-DENIED"), strings.Contains(line, "operation not permitted"):
		return svcInfo{service: "redis", banner: line, auth: "required"}
	}
	return svcInfo{}
}

func (p *prober) memcached(ctx context.Context) svcInfo {
	conn, err := p.dial(ctx)
	if err != nil {
		return svcInfo{}
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return svcInfo{}
	}
	line, _ := bufio.NewReader(io.LimitReader(conn, 512)).ReadString('\n')
	line = sanitize(line, 120)
	if v, ok := strings.CutPrefix(line, "VERSION "); ok {
		return svcInfo{service: "memcached", banner: line, version: strings.TrimSpace(v), auth: "none"}
	}
	return svcInfo{}
}

// mongoIsMaster builds an OP_QUERY isMaster handshake against admin.$cmd.
func mongoIsMaster() []byte {
	doc := []byte{19, 0, 0, 0, 0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0, 1, 0, 0, 0, 0}
	body := []byte{0, 0, 0, 0}
	body = append(body, "admin.$cmd\x00"...)
	body = append(body, 0, 0, 0, 0, 1, 0, 0, 0) // numberToSkip=0, numberToReturn=1
	body = append(body, doc...)
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:], uint32(16+len(body))) // #nosec G115 -- length of a small fixed-size protocol message
	binary.LittleEndian.PutUint32(hdr[4:], 1)
	binary.LittleEndian.PutUint32(hdr[12:], 2004) // OP_QUERY
	return append(hdr, body...)
}

func (p *prober) mongo(ctx context.Context) svcInfo {
	conn, err := p.dial(ctx)
	if err != nil {
		return svcInfo{}
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(mongoIsMaster()); err != nil {
		return svcInfo{}
	}
	buf := make([]byte, 2048)
	n, _ := io.ReadAtLeast(conn, buf, 16)
	resp := string(buf[:max(n, 0)])
	if n >= 16 && (strings.Contains(resp, "ismaster") || strings.Contains(resp, "isWritablePrimary") || strings.Contains(resp, "maxWireVersion")) {
		return svcInfo{service: "mongodb", banner: "isMaster handshake answered"}
	}
	return svcInfo{}
}

func (p *prober) http(ctx context.Context) svcInfo {
	conn, err := p.dial(ctx)
	if err != nil {
		return svcInfo{}
	}
	defer func() { _ = conn.Close() }()
	return p.httpOver(conn, svcInfo{})
}

func (p *prober) httpsProbe(ctx context.Context) svcInfo {
	conn, err := p.dial(ctx)
	if err != nil {
		return svcInfo{}
	}
	defer func() { _ = conn.Close() }()
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) // #nosec G402 -- scanner must inspect services with invalid certificates
	if err := tc.HandshakeContext(ctx); err != nil {
		return svcInfo{}
	}
	st := tc.ConnectionState()
	base := svcInfo{service: "tls", tls: true, tlsVersion: tls.VersionName(st.Version)}
	if r := p.httpOver(tc, base); r.identified() {
		return r
	}
	return base
}

var esVersionRe = regexp.MustCompile(`"number"\s*:\s*"([^"]+)"`)

func (p *prober) httpOver(rw io.ReadWriter, base svcInfo) svcInfo {
	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: deckard-audit\r\nAccept: */*\r\nConnection: close\r\n\r\n", p.host)
	if _, err := io.WriteString(rw, req); err != nil {
		return svcInfo{}
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(rw, 16<<10)), nil)
	if err != nil {
		return svcInfo{}
	}
	defer func() { _ = resp.Body.Close() }()
	info := base
	info.service = "http"
	if base.tls {
		info.service = "https"
	}
	info.server = sanitize(resp.Header.Get("Server"), 120)
	info.banner = fmt.Sprintf("HTTP %d", resp.StatusCode)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if bytesContains(body, `"cluster_name"`) && bytesContains(body, `"version"`) {
		info.service = "elasticsearch"
		if m := esVersionRe.FindSubmatch(body); m != nil {
			info.version = sanitize(string(m[1]), 40)
		}
		if resp.StatusCode == 200 {
			info.auth = "none"
		}
	} else if resp.StatusCode == http.StatusUnauthorized && p.port == 9200 {
		info.auth = "required"
	}
	return info
}

func bytesContains(b []byte, s string) bool { return strings.Contains(string(b), s) }

func buildServicesResult(a model.Asset, s svcInfo) (*check.Result, error) {
	data := map[string]any{"identified": s.identified()}
	res := &check.Result{}
	if s.identified() {
		data["service"] = s.service
		setIf(data, "banner", s.banner)
		setIf(data, "server", s.server)
		setIf(data, "version", s.version)
		setIf(data, "auth", s.auth)
		setIf(data, "tls_version", s.tlsVersion)
		data["tls"] = s.tls
		attrs := map[string]any{}
		for k, v := range a.Attrs {
			attrs[k] = v
		}
		attrs["product"] = s.service
		if s.tls {
			attrs["tls"] = true
		}
		res.Discovered = append(res.Discovered, model.AssetInput{Kind: model.KindService, Key: a.Key, Source: "net.services", Zone: a.Zone, Attrs: attrs})
	}
	res.Observations = []model.ObservationInput{{Check: "net.services", Data: data}}
	res.Findings = append(res.Findings, unauthFindings(s)...)
	vf, err := versionFindings(s)
	if err != nil {
		return nil, err
	}
	res.Findings = append(res.Findings, vf...)
	return res, nil
}

func setIf(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func unauthFindings(s svcInfo) []model.FindingInput {
	mk := func(key string, sev model.Severity, title, desc string) model.FindingInput {
		return model.FindingInput{Check: "net.services", Key: key, Severity: sev, Title: title, Description: desc,
			Evidence:    map[string]any{"service": s.service, "banner": s.banner, "version": s.version},
			Remediation: "Require authentication and bind the service to private interfaces or restrict it with a firewall.",
			Tags:        []string{"net", "exposure", "database", "unauthenticated"}}
	}
	switch {
	case s.service == "redis" && s.auth == "none":
		return []model.FindingInput{mk("unauth/redis", model.SeverityCritical, "Unauthenticated Redis",
			"The Redis port answered PING without authentication, so the data store appears to accept commands from any client that can reach it.")}
	case s.service == "memcached" && s.auth == "none":
		return []model.FindingInput{mk("unauth/memcached", model.SeverityHigh, "Unauthenticated memcached",
			"The memcached port answered a version command without authentication; it can be read, modified and abused for UDP/TCP amplification.")}
	case s.service == "elasticsearch" && s.auth == "none":
		return []model.FindingInput{mk("unauth/elasticsearch", model.SeverityHigh, "Unauthenticated Elasticsearch API",
			"The Elasticsearch root endpoint returned cluster information without credentials; the REST API appears open.")}
	case s.service == "mongodb":
		f := mk("exposed/mongodb", model.SeverityMedium, "MongoDB wire protocol reachable",
			"A MongoDB isMaster handshake was answered. The handshake succeeds even when authentication is enabled, so this shows reachability, not that data is open.")
		f.Tags = []string{"net", "exposure", "database"}
		return []model.FindingInput{f}
	}
	return nil
}

func versionFindings(s svcInfo) ([]model.FindingInput, error) {
	rs, err := loadRules()
	if err != nil {
		return nil, fmt.Errorf("net.services: version rules: %w", err)
	}
	subject := strings.TrimSpace(s.banner + " " + s.server)
	if s.service == "elasticsearch" && s.version != "" {
		subject += " elasticsearch " + s.version
	}
	var out []model.FindingInput
	for _, r := range rs {
		if !r.re.MatchString(subject) && !r.re.MatchString(s.banner) && !r.re.MatchString("elasticsearch "+s.version) {
			continue
		}
		sev := model.Severity(r.Severity)
		if !sev.Valid() {
			sev = model.SeverityLow
		}
		out = append(out, model.FindingInput{
			Check: "net.services", Key: "banner/" + r.ID, Severity: sev,
			Title:       "Service banner indicates outdated software (" + r.ID + ")",
			Description: strings.ToUpper(r.Advisory[:1]) + r.Advisory[1:] + ". Banners can be spoofed or patched downstream; verify the installed version.",
			Evidence:    map[string]any{"banner": s.banner, "server": s.server, "version": s.version},
			Remediation: "Update to a currently supported release, or hide version details after confirming the installed build is patched.",
			Tags:        []string{"net", "outdated"},
		})
	}
	return out, nil
}
