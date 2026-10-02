package netcheck

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

type plainDialer struct{ calls atomic.Int32 }

func (d *plainDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.calls.Add(1)
	var nd net.Dialer
	return nd.DialContext(ctx, network, addr)
}

// listen starts a TCP server on 127.0.0.1 running handler per connection.
func listen(t *testing.T, handler func(net.Conn)) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); handler(c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		spec    string
		want    []int
		wantErr bool
	}{
		{"22,80,443", []int{22, 80, 443}, false},
		{"8000-8002,22,22", []int{22, 8000, 8001, 8002}, false},
		{" 80 , 81 ", []int{80, 81}, false},
		{"0", nil, true},
		{"70000", nil, true},
		{"9-3", nil, true},
		{"abc", nil, true},
		{"", nil, true},
	}
	for _, tc := range tests {
		got, err := ParsePorts(tc.spec)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%q: err=%v wantErr=%v", tc.spec, err, tc.wantErr)
		}
		if err == nil && !equalInts(got, tc.want) {
			t.Errorf("%q: got %v want %v", tc.spec, got, tc.want)
		}
	}
	for spec, min := range map[string]int{"top-100": 90, "top-1000": 1000} {
		got, err := ParsePorts(spec)
		if err != nil || len(got) < min {
			t.Errorf("%s: len=%d err=%v", spec, len(got), err)
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ipAsset() model.Asset {
	return model.Asset{Kind: model.KindIP, Key: "127.0.0.1", Scope: model.ScopeOwned}
}

func TestPortsApplies(t *testing.T) {
	c := &portsCheck{}
	tests := []struct {
		a    model.Asset
		want bool
	}{
		{ipAsset(), true},
		{model.Asset{Kind: model.KindIP, Scope: model.ScopeShared}, false},
		{model.Asset{Kind: model.KindHostname, Scope: model.ScopeOwned}, false},
	}
	for _, tc := range tests {
		if got := c.Applies(tc.a); got != tc.want {
			t.Errorf("%+v: got %v", tc.a, got)
		}
	}
	if c.Tier() != model.TierActive {
		t.Error("tier")
	}
}

func TestPortsScan(t *testing.T) {
	p1 := listen(t, func(net.Conn) {})
	p2 := listen(t, func(net.Conn) {})
	closed := p2 + 1 // almost certainly unused
	if closed == p1 {
		closed++
	}
	spec := strconv.Itoa(p1) + "," + strconv.Itoa(p2) + "," + strconv.Itoa(closed)

	tests := []struct {
		name         string
		cfg          map[string]any
		baseline     map[string]map[string]any
		wantOpen     int
		wantFindings int
		wantKey      string
	}{
		{"all unexpected", map[string]any{"ports": spec, "timeout": "500ms"}, nil, 2, 2, ""},
		{"one allowed", map[string]any{"ports": spec, "allowed_ports": []any{p1}, "timeout": "500ms"}, nil, 2, 1, strconv.Itoa(p2) + "/tcp"},
		{"excluded not scanned", map[string]any{"ports": spec, "exclude_ports": []any{p2}, "timeout": "500ms"}, nil, 1, 1, strconv.Itoa(p1) + "/tcp"},
		{"baseline accepts low", map[string]any{"ports": spec, "timeout": "500ms"},
			map[string]map[string]any{"net.ports": {"ports": []any{float64(p1)}}}, 2, 2, ""}, // p1 baseline-skipped, p2 finding + drift
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &plainDialer{}
			res, err := (&portsCheck{}).Run(context.Background(), check.Target{Asset: ipAsset(), Dialer: d, Config: tc.cfg, Baseline: tc.baseline})
			if err != nil {
				t.Fatal(err)
			}
			open := res.Observations[0].Data["ports"].([]int)
			if len(open) != tc.wantOpen {
				t.Errorf("open=%v", open)
			}
			if len(res.Findings) != tc.wantFindings {
				t.Errorf("findings=%d want %d: %+v", len(res.Findings), tc.wantFindings, res.Findings)
			}
			if tc.wantKey != "" && res.Findings[0].Key != tc.wantKey {
				t.Errorf("key=%s", res.Findings[0].Key)
			}
			if len(res.Discovered) != tc.wantOpen || len(res.Relations) != tc.wantOpen {
				t.Errorf("discovered=%d relations=%d", len(res.Discovered), len(res.Relations))
			}
		})
	}
}

func TestPortsBaselineNeverHidesHighRisk(t *testing.T) {
	res := buildPortsResult("192.0.2.1", []int{6379, 80}, nil, map[int]bool{6379: true, 80: true}, nil)
	if len(res.Findings) != 1 || res.Findings[0].Key != "6379/tcp" || res.Findings[0].Severity != model.SeverityHigh {
		t.Fatalf("%+v", res.Findings)
	}
	if res.Discovered[0].Key != "192.0.2.1:6379/tcp" || res.Relations[0].Type != model.RelExposes {
		t.Fatalf("%+v %+v", res.Discovered, res.Relations)
	}
}

func TestPortSeverityClassesAndOverride(t *testing.T) {
	res := buildPortsResult("192.0.2.1", []int{22, 80, 2375, 40000}, nil, nil, map[string]any{"port_severity": map[string]any{"22": "medium"}})
	got := map[string]model.Severity{}
	for _, f := range res.Findings {
		got[f.Key] = f.Severity
	}
	want := map[string]model.Severity{"22/tcp": model.SeverityMedium, "80/tcp": model.SeverityInfo, "2375/tcp": model.SeverityCritical, "40000/tcp": model.SeverityLow}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %s want %s", k, got[k], v)
		}
	}
}

func TestPortsCancelReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&portsCheck{}).Run(ctx, check.Target{Asset: ipAsset(), Dialer: &plainDialer{}, Config: map[string]any{"ports": "1-2000"}})
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestPortsRequiresDialer(t *testing.T) {
	if _, err := (&portsCheck{}).Run(context.Background(), check.Target{Asset: ipAsset()}); err == nil {
		t.Fatal("expected error")
	}
}

func svcAsset(port int) model.Asset {
	return model.Asset{Kind: model.KindService, Key: "127.0.0.1:" + strconv.Itoa(port) + "/tcp", Scope: model.ScopeOwned,
		Attrs: map[string]any{"ip": "127.0.0.1", "port": port}}
}

func runSvc(t *testing.T, port int) *check.Result {
	t.Helper()
	res, err := (&servicesCheck{}).Run(context.Background(), check.Target{Asset: svcAsset(port), Dialer: &plainDialer{},
		Config: map[string]any{"timeout": "2s", "banner_wait": "300ms"}})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func findingKeys(r *check.Result) []string {
	var k []string
	for _, f := range r.Findings {
		k = append(k, f.Key)
	}
	return k
}

func hasKey(r *check.Result, key string) *model.FindingInput {
	for i := range r.Findings {
		if r.Findings[i].Key == key {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestServicesBanners(t *testing.T) {
	tests := []struct {
		name    string
		banner  string
		service string
		finding string
	}{
		{"old openssh", "SSH-2.0-OpenSSH_5.3\r\n", "ssh", "banner/openssh-legacy"},
		{"modern openssh", "SSH-2.0-OpenSSH_9.6\r\n", "ssh", ""},
		{"vsftpd backdoor version", "220 (vsFTPd 2.3.4)\r\n", "ftp", "banner/vsftpd-234"},
		{"smtp", "220 mail.example.com ESMTP Postfix\r\n", "smtp", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port := listen(t, func(c net.Conn) { _, _ = io.WriteString(c, tc.banner) })
			res := runSvc(t, port)
			if res.Observations[0].Data["service"] != tc.service {
				t.Fatalf("obs=%v", res.Observations[0].Data)
			}
			if tc.finding == "" && len(res.Findings) != 0 {
				t.Fatalf("unexpected findings %v", findingKeys(res))
			}
			if tc.finding != "" {
				f := hasKey(res, tc.finding)
				if f == nil {
					t.Fatalf("missing %s in %v", tc.finding, findingKeys(res))
				}
				if !strings.Contains(strings.ToLower(f.Description), "banner indicates") {
					t.Errorf("immodest description: %s", f.Description)
				}
			}
		})
	}
}

func TestServicesRedis(t *testing.T) {
	tests := []struct {
		name  string
		reply string
		want  string
		sev   model.Severity
	}{
		{"unauthenticated", "+PONG\r\n", "unauth/redis", model.SeverityCritical},
		{"auth required", "-NOAUTH Authentication required.\r\n", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// redis detection is by content, so any port works via the generic path.
			port := listen(t, func(c net.Conn) {
				buf := make([]byte, 16)
				n, _ := c.Read(buf)
				if strings.HasPrefix(string(buf[:n]), "PING") {
					_, _ = io.WriteString(c, tc.reply)
				}
			})
			p := &prober{d: &plainDialer{}, host: "127.0.0.1", port: port, timeout: 2 * time.Second, wait: 200 * time.Millisecond}
			info := p.redis(context.Background())
			res, err := buildServicesResult(svcAsset(port), info)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if len(res.Findings) != 0 || info.service != "redis" {
					t.Fatalf("%+v %v", info, findingKeys(res))
				}
				return
			}
			f := hasKey(res, tc.want)
			if f == nil || f.Severity != tc.sev || f.Title != "Unauthenticated Redis" {
				t.Fatalf("%v", res.Findings)
			}
		})
	}
}

func TestServicesMemcachedAndMongo(t *testing.T) {
	mc := listen(t, func(c net.Conn) {
		buf := make([]byte, 32)
		_, _ = c.Read(buf)
		_, _ = io.WriteString(c, "VERSION 1.6.9\r\n")
	})
	p := &prober{d: &plainDialer{}, host: "127.0.0.1", port: mc, timeout: 2 * time.Second}
	info := p.memcached(context.Background())
	if info.service != "memcached" || info.version != "1.6.9" {
		t.Fatalf("%+v", info)
	}
	res, _ := buildServicesResult(svcAsset(mc), info)
	if hasKey(res, "unauth/memcached") == nil {
		t.Fatal("missing memcached finding")
	}

	var gotReq []byte
	mg := listen(t, func(c net.Conn) {
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		gotReq = buf[:n]
		reply := make([]byte, 16)
		reply[0] = 40
		_, _ = io.WriteString(c, string(reply)+"\x08ismaster\x00")
	})
	p = &prober{d: &plainDialer{}, host: "127.0.0.1", port: mg, timeout: 2 * time.Second}
	info = p.mongo(context.Background())
	if info.service != "mongodb" {
		t.Fatalf("%+v", info)
	}
	if len(gotReq) != 16+4+11+8+19 || gotReq[12] != 0xd4 { // opcode 2004 = 0x7d4
		t.Errorf("handshake malformed: len=%d", len(gotReq))
	}
	res, _ = buildServicesResult(svcAsset(mg), info)
	if f := hasKey(res, "exposed/mongodb"); f == nil || f.Severity != model.SeverityMedium {
		t.Fatalf("%v", res.Findings)
	}
}

func TestServicesHTTPAndElasticsearch(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.2.15 (CentOS)")
		_, _ = io.WriteString(w, "hi")
	}))
	defer web.Close()
	res := runSvc(t, portOf(web.Listener))
	if d := res.Observations[0].Data; d["service"] != "http" || d["server"] != "Apache/2.2.15 (CentOS)" {
		t.Fatalf("%v", d)
	}
	if hasKey(res, "banner/apache-22") == nil {
		t.Fatalf("%v", findingKeys(res))
	}

	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"name":"n1","cluster_name":"prod","version":{"number":"7.10.2"},"tagline":"You Know, for Search"}`)
	}))
	defer es.Close()
	res = runSvc(t, portOf(es.Listener))
	if d := res.Observations[0].Data; d["service"] != "elasticsearch" || d["version"] != "7.10.2" {
		t.Fatalf("%v", d)
	}
	if f := hasKey(res, "unauth/elasticsearch"); f == nil {
		t.Fatalf("%v", findingKeys(res))
	}
}

func portOf(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }

func TestServicesTLSDetectionUpdatesAsset(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
	}))
	defer srv.Close()
	res := runSvc(t, portOf(srv.Listener))
	d := res.Observations[0].Data
	if d["tls"] != true || d["service"] != "https" {
		t.Fatalf("%v", d)
	}
	if len(res.Discovered) != 1 || res.Discovered[0].Attrs["tls"] != true || res.Discovered[0].Attrs["port"] == nil {
		t.Fatalf("%+v", res.Discovered)
	}
	_ = tls.VersionTLS12
}

func TestServicesUnidentifiedAndBadKey(t *testing.T) {
	port := listen(t, func(c net.Conn) { time.Sleep(50 * time.Millisecond) })
	res := runSvc(t, port)
	if res.Observations[0].Data["identified"] != false || len(res.Findings) != 0 {
		t.Fatalf("%+v", res)
	}
	_, err := (&servicesCheck{}).Run(context.Background(), check.Target{Asset: model.Asset{Kind: model.KindService, Key: "nonsense"}, Dialer: &plainDialer{}})
	if err == nil {
		t.Fatal("expected key error")
	}
}

func TestVersionRulesCompile(t *testing.T) {
	rs, err := loadRules()
	if err != nil || len(rs) < 5 {
		t.Fatalf("%v %d", err, len(rs))
	}
}

func TestChecksConstructor(t *testing.T) {
	cs := Checks(map[string]map[string]any{"net.ports": {"ports": "22"}})
	if len(cs) != 2 || cs[0].Name() != "net.ports" || cs[1].Name() != "net.services" {
		t.Fatal("unexpected checks")
	}
}
