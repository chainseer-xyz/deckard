package assessmentexec

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/chainseer-xyz/deckard/internal/assessment"
	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

type fixtureResolver struct{}

func (fixtureResolver) LookupHost(context.Context, string) ([]string, error) {
	return []string{"10.20.30.50"}, nil
}
func (fixtureResolver) LookupCNAME(context.Context, string) (string, error) { return "", nil }
func (fixtureResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (fixtureResolver) LookupNS(context.Context, string) ([]string, error)  { return nil, nil }

type fixtureDialer struct{ address string }

func (d fixtureDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func zapFixture(t *testing.T, handler http.HandlerFunc) (zapSettings, *http.Client) {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	guard, err := scope.NewGuard(config.ScopeConfig{Include: []string{"app.example.com", "10.20.30.50/32"}}, scope.WithResolver(fixtureResolver{}), scope.WithDialer(fixtureDialer{upstream.Listener.Addr().String()}))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := assessment.NewPolicy(context.Background(), guard, []string{"http://app.example.com"}, assessment.Limits{MaxRequests: 20, MaxRequestBytes: 1 << 20, MaxResponseBytes: 1 << 20, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	proxy, err := assessment.NewProxy(policy, strings.Repeat("p", 43))
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(proxy)
	t.Cleanup(func() { _ = proxy.Finish(context.Background()); broker.Close() })
	cfg := zapSettings{proxyURL: "http://10.20.30.40:9092", token: strings.Repeat("p", 43), ca: proxy.CAPEM()}
	client, err := newProxyClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, broker.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	return cfg, client
}

func TestZAPVerifiesAuthenticationControlBeforeGeneratedScopedScan(t *testing.T) {
	var seen []string
	cfg, client := zapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path+"|"+r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") == "Bearer app-only" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	})
	cfg.auth = []zapAuthOrigin{{Origin: "http://app.example.com", VerificationPath: "/private", Header: "Authorization", Value: "Bearer app-only", ExpectedStatus: 200}}
	r := assessmentjob.ExecutionRequest{Tool: assessmentjob.ToolZAP, SessionID: "session-1", Targets: []string{"http://app.example.com"}, TimeoutSeconds: 30, MaxRequests: 50, MaxOutputBytes: 32 << 20}
	work := t.TempDir()
	calls := 0
	raw, err := runZAPPrepared(context.Background(), r, work, func(cmd *exec.Cmd) error {
		calls++
		if cmd.Path != "/zap/zap.sh" || !strings.Contains(strings.Join(cmd.Args, " "), "-cmd -silent -notel -autorun") {
			t.Fatal("not fixed ZAP automation command")
		}
		args := cmd.Args
		planPath := ""
		for i, arg := range args {
			if arg == "-autorun" {
				planPath = args[i+1]
			}
		}
		data, err := os.ReadFile(planPath)
		if err != nil {
			t.Fatal(err)
		}
		var plan map[string]any
		if yaml.Unmarshal(data, &plan) != nil {
			t.Fatal("invalid YAML")
		}
		if !strings.Contains(string(data), "httpProxy") || !strings.Contains(string(data), "traditional-json") || !strings.Contains(string(data), "threadPerHost: 1") || !strings.Contains(string(data), "postForm: false") {
			t.Fatal("missing bounded native plan")
		}
		if strings.Contains(strings.Join(cmd.Args, " "), "app-only") || strings.Contains(strings.Join(cmd.Args, " "), strings.Repeat("p", 43)) {
			t.Fatal("credential passed in argv")
		}
		return os.WriteFile(filepath.Join(work, "native.json"), []byte(`{"site":[]}`), 0600)
	}, cfg, client)
	if err != nil || !json.Valid(raw) || calls != 1 {
		t.Fatalf("ZAP launch=%d err=%v", calls, err)
	}
	if len(seen) != 2 || seen[0] != "/private|" || seen[1] != "/private|Bearer app-only" {
		t.Fatalf("auth controls=%v", seen)
	}
}

func TestZAPRejectsPublicAuthenticationControlBeforeNativeLaunch(t *testing.T) {
	cfg, client := zapFixture(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	cfg.auth = []zapAuthOrigin{{Origin: "http://app.example.com", VerificationPath: "/private", Header: "Authorization", Value: "Bearer app-only", ExpectedStatus: 200}}
	r := assessmentjob.ExecutionRequest{Targets: []string{"http://app.example.com"}}
	calls := 0
	if _, err := runZAPPrepared(context.Background(), r, t.TempDir(), func(*exec.Cmd) error { calls++; return nil }, cfg, client); err == nil || calls != 0 {
		t.Fatal("always-public endpoint falsely verified auth")
	}
}

func TestZAPAnonymousPreflightStillRequiresBrokerForEveryOrigin(t *testing.T) {
	requests := 0
	cfg, client := zapFixture(t, func(w http.ResponseWriter, _ *http.Request) { requests++; _, _ = io.WriteString(w, "ok") })
	if err := zapPreflight(context.Background(), []string{"http://app.example.com"}, cfg, client); err != nil || requests != 1 {
		t.Fatal("anonymous origin missed proxy preflight")
	}
	client.Transport.(*http.Transport).Proxy = nil
	if err := zapPreflight(context.Background(), []string{"https://app.example.com"}, cfg, client); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	strict, _ := newProxyClient(cfg)
	transport := strict.Transport.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.RootCAs == nil || transport.Proxy == nil || strict.CheckRedirect == nil || !transport.DisableKeepAlives {
		t.Fatal("preflight weakened TLS, proxy or redirect policy")
	}
}

func TestZAPHeaderRegexCannotEscapeExactGrantedOrigin(t *testing.T) {
	for _, origin := range []string{"https://app.example.com", "https://app.example.com:8443", "http://app.example.com"} {
		pattern, err := regexp.Compile(originPattern(origin))
		if err != nil {
			t.Fatal(err)
		}
		if !pattern.MatchString(origin + "/path?x=1") {
			t.Fatalf("origin missed %s", origin)
		}
		for _, other := range []string{origin + ".evil/path", origin + "@evil/path", "https://evil.example.com/path", origin + ":123/path"} {
			if pattern.MatchString(other) {
				t.Fatalf("credential escaped grant: %s", other)
			}
		}
	}
	pattern := regexp.MustCompile(originPattern("https://app.example.com"))
	if !pattern.MatchString("https://app.example.com:443/path") {
		t.Fatal("equivalent default-port origin missed")
	}
}

func TestZAPAuthFileRejectsUnscopedHeadersAndSecretBearingLocations(t *testing.T) {
	for _, field := range []string{"origin", "query", "authority", "header", "newline", "interpolation", "duplicate", "oversize"} {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "auth.json")
			entry := zapAuthOrigin{Origin: "https://app.example.com", VerificationPath: "/private", Header: "Authorization", Value: "Bearer app-only", ExpectedStatus: 200}
			switch field {
			case "origin":
				entry.Origin = "https://other.example.com"
			case "query":
				entry.VerificationPath = "/private?secret=x"
			case "authority":
				entry.VerificationPath = "//evil/path"
			case "header":
				entry.Header = "Proxy-Authorization"
			case "newline":
				entry.Value = "Bearer x\r\nsecret"
			case "interpolation":
				entry.Value = "${SECRET}"
			case "oversize":
				entry.Value = strings.Repeat("x", 4097)
			}
			entries := []zapAuthOrigin{entry}
			if field == "duplicate" {
				entries = append(entries, entry)
			}
			raw, _ := json.Marshal(zapAuthFile{SchemaVersion: 1, Origins: entries})
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadZAPAuth(path, []string{"https://app.example.com"}); err == nil {
				t.Fatal("unsafe auth file accepted")
			}
		})
	}
}

func TestZAPConfigReloadNormalizesNativeProxyPortToString(t *testing.T) {
	raw, err := zapPlan(assessmentjob.ExecutionRequest{Targets: []string{"https://app.example.com"}, TimeoutSeconds: 60}, t.TempDir(), zapSettings{proxyURL: "http://10.20.30.40:9092", token: strings.Repeat("p", 43)})
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := yaml.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	configs := plan["env"].(map[string]any)["configs"].(map[string]any)
	if configs["network.connection.httpProxy.port"] != "9092" {
		t.Fatal("native env.proxy stores an Integer that breaks generic config reload without explicit string normalization")
	}
}
