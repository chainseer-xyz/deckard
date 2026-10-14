//go:build live

package assessmentexec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessment"
	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
	"github.com/chainseer-xyz/deckard/internal/assessmentresult"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

const nativeFixtureHost = "app.deckard.test"

// This suite proves binary/wrapper interoperability against task-owned local
// targets. A Docker internal network is NOT a Kubernetes CNI containment proof.
func TestNativeAssessmentInteroperability(t *testing.T) {
	if os.Getenv("DECKARD_ASSESSMENT_NATIVE_INTEGRATION") != "1" {
		t.Skip("set DECKARD_ASSESSMENT_NATIVE_INTEGRATION=1 with locally built pinned scanner images")
	}
	if tool := os.Getenv("DECKARD_ASSESSMENT_NATIVE_CONTAINER"); tool != "" {
		runNativeContainerCases(t, assessmentjob.Tool(tool))
		return
	}
	runNativeDockerCases(t)
}

func runNativeDockerCases(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	images := map[assessmentjob.Tool]string{}
	architecture := ""
	tools := nativeSelectedTools(t)
	for _, tool := range tools {
		tag := "deckard:" + string(tool) + "-candidate"
		if tool == assessmentjob.ToolZGrab2 {
			tag = "deckard:zgrab-candidate"
		}
		if value := os.Getenv("DECKARD_ASSESSMENT_" + strings.ToUpper(string(tool)) + "_IMAGE"); value != "" {
			tag = value
		}
		fields := strings.Fields(nativeDocker(t, ctx, "image", "inspect", tag, "--format", "{{.Id}} {{.Architecture}}"))
		if len(fields) != 2 || (fields[1] != "arm64" && fields[1] != "amd64") || (architecture != "" && architecture != fields[1]) {
			t.Fatal("native scanner images unavailable or architecture mismatch")
		}
		architecture, images[tool] = fields[1], fields[0]
	}
	binary := buildNativeTestBinary(t, ctx, architecture)
	network := nativeResourceName(t)
	nativeDocker(t, ctx, "network", "create", "--internal", "--driver", "bridge", network)
	t.Cleanup(func() { cleanupNativeDocker(t, "network", "rm", network) })
	for _, tool := range tools {
		t.Run(string(tool), func(t *testing.T) { nativeDockerRunner(t, ctx, network, binary, images[tool], tool) })
	}
}

func nativeSelectedTools(t *testing.T) []assessmentjob.Tool {
	t.Helper()
	if value := os.Getenv("DECKARD_ASSESSMENT_NATIVE_TOOL"); value != "" {
		tool := assessmentjob.Tool(value)
		if !validTool(tool) {
			t.Fatal("unsupported native fixture tool")
		}
		return []assessmentjob.Tool{tool}
	}
	return []assessmentjob.Tool{assessmentjob.ToolZGrab2, assessmentjob.ToolZAP, assessmentjob.ToolStrix}
}

func TestNativeBinaryTempBase(t *testing.T) {
	for _, tc := range []struct {
		name, goos, cache, configured, want string
	}{
		{"macos ignores unshared system temp", "darwin", "/Users/fixture/Library/Caches", "", "/Users/fixture/Library/Caches"},
		{"macos explicit shared directory", "darwin", "/Users/fixture/Library/Caches", "/Users/fixture/native-fixtures", "/Users/fixture/native-fixtures"},
		{"linux retains testing temp directory", "linux", "/home/fixture/.cache", "", ""},
		{"linux ignores macos override", "linux", "/home/fixture/.cache", "/Users/fixture/native-fixtures", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeBinaryTempBase(tc.goos, tc.cache, tc.configured); got != tc.want {
				t.Fatalf("native binary temp base = %q, want %q", got, tc.want)
			}
		})
	}
}

func nativeBinaryTempBase(goos, cache, configured string) string {
	if goos != "darwin" {
		return ""
	}
	if configured != "" {
		return configured
	}
	return cache
}

// Colima shares /Users but not macOS's default /var/folders temporary paths.
// DECKARD_ASSESSMENT_NATIVE_TMPDIR can select another already-shared macOS path.
// Linux retains testing.T.TempDir, including the Ubuntu CI runner's defaults.
func nativeBinaryTempDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "darwin" {
		return t.TempDir()
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal("cannot find a Colima-shared native fixture directory")
	}
	base := nativeBinaryTempBase(runtime.GOOS, cache, os.Getenv("DECKARD_ASSESSMENT_NATIVE_TMPDIR"))
	directory, err := os.MkdirTemp(base, "deckard-native-")
	if err != nil {
		t.Fatalf("create native fixture directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove task-owned native fixture directory: %v", err)
		}
	})
	return directory
}

func buildNativeTestBinary(t *testing.T, ctx context.Context, architecture string) string {
	t.Helper()
	directory := nativeBinaryTempDir(t)
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "assessmentexec.test")
	command := exec.CommandContext(ctx, "go", "test", "-c", "-tags", "live", "-o", binary, ".")
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+architecture, "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile native test fixture: %v\n%s", err, output)
	}
	return binary
}

func nativeDockerRunner(t *testing.T, ctx context.Context, network, binary, image string, tool assessmentjob.Tool) {
	t.Helper()
	name := nativeResourceName(t)
	t.Cleanup(func() { cleanupNativeDocker(t, "rm", "-f", name) })
	args := []string{"run", "--rm", "--name", name, "--network", network, "--dns", "127.0.0.1", "--user", "65532:65532", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "2g", "--pids-limit", "256", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777", "--mount", "type=bind,src=" + filepath.Dir(binary) + ",dst=/fixture,readonly", "--env", "DECKARD_ASSESSMENT_NATIVE_INTEGRATION=1", "--env", "DECKARD_ASSESSMENT_NATIVE_CONTAINER=" + string(tool), "--entrypoint", "/fixture/assessmentexec.test", image, "-test.run=^TestNativeAssessmentInteroperability$", "-test.v", "-test.timeout=6m"}
	output := nativeDocker(t, ctx, args...)
	if strings.Contains(output, "--- SKIP") {
		t.Fatal("native fixture skipped; missing integration coverage")
	}
	if strings.Contains(output, "partial transport") {
		t.Log("native HTTPS report accepted as additive; conservative partial transport remains visible")
	}
	t.Logf("image=%s; native binary/wrapper fixtures passed", image)
}

func nativeDocker(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("task-owned Docker fixture failed: %v\n%s", err, output)
	}
	return string(output)
}

func cleanupNativeDocker(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil && !strings.Contains(string(output), "No such container") {
		t.Errorf("task-owned Docker fixture cleanup failed: %v", err)
	}
}

func nativeResourceName(t *testing.T) string {
	t.Helper()
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	return "deckard-native-" + hex.EncodeToString(suffix[:])
}

func runNativeContainerCases(t *testing.T, tool assessmentjob.Tool) {
	t.Helper()
	ip := nativeContainerIP(t)
	switch tool {
	case assessmentjob.ToolZGrab2:
		for _, status := range []int{200, 302} {
			t.Run(strconv.Itoa(status), func(t *testing.T) { nativeZGrabCase(t, ip, status) })
		}
	case assessmentjob.ToolZAP:
		for _, scenario := range []string{"authenticated", "foreign-origin", "bad-auth", "body-budget"} {
			t.Run(scenario, func(t *testing.T) { nativeZAPCase(t, ip, scenario) })
		}
	case assessmentjob.ToolStrix:
		nativeStrixCase(t, ip)
	default:
		t.Fatal("unknown native fixture tool")
	}
}

func nativeContainerIP(t *testing.T) netip.Addr {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range interfaces {
		if network.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := network.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range addresses {
			prefix, err := netip.ParsePrefix(raw.String())
			if err == nil && prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() {
				return prefix.Addr()
			}
		}
	}
	t.Fatal("isolated native fixture has no private unicast interface")
	return netip.Addr{}
}

func nativeServer(t *testing.T, ip netip.Addr, handler http.Handler, certificate *tls.Certificate) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	scheme := "http"
	if certificate != nil {
		listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{*certificate}, MinVersion: tls.VersionTLS12})
		scheme = "https"
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); <-done })
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	return scheme + "://" + net.JoinHostPort(nativeFixtureHost, port)
}

type nativeResolver struct{ ip netip.Addr }

func (r nativeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if host != nativeFixtureHost {
		return nil, fmt.Errorf("outside native fixture")
	}
	return []string{r.ip.String()}, nil
}
func (nativeResolver) LookupCNAME(context.Context, string) (string, error) { return "", nil }
func (nativeResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (nativeResolver) LookupNS(context.Context, string) ([]string, error)  { return nil, nil }

func nativeGuard(t *testing.T, ip netip.Addr) *scope.Guard {
	t.Helper()
	guard, err := scope.NewGuard(config.ScopeConfig{Include: []string{nativeFixtureHost, ip.String() + "/32"}}, scope.WithResolver(nativeResolver{ip}))
	if err != nil || !guard.VerifyOwnedTarget(context.Background(), nativeFixtureHost) {
		t.Fatal("task-owned native fixture did not pass ownership guard")
	}
	return guard
}

func nativeExecution(t *testing.T, tool assessmentjob.Tool, origin string, maxRequests int) (ExecuteOptions, assessmentjob.ExecutionRequest, assessmentjob.Target) {
	t.Helper()
	portText := origin[strings.LastIndex(origin, ":")+1:]
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	o := ExecuteOptions{Tool: tool, RequestFile: filepath.Join(directory, "request.json"), ReportFile: filepath.Join(directory, "report.json"), DoneFile: filepath.Join(directory, "done")}
	r := assessmentjob.ExecutionRequest{SchemaVersion: 1, SessionID: "native-fixture", Tool: tool, Targets: []string{origin}, MaxTurns: 30, TimeoutSeconds: 150, MaxRequests: maxRequests, MaxOutputBytes: 32 << 20}
	return o, r, assessmentjob.Target{AssetID: 1, Origin: origin, Port: uint16(port)}
}

func nativeZGrabCase(t *testing.T, ip netip.Addr, status int) {
	var targetRequests, foreignRequests atomic.Int64
	foreign := nativeServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { foreignRequests.Add(1); w.WriteHeader(200) }), nil)
	origin := nativeServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		if !strings.HasPrefix(r.Host, nativeFixtureHost+":") {
			t.Error("native Host differs from fixed domain")
		}
		if status == 302 {
			w.Header().Set("Location", foreign)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, "native fixture")
	}), nil)
	_ = nativeGuard(t, ip)
	o, r, target := nativeExecution(t, assessmentjob.ToolZGrab2, origin, 1)
	target.Addresses = []netip.Addr{ip}
	r.FixedTargets = []assessmentjob.Target{target}
	writeRequest(t, o.RequestFile, r)
	if err := Execute(context.Background(), o); err != nil {
		t.Fatalf("native ZGrab wrapper failed: %v", err)
	}
	raw, err := os.ReadFile(o.ReportFile)
	if err != nil {
		t.Fatal(err)
	}
	result, err := assessmentresult.Parse(assessmentjob.Completion{Session: assessmentjob.Session{ID: r.SessionID, Tool: r.Tool}, Targets: []assessmentjob.Target{target}, Data: raw, Complete: true})
	if err != nil || !result.Complete || len(result.Observations[1]) != 1 {
		t.Fatalf("native ZGrab report did not bind completely: %v", err)
	}
	values, ok := result.Observations[1][0].Data["endpoints"].([]map[string]any)
	if !ok || len(values) != 1 || values[0]["http_status"] != status {
		t.Fatal("native ZGrab status differs from fixture")
	}
	if targetRequests.Load() != 1 || foreignRequests.Load() != 0 {
		t.Fatalf("native request/redirect counts: target=%d foreign=%d", targetRequests.Load(), foreignRequests.Load())
	}
}

func nativeTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{nativeFixtureHost}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func nativeZAPCase(t *testing.T, ip netip.Addr, scenario string) {
	var authenticatedRoot, anonymousVerification, authenticatedVerification atomic.Int64
	certificate, roots := nativeTLSCertificate(t)
	serverCertificate := &certificate
	if scenario == "foreign-origin" {
		serverCertificate = nil
	}
	origin := nativeServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated := r.Header.Get("Authorization") == "Bearer fixture-only"
		if r.URL.Path == "/private" && r.UserAgent() == "Go-http-client/1.1" {
			if authenticated {
				authenticatedVerification.Add(1)
			} else if r.Header.Get("Authorization") == "" {
				anonymousVerification.Add(1)
			}
		}
		if !authenticated {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path != "/" && r.URL.Path != "/private" {
			w.WriteHeader(404)
			return
		}
		if r.URL.Path == "/" {
			authenticatedRoot.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		if scenario == "body-budget" && r.URL.Path == "/" {
			_, _ = io.WriteString(w, strings.Repeat("x", 512<<10))
			return
		}
		_, _ = io.WriteString(w, "<!doctype html><html><body>native fixture</body></html>")
	}), serverCertificate)
	_, proxy, broker := nativeProxy(t, ip, origin, roots, scenario)
	o, r, target := nativeExecution(t, assessmentjob.ToolZAP, origin, 10000)
	writeRequest(t, o.RequestFile, r)
	nativeZAPEnvironment(t, o, origin, proxy, broker, scenario)
	err := Execute(context.Background(), o)
	finishCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	policyErr := proxy.Finish(finishCtx)
	if anonymousVerification.Load() != 1 {
		t.Fatal("native authentication had no unauthenticated control")
	}
	if scenario == "bad-auth" {
		if err == nil || authenticatedRoot.Load() != 0 || authenticatedVerification.Load() != 0 {
			t.Fatal("bad auth reached native scan or looked successful")
		}
		return
	}
	if authenticatedVerification.Load() != 1 || authenticatedRoot.Load() == 0 {
		t.Fatalf("native ZAP did not receive exact-origin auth after strict preflight: verification=%d root=%d wrapper=%v policy=%v", authenticatedVerification.Load(), authenticatedRoot.Load(), err, policyErr)
	}
	if scenario == "body-budget" {
		if policyErr == nil || !strings.Contains(policyErr.Error(), "response") || !strings.Contains(policyErr.Error(), "budget") {
			t.Fatal("native ZAP exceeded body budget without incomplete policy")
		}
		return
	}
	if err != nil {
		t.Fatalf("authenticated native ZAP failed: wrapper=%v policy=%v", err, policyErr)
	}
	if scenario == "foreign-origin" {
		if !errors.Is(policyErr, assessment.ErrDenied) || !strings.Contains(policyErr.Error(), "origin is not an explicit target") {
			t.Fatalf("native origin-upgrade attempt was not refused: %v", policyErr)
		}
		t.Log("partial transport: native origin-upgrade refused; valid HTTP report remains additive")
	}
	if scenario == "authenticated" && policyErr != nil {
		if !errors.Is(policyErr, assessment.ErrDenied) || !strings.Contains(policyErr.Error(), "HTTPS request did not parse or complete") {
			t.Fatalf("unexpected HTTPS native transport failure: %v", policyErr)
		}
		t.Log("partial transport: conservative HTTPS tunnel completeness; native report remains additive")
	}
	raw, readErr := os.ReadFile(o.ReportFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	result, parseErr := assessmentresult.Parse(assessmentjob.Completion{Session: assessmentjob.Session{ID: r.SessionID, Tool: r.Tool}, Targets: []assessmentjob.Target{target}, Data: raw, Complete: true})
	if parseErr != nil || result.Complete {
		t.Fatal("native ZAP report was invalid or falsely claimed complete coverage")
	}
}

func nativeStrixCase(t *testing.T, ip netip.Addr) {
	var requests atomic.Int64
	origin := nativeServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(200) }), nil)
	o, r, target := nativeExecution(t, assessmentjob.ToolStrix, origin, 50)
	r.MaxOutputBytes = 4 << 20
	writeRequest(t, o.RequestFile, r)
	if err := Execute(context.Background(), o); err == nil {
		t.Fatal("unconfigured Strix model appeared successful")
	}
	raw, err := os.ReadFile(o.ReportFile)
	if err != nil {
		t.Fatal("native Strix did not publish structured failure")
	}
	var report struct {
		Error     string `json:"error"`
		Completed bool   `json:"completed"`
	}
	if json.Unmarshal(raw, &report) != nil || report.Error != "model_unavailable" || report.Completed {
		t.Fatal("native Strix failed before its real adapter/model boundary")
	}
	done, err := os.ReadFile(o.DoneFile)
	if err != nil || string(done) != `{"status":"failed"}` {
		t.Fatal("native Strix did not wake uploader")
	}
	result, err := assessmentresult.Parse(assessmentjob.Completion{Session: assessmentjob.Session{ID: r.SessionID, Tool: r.Tool}, Targets: []assessmentjob.Target{target}, Data: raw, Complete: false})
	if err != nil || result.Complete || requests.Load() != 0 {
		t.Fatal("native Strix failure claimed coverage or sent target requests")
	}
}

func nativeProxy(t *testing.T, ip netip.Addr, origin string, roots *x509.CertPool, scenario string) (*assessment.Policy, *assessment.Proxy, string) {
	t.Helper()
	responseLimit := int64(32 << 20)
	if scenario == "body-budget" {
		responseLimit = 128 << 10
	}
	policy, err := assessment.NewPolicy(context.Background(), nativeGuard(t, ip), []string{origin}, assessment.Limits{MaxRequests: 10000, MaxRequestBytes: 32 << 20, MaxResponseBytes: responseLimit, Timeout: 3 * time.Minute}, assessment.WithRootCAs(roots))
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := assessment.NewProxy(policy, strings.Repeat("p", 43))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	// Match Manager's real identity dispatch: an initial anonymous proxy
	// challenge must not poison any session's policy. Unknown requests exercise
	// the actual Manager handler; the fixture's known token enters real Proxy.
	unknown := new(assessmentjob.Manager)
	identity := "Basic " + base64.StdEncoding.EncodeToString([]byte("deckard:"+strings.Repeat("p", 43)))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") == identity {
			proxy.ServeHTTP(w, r)
		} else {
			unknown.ServeBroker(w, r)
		}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 3 * time.Minute, WriteTimeout: 3 * time.Minute, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = proxy.Finish(ctx)
		_ = server.Close()
		<-done
	})
	return policy, proxy, "http://" + listener.Addr().String()
}

func nativeZAPEnvironment(t *testing.T, o ExecuteOptions, origin string, proxy *assessment.Proxy, broker, scenario string) {
	t.Helper()
	directory := filepath.Dir(o.RequestFile)
	for name, value := range map[string]string{"DECKARD_PROXY_URL": broker, "DECKARD_PROXY_TOKEN_FILE": filepath.Join(directory, "proxy-token"), "DECKARD_PROXY_CA_FILE": filepath.Join(directory, "ca.pem"), "DECKARD_ZAP_AUTH_FILE": filepath.Join(directory, "auth.json")} {
		t.Setenv(name, value)
	}
	value := "Bearer fixture-only"
	if scenario == "bad-auth" {
		value = "Bearer wrong-fixture-token"
	}
	auth, _ := json.Marshal(zapAuthFile{SchemaVersion: 1, Origins: []zapAuthOrigin{{Origin: origin, VerificationPath: "/private", Header: "Authorization", Value: value, ExpectedStatus: 200}}})
	for name, raw := range map[string][]byte{"proxy-token": []byte(strings.Repeat("p", 43)), "ca.pem": proxy.CAPEM(), "auth.json": auth} {
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
