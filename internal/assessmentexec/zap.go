package assessmentexec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

type zapSettings struct {
	proxyURL, token string
	ca              []byte
	auth            []zapAuthOrigin
}
type zapAuthOrigin struct {
	Origin           string `json:"origin"`
	VerificationPath string `json:"verification_path"`
	Header           string `json:"header"`
	Value            string `json:"value"`
	ExpectedStatus   int    `json:"expected_status"`
}
type zapAuthFile struct {
	SchemaVersion int             `json:"schema_version"`
	Origins       []zapAuthOrigin `json:"origins"`
}

func newProxyClient(cfg zapSettings) (*http.Client, error) {
	if brokerEndpoint(cfg.proxyURL, "") != nil {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.ca) {
		return nil, ErrInvalid
	}
	proxyURL, _ := url.Parse(cfg.proxyURL)
	proxyURL.User = url.UserPassword("deckard", cfg.token)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{}, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func runZAPPrepared(ctx context.Context, r assessmentjob.ExecutionRequest, work string, run func(*exec.Cmd) error, cfg zapSettings, client *http.Client) ([]byte, error) {
	if err := zapPreflight(ctx, r.Targets, cfg, client); err != nil {
		return nil, ErrInvalid
	}
	plan, err := zapPlan(r, work, cfg)
	if err != nil {
		return nil, ErrInvalid
	}
	path := filepath.Join(work, "automation.yaml")
	if err := os.WriteFile(path, plan, 0600); err != nil {
		return nil, ErrInvalid
	}
	cmd := nativeCommand(ctx, work, "/zap/zap.sh", "-cmd", "-silent", "-notel", "-autorun", path, "-dir", filepath.Join(work, "zap"), "-host", "127.0.0.1")
	cmd.Env = append(cmd.Env, "JAVA_TOOL_OPTIONS=-Duser.home="+work+" -Djava.util.prefs.userRoot="+filepath.Join(work, "prefs"))
	runErr := run(cmd)
	raw, err := readRegular(filepath.Join(work, "native.json"), r.MaxOutputBytes, false)
	if err != nil {
		return nil, ErrInvalid
	}
	return raw, runErr
}

func zapPreflight(ctx context.Context, targets []string, cfg zapSettings, client *http.Client) error {
	byOrigin := map[string]zapAuthOrigin{}
	for _, grant := range cfg.auth {
		byOrigin[grant.Origin] = grant
	}
	for _, target := range targets {
		grant, authenticated := byOrigin[target]
		endpoint := target + "/"
		if authenticated {
			endpoint = target + grant.VerificationPath
		}
		status, err := proxyPreflightRequest(ctx, client, endpoint, "", "")
		if err != nil {
			return ErrInvalid
		}
		if !authenticated {
			continue
		}
		if status != 401 && status != 403 {
			return ErrInvalid
		}
		status, err = proxyPreflightRequest(ctx, client, endpoint, grant.Header, grant.Value)
		if err != nil || status != grant.ExpectedStatus {
			return ErrInvalid
		}
	}
	return nil
}

func proxyPreflightRequest(ctx context.Context, client *http.Client, endpoint, header, value string) (int, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, ErrInvalid
	}
	r.Close = true
	if header != "" {
		r.Header.Set(header, value)
	}
	response, err := client.Do(r)
	if err != nil {
		return 0, ErrInvalid
	}
	defer func() { _ = response.Body.Close() }()
	n, err := io.Copy(io.Discard, io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || n > 64<<10 || response.StatusCode < 100 || response.StatusCode > 599 {
		return 0, ErrInvalid
	}
	return response.StatusCode, nil
}

func runZAP(ctx context.Context, r assessmentjob.ExecutionRequest, work string, run func(*exec.Cmd) error, getenv func(string) string) ([]byte, error) {
	cfg := zapSettings{proxyURL: getenv("DECKARD_PROXY_URL")}
	token, err := readToken(getenv("DECKARD_PROXY_TOKEN_FILE"))
	if err != nil {
		return nil, ErrInvalid
	}
	cfg.token = string(token)
	cfg.ca, err = readRegular(getenv("DECKARD_PROXY_CA_FILE"), 64<<10, true)
	if err != nil {
		return nil, ErrInvalid
	}
	if path := getenv("DECKARD_ZAP_AUTH_FILE"); path != "" {
		cfg.auth, err = loadZAPAuth(path, r.Targets)
		if err != nil {
			return nil, ErrInvalid
		}
	}
	client, err := newProxyClient(cfg)
	if err != nil {
		return nil, ErrInvalid
	}
	defer client.CloseIdleConnections()
	return runZAPPrepared(ctx, r, work, run, cfg, client)
}
