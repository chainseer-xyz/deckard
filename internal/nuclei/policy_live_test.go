//go:build live

package nuclei

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestLiveDestinationPolicy checks the actual Nuclei HTTP clients, including
// unsafe raw requests and pipelining. All destinations are local fixtures.
// A dial-time refusal must remain an error even when Nuclei itself exits zero.
func TestLiveDestinationPolicy(t *testing.T) {
	bin := os.Getenv("NUCLEI_BIN")
	if bin == "" {
		var err error
		bin, err = exec.LookPath("nuclei")
		if err != nil {
			t.Skip("needs the nuclei binary (PATH or NUCLEI_BIN)")
		}
	}
	for _, tc := range []struct {
		name string
		http string
	}{
		{"standard", "  - method: GET\n    path: [\"{{BaseURL}}/vuln\"]\n"},
		{"raw", policyLiveRawRequest("")},
		{"unsafe", policyLiveRawRequest("    unsafe: true\n")},
		{"pipeline", policyLiveRawRequest("    unsafe: true\n    pipeline: true\n    pipeline-concurrent-connections: 1\n    pipeline-requests-per-connection: 1\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int64
			fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				_, _ = w.Write([]byte("vulnerable-marker"))
			}))
			defer fixture.Close()
			u, err := url.Parse(fixture.URL)
			if err != nil {
				t.Fatal(err)
			}
			// Keep the hostname in the input list. Nuclei's CIDR exclusion
			// removes literal IP targets before the dialer can check them.
			// localhost resolves only to loopback via the hosts file.
			u.Host = net.JoinHostPort("localhost", u.Port())
			state := t.TempDir()
			template := filepath.Join(state, "policy-live.yaml")
			header, _, _ := strings.Cut(liveTemplate, "http:\n")
			body := header + "http:\n" + tc.http + "    matchers:\n      - type: word\n        words: [\"vulnerable-marker\"]\n"
			if err := os.WriteFile(template, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			env := func() ([]string, func(), error) {
				return []string{"HOME=" + state, "XDG_CONFIG_HOME=" + state + "/config", "XDG_CACHE_HOME=" + state + "/cache",
					"NUCLEI_CONFIG_DIR=" + state + "/config/nuclei", "NUCLEI_TEMPLATES_DIR=" + state}, func() {}, nil
			}
			args := []string{"-u", fixture.URL, "-t", template, "-jsonl", "-silent", "-no-color", "-duc", "-dr",
				"-no-interactsh", "-retries", "0", "-timeout", "2", "-pt", "http", "-no-stdin"}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			allowed := ExecRunner{Env: env, Policy: fixturePolicy}
			out, err := allowed.Run(ctx, bin, args)
			if err != nil {
				t.Fatalf("approved scan: %v", err)
			}
			if requests.Load() == 0 || !strings.Contains(string(out), "deckard-live-test") {
				t.Fatalf("approved scan did not reach fixture or match: requests=%d output=%q", requests.Load(), out)
			}
			requests.Store(0)
			denied := ExecRunner{Env: env, Policy: func(context.Context, []string) ([]string, error) {
				return []string{"127.0.0.0/8", "::1/128"}, nil
			}}
			args[1] = u.String()
			out, err = denied.Run(ctx, bin, args)
			if got := requests.Load(); got != 0 {
				t.Fatalf("denied fixture received %d requests", got)
			}
			if len(out) != 0 {
				t.Errorf("denied scan returned findings: %q", out)
			}
			if err == nil {
				t.Fatal("Nuclei denied every dial but Deckard reported a successful clean observation")
			}
		})
	}
}

func policyLiveRawRequest(options string) string {
	return fmt.Sprintf("  - raw:\n      - |+\n        GET /vuln HTTP/1.1\n        Host: {{Hostname}}\n\n%s", options)
}

// TestLiveDestinationPolicyIgnoresGlobalProxy proves that neither an inherited
// proxy environment nor a user's global Nuclei config can redirect scan traffic.
func TestLiveDestinationPolicyIgnoresGlobalProxy(t *testing.T) {
	bin := os.Getenv("NUCLEI_BIN")
	if bin == "" {
		var err error
		bin, err = exec.LookPath("nuclei")
		if err != nil {
			t.Skip("needs the nuclei binary (PATH or NUCLEI_BIN)")
		}
	}
	var requests, proxyRequests atomic.Int64
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("vulnerable-marker"))
	}))
	defer fixture.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyRequests.Add(1)
		_, _ = w.Write([]byte("vulnerable-marker"))
	}))
	defer proxy.Close()
	state := t.TempDir()
	for _, dir := range []string{filepath.Join(state, "config", "nuclei"), filepath.Join(state, "Library", "Application Support", "nuclei")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("proxy: ["+proxy.URL+"]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	template := filepath.Join(state, "policy-live.yaml")
	if err := os.WriteFile(template, []byte(liveTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	env := func() ([]string, func(), error) {
		return []string{"HOME=" + state, "XDG_CONFIG_HOME=" + state + "/config", "XDG_CACHE_HOME=" + state + "/cache",
			"NUCLEI_CONFIG_DIR=" + state + "/config/nuclei", "NUCLEI_TEMPLATES_DIR=" + state}, func() {}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := (ExecRunner{Env: env, Policy: fixturePolicy}).Run(ctx, bin, []string{
		"-u", fixture.URL, "-t", template, "-jsonl", "-silent", "-no-color", "-duc", "-dr", "-no-interactsh", "-pt", "http", "-no-stdin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() == 0 || !strings.Contains(string(out), "deckard-live-test") {
		t.Fatalf("approved fixture was not scanned: requests=%d output=%q", requests.Load(), out)
	}
	if got := proxyRequests.Load(); got != 0 {
		t.Fatalf("global proxy received %d requests", got)
	}
}
