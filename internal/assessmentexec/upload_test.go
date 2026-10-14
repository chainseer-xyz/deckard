package assessmentexec

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

func uploadFixture(t *testing.T) UploadOptions {
	t.Helper()
	dir := t.TempDir()
	o := UploadOptions{ReportFile: filepath.Join(dir, "report.json"), DoneFile: filepath.Join(dir, "done"), TokenFile: filepath.Join(dir, "token"), URL: "http://10.20.30.40:9092/v1/report", Session: "session-1", Tool: assessmentjob.ToolZGrab2, Timeout: time.Second}
	for path, content := range map[string]string{o.ReportFile: `{"native":"report"}`, o.DoneFile: `{"status":"succeeded"}`, o.TokenFile: strings.Repeat("u", 43)} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

func fixtureClient(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := newUploadClient()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	client.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)
	return client
}

func TestUploadPostsNativeReportWithOnlyItsSessionCredential(t *testing.T) {
	o := uploadFixture(t)
	var calls atomic.Int64
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || r.URL.Path != "/v1/report" || r.Host != "10.20.30.40:9092" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("u", 43) || r.Header.Get("X-Deckard-Session") != "session-1" || r.Header.Get("X-Deckard-Tool") != "zgrab2" || string(body) != `{"native":"report"}` {
			t.Errorf("report grant or payload mismatch")
		}
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(map[string]string{"session_id": "session-1", "status": "report_received"})
	})
	if err := upload(context.Background(), o, client); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("requests=%d", calls.Load())
	}
}

func TestUploadNeverRedirectsTheOpaqueCredential(t *testing.T) {
	o := uploadFixture(t)
	var calls atomic.Int64
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "http://10.20.30.41:9092/v1/report")
		w.WriteHeader(307)
	})
	if err := upload(context.Background(), o, client); err == nil {
		t.Fatal("redirect accepted")
	}
	if calls.Load() != 1 {
		t.Fatalf("credential followed redirect: %d", calls.Load())
	}
}

func TestUploadRequiresLiteralBrokerAndExactReceipt(t *testing.T) {
	for _, endpoint := range []string{"http://broker:9092/v1/report", "http://127.0.0.1:9092/v1/report", "http://169.254.169.254:9092/v1/report", "http://10.20.30.40:9092/other", "http://u:p@10.20.30.40:9092/v1/report", "http://10.20.30.40:9092/v1/report?q=secret", "https://10.20.30.40:9092/v1/report"} {
		t.Run(endpoint, func(t *testing.T) {
			o := uploadFixture(t)
			o.URL = endpoint
			var calls atomic.Int64
			client := fixtureClient(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
			if err := upload(context.Background(), o, client); err == nil || calls.Load() != 0 {
				t.Fatal("invalid broker reached network")
			}
		})
	}
	for _, receipt := range []string{`{"session_id":"wrong","status":"report_received"}`, `{"session_id":"session-1","status":"wrong"}`, `{}`, `{"session_id":"session-1","status":"report_received"} {}`} {
		t.Run(receipt, func(t *testing.T) {
			o := uploadFixture(t)
			client := fixtureClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(202); _, _ = io.WriteString(w, receipt) })
			if err := upload(context.Background(), o, client); err == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
}

func TestUploadWaitsForDoneButMissingFailedReportReturnsImmediately(t *testing.T) {
	o := uploadFixture(t)
	if err := os.Remove(o.ReportFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.DoneFile, []byte(`{"status":"failed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := upload(context.Background(), o, newUploadClient()); err == nil {
		t.Fatal("missing failed report accepted")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("failed producer did not wake uploader")
	}
	if err := os.Remove(o.DoneFile); err != nil {
		t.Fatal(err)
	}
	o.Timeout = 30 * time.Millisecond
	start = time.Now()
	if err := upload(context.Background(), o, newUploadClient()); err == nil {
		t.Fatal("missing done accepted")
	}
	if time.Since(start) < 20*time.Millisecond {
		t.Fatal("uploader did not wait for its producer")
	}
}

func TestUploadObservesReportOnlyAfterFreshCompletionPublication(t *testing.T) {
	o := uploadFixture(t)
	if err := os.Remove(o.DoneFile); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	client := fixtureClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(202)
		_, _ = io.WriteString(w, `{"session_id":"session-1","status":"report_received"}`)
	})
	result := make(chan error, 1)
	go func() { result <- upload(context.Background(), o, client) }()
	if calls.Load() != 0 {
		t.Fatal("native report uploaded before completion")
	}
	if err := publishDone(o.DoneFile, "succeeded"); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil || calls.Load() != 1 {
		t.Fatal("fresh completed report was not accepted")
	}
}

func TestUploadStrixBoundAndUnsafeFilesFailBeforeNetwork(t *testing.T) {
	for _, kind := range []string{"oversize", "symlink", "invalid-token", "invalid-done"} {
		t.Run(kind, func(t *testing.T) {
			o := uploadFixture(t)
			o.Tool = assessmentjob.ToolStrix
			switch kind {
			case "oversize":
				if err := os.WriteFile(o.ReportFile, []byte(strings.Repeat("x", (4<<20)+1)), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				path := o.ReportFile
				o.ReportFile = path + "-link"
				if err := os.Symlink(path, o.ReportFile); err != nil {
					t.Fatal(err)
				}
			case "invalid-token":
				if err := os.WriteFile(o.TokenFile, []byte("token\nsecret"), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid-done":
				if err := os.WriteFile(o.DoneFile, []byte(`{"status":"succeeded","extra":"secret"}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var calls atomic.Int64
			client := fixtureClient(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
			if err := upload(context.Background(), o, client); err == nil || calls.Load() != 0 {
				t.Fatal("unsafe upload accepted")
			}
		})
	}
}

func TestUploadClientCannotInheritProxy(t *testing.T) {
	client := newUploadClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || client.CheckRedirect == nil {
		t.Fatal("upload transport can inherit ambient proxy or redirects")
	}
}
