package assessmentexec

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

func executionFixture(t *testing.T) (ExecuteOptions, assessmentjob.ExecutionRequest) {
	t.Helper()
	dir := t.TempDir()
	o := ExecuteOptions{Tool: assessmentjob.ToolZGrab2, RequestFile: filepath.Join(dir, "request.json"), ReportFile: filepath.Join(dir, "report.json"), DoneFile: filepath.Join(dir, "done")}
	r := assessmentjob.ExecutionRequest{SchemaVersion: 1, SessionID: "session-1", Tool: o.Tool, Targets: []string{"https://app.example.com:8443"}, MaxTurns: 30, TimeoutSeconds: 30, MaxRequests: 50, MaxOutputBytes: 32 << 20, FixedTargets: []assessmentjob.Target{{AssetID: 1, Origin: "https://app.example.com:8443", Port: 8443, Addresses: []netip.Addr{netip.MustParseAddr("10.20.30.40")}}}}
	writeRequest(t, o.RequestFile, r)
	return o, r
}

func writeRequest(t *testing.T, path string, request assessmentjob.ExecutionRequest) {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func noEnvironment(string) string { return "" }

func TestZGrabUsesLiteralCSVWithBoundHostSNISingleRequestAndNoAmbientAuthority(t *testing.T) {
	o, _ := executionFixture(t)
	calls := 0
	err := execute(context.Background(), o, func(cmd *exec.Cmd) error {
		calls++
		args := strings.Join(cmd.Args, " ")
		for _, flag := range []string{"--senders=1", "--connections-per-host=1", "--blocklist-file=", "--no-http2", "--max-redirects=0", "--use-https", "--method=GET", "--endpoint=/", "--port=8443"} {
			if !strings.Contains(args, flag) {
				t.Errorf("missing fixed flag %s", flag)
			}
		}
		if strings.Contains(args, "retry-https") || strings.Contains(args, "fail-http-to-https") || strings.Contains(args, "token") {
			t.Fatal("enabled retries or key args")
		}
		rows, err := csv.NewReader(cmd.Stdin).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || len(rows[0]) != 4 || rows[0][0] != "10.20.30.40" || rows[0][1] != "app.example.com" || rows[0][3] != "8443" {
			t.Fatalf("fixed CSV=%v", rows)
		}
		for _, value := range cmd.Env {
			if strings.HasPrefix(value, "AWS_") || strings.HasPrefix(value, "HTTP_PROXY=") || strings.HasPrefix(value, "DECKARD_ADMIN_TOKEN=") {
				t.Fatal("ambient authority inherited")
			}
		}
		_, err = io.WriteString(cmd.Stdout, `{"ip":"10.20.30.40","domain":"app.example.com","port":8443,"data":{"http":{"status":"success"}}}`+"\n")
		return err
	}, func(name string) string { return "SECRET_" + name })
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
	raw, err := os.ReadFile(o.ReportFile)
	if err != nil || !strings.Contains(string(raw), "10.20.30.40") {
		t.Fatal("native report missing")
	}
	done, err := os.ReadFile(o.DoneFile)
	if err != nil || string(done) != `{"status":"succeeded"}` {
		t.Fatalf("success marker=%s err=%v", done, err)
	}
}

func TestFailedScannerWakesUploaderAndPreservesOnlyBoundedPartialNativeReport(t *testing.T) {
	o, _ := executionFixture(t)
	err := execute(context.Background(), o, func(cmd *exec.Cmd) error {
		_, _ = io.WriteString(cmd.Stdout, `{"partial":true}`)
		return errors.New("SECRET_native_failure")
	}, noEnvironment)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("native failure accepted or leaked")
	}
	done, readErr := os.ReadFile(o.DoneFile)
	if readErr != nil || string(done) != `{"status":"failed"}` {
		t.Fatal("failed scanner did not wake uploader")
	}
	raw, readErr := os.ReadFile(o.ReportFile)
	if readErr != nil || string(raw) != `{"partial":true}` {
		t.Fatal("valid bounded partial report lost")
	}
}

func TestExecutionRejectsInvalidRequestsBeforeNativeProcess(t *testing.T) {
	for _, kind := range []string{"unknown-field", "duplicate-field", "too-large", "bad-tool", "timeout", "request-budget", "output-budget", "fixed-origin", "fixed-port", "loopback", "missing-fixed", "path-origin", "duplicate-origin"} {
		t.Run(kind, func(t *testing.T) {
			o, r := executionFixture(t)
			switch kind {
			case "bad-tool":
				r.Tool = assessmentjob.ToolStrix
			case "timeout":
				r.TimeoutSeconds = 901
			case "request-budget":
				r.MaxRequests = 0
			case "output-budget":
				r.MaxOutputBytes = 33 << 20
			case "fixed-origin":
				r.FixedTargets[0].Origin = "https://other.example.com:8443"
			case "fixed-port":
				r.FixedTargets[0].Port = 443
			case "loopback":
				r.FixedTargets[0].Addresses = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
			case "missing-fixed":
				r.FixedTargets = nil
			case "path-origin":
				r.Targets[0] += "/admin"
			case "duplicate-origin":
				r.Targets = append(r.Targets, r.Targets[0])
			}
			writeRequest(t, o.RequestFile, r)
			if kind == "unknown-field" || kind == "duplicate-field" {
				raw, _ := os.ReadFile(o.RequestFile)
				extra := `,"command":"SECRET"}`
				if kind == "duplicate-field" {
					extra = `,"max_requests":1}`
				}
				if err := os.WriteFile(o.RequestFile, append(raw[:len(raw)-1], []byte(extra)...), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "too-large" {
				if err := os.WriteFile(o.RequestFile, []byte(strings.Repeat("x", 65537)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			err := execute(context.Background(), o, func(*exec.Cmd) error { calls++; return nil }, noEnvironment)
			if err == nil || calls != 0 || strings.Contains(err.Error(), "SECRET") {
				t.Fatal("invalid request reached process or leaked input")
			}
		})
	}
}

func TestExecutionRefusesStaleReportOrDoneWithoutOverwriting(t *testing.T) {
	for _, which := range []string{"report", "done"} {
		t.Run(which, func(t *testing.T) {
			o, _ := executionFixture(t)
			path := o.ReportFile
			if which == "done" {
				path = o.DoneFile
			}
			if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			if err := execute(context.Background(), o, func(*exec.Cmd) error { calls++; return nil }, noEnvironment); err == nil || calls != 0 {
				t.Fatal("stale output accepted")
			}
			raw, _ := os.ReadFile(path)
			if string(raw) != "old" {
				t.Fatal("stale output overwritten")
			}
		})
	}
}

func TestZGrabCountsEveryFixedAddressAgainstSessionBudget(t *testing.T) {
	o, r := executionFixture(t)
	r.MaxRequests = 1
	r.FixedTargets[0].Addresses = append(r.FixedTargets[0].Addresses, netip.MustParseAddr("10.20.30.41"))
	writeRequest(t, o.RequestFile, r)
	calls := 0
	if err := execute(context.Background(), o, func(*exec.Cmd) error { calls++; return nil }, noEnvironment); err == nil || calls != 0 {
		t.Fatal("fixed addresses exceeded request budget")
	}
}

func TestExecutionBoundsNativeOutputAndStillPublishesFailure(t *testing.T) {
	o, r := executionFixture(t)
	r.MaxOutputBytes = 128
	writeRequest(t, o.RequestFile, r)
	err := execute(context.Background(), o, func(cmd *exec.Cmd) error { _, err := io.WriteString(cmd.Stdout, strings.Repeat("x", 129)); return err }, noEnvironment)
	if err == nil {
		t.Fatal("oversized native output accepted")
	}
	done, _ := os.ReadFile(o.DoneFile)
	if string(done) != `{"status":"failed"}` {
		t.Fatal("overflow did not wake uploader")
	}
}

func TestInvalidManagerRequestWakesUploaderWithoutStartingScanner(t *testing.T) {
	o, r := executionFixture(t)
	r.MaxRequests = 0
	writeRequest(t, o.RequestFile, r)
	calls := 0
	if err := execute(context.Background(), o, func(*exec.Cmd) error { calls++; return nil }, noEnvironment); err == nil || calls != 0 {
		t.Fatal("invalid manager grant reached scanner")
	}
	done, err := os.ReadFile(o.DoneFile)
	if err != nil || string(done) != `{"status":"failed"}` {
		t.Fatal("invalid manager request left uploader waiting")
	}
}
