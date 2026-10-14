package assessmentexec

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

func TestStrixRunsPinnedAdapterWithOnlyExplicitControllerAuthority(t *testing.T) {
	o, r := executionFixture(t)
	o.Tool = assessmentjob.ToolStrix
	r.Tool = o.Tool
	r.FixedTargets = nil
	r.MaxOutputBytes = 4 << 20
	writeRequest(t, o.RequestFile, r)
	tokenPath := filepath.Join(t.TempDir(), "runtime-token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("r", 43)), 0600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"DECKARD_RUNTIME_URL": "http://10.20.30.41:9093", "DECKARD_RUNTIME_TOKEN_FILE": tokenPath, "STRIX_LLM": "openai/approved-model", "LLM_API_BASE": "https://10.20.30.42:8443/v1", "LLM_API_KEY": "model-only-secret", "HTTPS_PROXY": "SECRET_proxy", "DECKARD_ADMIN_TOKEN": "SECRET_admin"}
	calls := 0
	err := execute(context.Background(), o, func(cmd *exec.Cmd) error {
		calls++
		if cmd.Path != "/opt/venv/bin/python" || len(cmd.Args) != 7 || cmd.Args[1] != "/opt/deckard/strix_adapter.py" || cmd.Args[2] != "run" {
			t.Fatal("not fixed Strix adapter")
		}
		if strings.Contains(strings.Join(cmd.Args, " "), "secret") {
			t.Fatal("model credential in argv")
		}
		joined := strings.Join(cmd.Env, "\n")
		for _, required := range []string{"PYTHONPATH=/opt/strix:/opt/deckard", "PYTHONDONTWRITEBYTECODE=1", "STRIX_TELEMETRY=false", "OPENAI_AGENTS_DISABLE_TRACING=1", "LITELLM_LOCAL_MODEL_COST_MAP=true"} {
			if !strings.Contains(joined, required) {
				t.Errorf("missing fixed Python runtime %s", required)
			}
		}
		if !strings.Contains(joined, "LLM_API_KEY=model-only-secret") || strings.Contains(joined, "SECRET_") || strings.Contains(joined, "HTTP_PROXY") {
			t.Fatal("wrong controller authority")
		}
		return os.WriteFile(cmd.Args[6], []byte(`{"schema_version":1,"tool":"strix","completed":true,"complete":false,"findings":[]}`), 0600)
	}, func(name string) string { return env[name] })
	if err != nil || calls != 1 {
		t.Fatalf("Strix launch=%d err=%v", calls, err)
	}
}

func TestStrixMissingModelStillPublishesStructuredFailure(t *testing.T) {
	o, r := executionFixture(t)
	o.Tool = assessmentjob.ToolStrix
	r.Tool = o.Tool
	r.FixedTargets = nil
	r.MaxOutputBytes = 4 << 20
	writeRequest(t, o.RequestFile, r)
	calls := 0
	err := execute(context.Background(), o, func(cmd *exec.Cmd) error {
		calls++
		if err := os.WriteFile(cmd.Args[6], []byte(`{"completed":false,"complete":false,"error":"model_unavailable"}`), 0600); err != nil {
			return err
		}
		return ErrInvalid
	}, noEnvironment)
	if err == nil || calls != 1 {
		t.Fatalf("missing model bypassed adapter failure report: calls=%d err=%v", calls, err)
	}
	raw, readErr := os.ReadFile(o.ReportFile)
	if readErr != nil || !strings.Contains(string(raw), "model_unavailable") {
		t.Fatal("structured model failure missing")
	}
	done, _ := os.ReadFile(o.DoneFile)
	if string(done) != `{"status":"failed"}` {
		t.Fatal("missing model did not wake uploader")
	}
}
