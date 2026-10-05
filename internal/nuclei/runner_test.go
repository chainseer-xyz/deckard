package nuclei

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// Warnings nuclei prints to stderr (per-template errors on a large scan) must
// not fail the run: a stderr write error stops os/exec draining the pipe, so
// the run fails, its matches count as partial and nothing can ever resolve.
func TestExecRunnerVerboseStderrDoesNotFailRun(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	script := `i=0; while [ $i -lt 64 ]; do printf '%01023d\n' 0 >&2; i=$((i+1)); done; echo '{"ok":true}'`

	out, err := ExecRunner{}.Run(context.Background(), sh, []string{"-c", script})

	if err != nil {
		t.Fatalf("64 KiB of stderr failed the run: %.200v", err)
	}
	if !strings.Contains(string(out), `"ok":true`) {
		t.Fatalf("stdout = %q", out)
	}
}

func TestExecRunnerSuccessfulExitWithFailedRequestsIsIncomplete(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	script := `previous=''; for argument do
	if [ "$previous" = '-elog' ]; then printf '{"error":"denied address found for host"}\n' > "$argument"; fi
	previous="$argument"
	done
	printf '{"partial_match":true}\n'`
	r := ExecRunner{Policy: fixturePolicy}
	out, err := r.Run(context.Background(), sh, []string{"-c", script, "--", "-u", "https://app.example.com/"})
	if err == nil || !strings.Contains(err.Error(), "incomplete scan") || !strings.Contains(string(out), "partial_match") {
		t.Fatalf("request failure became clean or lost matches: stdout=%q err=%v", out, err)
	}
	if errors.Is(err, ErrOutOfScope) {
		t.Fatal("partial process output must remain salvageable, not a preflight refusal")
	}
}
