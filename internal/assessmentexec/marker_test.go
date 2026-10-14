package assessmentexec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedDoneIsCompleteExclusiveAndLeavesNoTemporaryMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "done")
	if err := publishDone(path, "succeeded"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != `{"status":"succeeded"}` {
		t.Fatal("published marker incomplete")
	}
	if err := publishDone(path, "failed"); err == nil {
		t.Fatal("stale completion overwritten")
	}
	raw, _ = os.ReadFile(path)
	if string(raw) != `{"status":"succeeded"}` {
		t.Fatal("published status changed")
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(files) != 1 {
		t.Fatal("marker temp file leaked")
	}
}
