package nuclei

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/nuclei/fakenuclei"
)

func TestValidExtraDirsSkipsUnsafeAndMalformed(t *testing.T) {
	good := t.TempDir()
	fakenuclei.WriteTree(t, good, fakenuclei.Template{Path: "http/good.yaml", ID: "good"})
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "outside.yaml"), []byte("id: outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafe := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "outside.yaml"), filepath.Join(unsafe, "escape.yaml")); err != nil {
		t.Fatal(err)
	}
	malformed := t.TempDir()
	if err := os.WriteFile(filepath.Join(malformed, "bad.yaml"), []byte("id: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := validExtraDirs([]string{good, unsafe, malformed}, options{logger: slog.New(slog.DiscardHandler)})
	realGood, err := filepath.EvalSymlinks(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !slices.Equal(got, []string{realGood}) {
		t.Fatalf("valid extra dirs = %v, want only %s", got, realGood)
	}
}
