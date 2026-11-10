package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/inventory/pgtest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

func TestSyncAcceptShrinkSelectsOnlyOneSource(t *testing.T) {
	ctx := context.Background()
	url := pgtest.NewURL(t)
	st, err := postgres.New(ctx, url, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, name := range []string{"first", "second"} {
		var assets []store.AssetUpsert
		for i := range 30 {
			assets = append(assets, store.AssetUpsert{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: fmt.Sprintf("%s-%d.example.com", name, i)}, Scope: model.ScopeExternal})
		}
		if _, err := st.ApplySnapshot(ctx, name, assets, nil, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "deckard.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("database:\n  url: %q\nserver:\n  roles: [api]\nsources:\n  - {name: first, type: static}\n  - {name: second, type: static}\n", url)), 0o600); err != nil {
		t.Fatal(err)
	}
	runSyncWith := func(want int, args ...string) {
		t.Helper()
		var out, stderr bytes.Buffer
		if code := runSync(append([]string{"--config", path}, args...), &out, &stderr); code != want {
			t.Fatalf("%v: code=%d want=%d stdout=%s stderr=%s", args, code, want, out.String(), stderr.String())
		}
	}
	runSyncWith(2, "--accept-shrink")
	runSyncWith(1, "--source", "missing", "--accept-shrink")
	runSyncWith(0, "--source", "first", "--accept-shrink")
	for name, want := range map[string]int{"first": 0, "second": 30} {
		_, total, err := st.ListAssets(ctx, store.AssetFilter{Source: name})
		if err != nil || total != want {
			t.Fatalf("source=%s live=%d want=%d err=%v", name, total, want, err)
		}
	}
	// A later native invocation without explicit acceptance still uses the guard.
	var out, stderr bytes.Buffer
	if code := runSync([]string{"--config", path, "--source", "second"}, &out, &stderr); code != 1 || !strings.Contains(out.String(), "suspicious shrink") {
		t.Fatalf("normal sync: code=%d stdout=%s stderr=%s", code, out.String(), stderr.String())
	}
	_, total, err := st.ListAssets(ctx, store.AssetFilter{Source: "second"})
	if err != nil || total != 30 {
		t.Fatalf("other source removed: %d %v", total, err)
	}
}
