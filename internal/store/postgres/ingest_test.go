package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func ingestInput(scope string, obs time.Time, complete bool, keys ...string) store.IngestInput {
	in := store.IngestInput{
		Tool: "prowler", Scope: scope, Check: model.IngestCheck("prowler"), Source: model.IngestSource("prowler"),
		AssetScope: model.ScopeExternal, Complete: complete, ObservedAt: obs, Now: obs, ResolveAfter: 2,
		Digest: fmt.Sprintf("%s|%d|%v|%s", scope, obs.UnixNano(), complete, strings.Join(keys, ",")),
	}
	for i, k := range keys {
		in.Items = append(in.Items, store.IngestItem{Index: i, AssetKind: model.KindCloudResource, AssetKey: "arn:aws:s3:::" + k,
			Finding: model.FindingInput{Key: k, Severity: model.SeverityHigh, Title: k}})
	}
	return in
}

// Concurrent requests for one (tool, scope) serialise: no request fails, no
// finding is duplicated, and the result equals some serial order. Requests for
// other scopes that share assets run alongside without deadlocking.
func TestIngestConcurrentRequestsSerialise(t *testing.T) {
	ctx := context.Background()
	s := newMigratedStore(t)
	base := time.Date(2026, 10, 3, 7, 0, 0, 0, time.UTC)
	keys := []string{"a", "b", "c", "d", "e", "f", "g", "h"}

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scope := []string{"aws:111111111111:us-west-2", "aws:222222222222:us-west-2", "aws:333333333333:us-west-2"}[i%3]
			// Every request reports all keys (in a rotated order, so lock
			// acquisition order is exercised), complete, each its own run.
			ks := append(append([]string{}, keys[i%len(keys):]...), keys[:i%len(keys)]...)
			_, err := s.IngestFindings(ctx, ingestInput(scope, base.Add(time.Duration(i)*time.Second), true, ks...))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent ingest: %v", err)
		}
	}
	fs, total, err := s.ListFindings(ctx, store.FindingFilter{Check: "ext.prowler"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3*len(keys) {
		t.Fatalf("findings = %d, want %d (one per key per scope)", total, 3*len(keys))
	}
	for _, f := range fs {
		if f.Status != model.StatusOpen || f.MissedRuns != 0 {
			t.Errorf("finding %s/%s = %s missed %d", f.IngestScope, f.Title, f.Status, f.MissedRuns)
		}
	}
	assets, _, err := s.ListAssets(ctx, store.AssetFilter{Kind: model.KindCloudResource})
	if err != nil || len(assets) != len(keys) {
		t.Fatalf("assets = %d err %v, want %d shared assets", len(assets), err, len(keys))
	}
}

// A request that fails mid-transaction leaves nothing behind: no asset, no
// finding, no scope state (the next delivery of the same run is not a replay).
func TestIngestIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := newMigratedStore(t)
	now := time.Date(2026, 10, 3, 7, 0, 0, 0, time.UTC)
	in := ingestInput("aws:123456789012:us-west-2", now, true, "good", "bad\x00key")
	if _, err := s.IngestFindings(ctx, in); err == nil {
		t.Fatal("expected an error for a NUL byte (invalid in Postgres text)")
	}
	if _, total, _ := s.ListFindings(ctx, store.FindingFilter{}); total != 0 {
		t.Fatalf("%d findings left behind", total)
	}
	if as, _, _ := s.ListAssets(ctx, store.AssetFilter{IncludeRemoved: true}); len(as) != 0 {
		t.Fatalf("%d assets left behind", len(as))
	}
	if sc, _ := s.ListIngestScopes(ctx); len(sc) != 0 {
		t.Fatalf("scope state left behind: %+v", sc)
	}
	in.Items, in.Digest = in.Items[:1], "same run, fixed"
	r, err := s.IngestFindings(ctx, in)
	if err != nil || r.Replay || len(r.Opened) != 1 {
		t.Fatalf("retry after failure: %+v err %v", r, err)
	}
}

// The ingest migration's statements are idempotent: re-running its Up section
// on an already-migrated database succeeds and changes nothing.
func TestIngestMigrationReappliesCleanly(t *testing.T) {
	ctx := context.Background()
	raw, err := os.ReadFile("migrations/00008_ingest.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, _, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("no goose Down marker")
	}
	_, up, _ = strings.Cut(up, "-- +goose Up")
	url := freshDB(t, true) // already migrated from the template
	c, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()
	for i := 0; i < 2; i++ {
		if _, err := c.Exec(ctx, up); err != nil {
			t.Fatalf("re-apply #%d: %v", i, err)
		}
	}
	var n int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname = 'findings_ingest_scope_idx'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("index count = %d err %v", n, err)
	}
}
