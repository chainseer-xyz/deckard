package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

func TestStateMigrationsRecoverExistingRelationshipsAndScanWatermarks(t *testing.T) {
	ctx := context.Background()
	url := freshDB(t, false)
	s, err := postgres.New(ctx, url, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	db := stdlib.OpenDBFromPool(s.Pool())
	defer func() { _ = db.Close() }()
	p, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 8); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, err = s.Pool().Exec(ctx, `INSERT INTO assets (id, kind, key, source, scope, first_seen, last_seen, reporters) VALUES
		(1, 'hostname', 'a.example.com', 'cf', 'owned', $1, $1, '{cf}'),
		(2, 'hostname', 'b.example.com', 'cf', 'owned', $1, $1, '{cf}'),
		(3, 'ip', '192.0.2.1', 'aws', 'owned', $1, $1, '{aws}'),
		(4, 'service', 'a.example.com:443', 'net.ports', 'owned', $1, $1, '{}')`, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool().Exec(ctx, `INSERT INTO relations (from_id, to_id, type) VALUES (1, 2, 'cname_to'), (1, 4, 'exposes'), (2, 3, 'resolves_to');
		INSERT INTO derivations (child_id, parent_id, origin) VALUES (4, 1, 'net.ports')`); err != nil {
		t.Fatal(err)
	}
	_, err = s.Pool().Exec(ctx, `INSERT INTO scans (asset_id, check_name, tier, started_at, error) VALUES
		(1, 'c1', 'passive', $1, ''), (1, 'c1', 'passive', $2, 'timeout'),
		(1, 'c2', 'active', $3, $4)`, now, now.Add(time.Hour), now.Add(2*time.Hour), store.UnownedDestinationSkip+"shared destination")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		to       int64
		reporter string
	}{{2, "source:cf"}, {4, "check:1:net.ports"}, {3, "discovered"}} {
		var reporter string
		if err := s.Pool().QueryRow(ctx, `SELECT reporter FROM relation_reporters WHERE to_id = $1`, want.to).Scan(&reporter); err != nil || reporter != want.reporter {
			t.Errorf("relation %d provenance=%q err=%v, want %q", want.to, reporter, err, want.reporter)
		}
	}
	if n, err := s.PruneScans(ctx, now.Add(24*time.Hour)); err != nil || n != 3 {
		t.Fatalf("history prune: n=%d err=%v", n, err)
	}
	peer, err := postgres.New(ctx, url, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	last, err := peer.LastScans(ctx)
	if err != nil || len(last) != 2 {
		t.Fatalf("peer watermarks after pruning all history: %+v err=%v", last, err)
	}
	if !last[0].LastAttempt.Equal(now.Add(time.Hour)) || !last[0].LastSuccess.Equal(now) ||
		!last[1].LastSuccess.Equal(now.Add(2*time.Hour)) {
		t.Errorf("migrated watermarks=%+v", last)
	}
	assets := []store.AssetUpsert{
		{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: "a.example.com", Source: "cf"}, Scope: model.ScopeOwned},
		{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: "b.example.com", Source: "cf"}, Scope: model.ScopeOwned},
	}
	if _, err := s.ApplySnapshot(ctx, "cf", assets, nil, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if edges, err := s.Edges(ctx, 1); err != nil || len(edges) != 1 || edges[0].Other.ID != 4 {
		t.Fatalf("source reconciliation did not retire legacy source edge: %+v err=%v", edges, err)
	}
	if _, err := s.ReplaceDerived(ctx, 1, "net.ports", nil, nil, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if edges, err := s.Edges(ctx, 1); err != nil || len(edges) != 0 {
		t.Errorf("check reconciliation did not retire legacy derived edge: %+v err=%v", edges, err)
	}
}
