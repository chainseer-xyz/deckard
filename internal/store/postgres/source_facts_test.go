package postgres_test

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

func TestSourceFactsMigrationSeedsOnlyRetainedCanonicalAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := postgres.New(ctx, freshDB(t, false), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	db := stdlib.OpenDBFromPool(s.Pool())
	t.Cleanup(func() { _ = db.Close() })
	p, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 11); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	_, err = s.Pool().Exec(ctx, `INSERT INTO assets (kind, key, source, scope, zone, attrs, first_seen, last_seen, reporters, removed_at) VALUES
		('hostname', 'overlap.example.com', 'cf', 'owned', 'example.com', '{"provider":"cf"}', $1, $1, '{cf,k8s,aws}', NULL),
		('service', 'overlap.example.com:443', 'net.ports', 'owned', '', '{"port":443}', $1, $1, '{}', NULL),
		('hostname', 'removed.example.com', 'cf', 'owned', 'example.com', '{"provider":"cf"}', $1, $1, '{cf,aws}', $1),
		('hostname', 'unknown.example.com', 'cf', 'owned', 'example.com', '{"provider":"cf"}', $1, $1, '{aws}', NULL),
		('hostname', 'empty.example.com', 'static', 'owned', '', '{}', $1, $1, '{static}', NULL)`, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetAssetByKey(ctx, model.KindHostname, "overlap.example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]model.SourceFact{"cf": {Zone: "example.com", Attrs: map[string]any{"provider": "cf"}}}
	if !reflect.DeepEqual(a.SourceFacts, want) || !reflect.DeepEqual(a.Reporters, []string{"aws", "cf", "k8s"}) {
		t.Fatalf("migration invented or lost authority facts: %+v", a)
	}
	var otherFacts int
	if err := s.Pool().QueryRow(ctx, `SELECT count(*) FROM assets WHERE key NOT IN ('overlap.example.com', 'empty.example.com') AND source_facts <> '{}'`).Scan(&otherFacts); err != nil || otherFacts != 0 {
		t.Fatalf("non-authority facts count=%d err=%v", otherFacts, err)
	}
	var emptyFact bool
	if err := s.Pool().QueryRow(ctx, `SELECT source_facts = '{"static":{}}' FROM assets WHERE key = 'empty.example.com'`).Scan(&emptyFact); err != nil || !emptyFact {
		t.Fatalf("known empty canonical fact not normalized: %v err=%v", emptyFact, err)
	}
	// A legacy secondary reporter has no saved fields. It cannot inherit cf's.
	diff, err := s.ApplySnapshot(ctx, "cf", nil, nil, now.Add(time.Hour))
	if err != nil || len(diff.Changed) != 1 {
		t.Fatalf("legacy promotion diff=%+v err=%v", diff, err)
	}
	a, err = s.GetAsset(ctx, a.ID)
	if err != nil || a.Source != "aws" || a.Zone != "" || len(a.Attrs) != 0 || len(a.SourceFacts) != 0 {
		t.Fatalf("legacy promotion borrowed absent facts: %+v err=%v", a, err)
	}
	// A later real snapshot supplies only the newly reporting authority's data.
	input := store.AssetUpsert{AssetInput: model.AssetInput{Kind: a.Kind, Key: a.Key, Zone: "aws.example.com", Attrs: map[string]any{"provider": "aws"}}, Scope: model.ScopeOwned}
	diff, err = s.UpsertSnapshot(ctx, "aws", []store.AssetUpsert{input}, nil, now.Add(2*time.Hour))
	if err != nil || len(diff.Changed) != 1 || len(diff.Changed[0].SourceFacts) != 1 || diff.Changed[0].Attrs["provider"] != "aws" {
		t.Fatalf("legacy authority resync: %+v err=%v", diff, err)
	}
}

func TestSourceFactsMigrationDrainsExistingWritersBeforeBackfill(t *testing.T) {
	url := freshDB(t, false)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	now := seedStateMigration(t, ctx, url, 12)
	observer := stateMigrationConn(t, ctx, url)
	worker := stateMigrationTx(t, ctx, stateMigrationConn(t, ctx, url))
	if _, err := worker.Exec(ctx, `SELECT id FROM assets WHERE id = 1 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("migrations/00012_asset_source_facts.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, _, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("migration has no Down marker")
	}
	migrator := stateMigrationConn(t, ctx, url)
	migration := stateMigrationTx(t, ctx, migrator)
	done := stateMigrationAsync(t, cancel, func() error {
		_, err := migration.Exec(ctx, up)
		return err
	})
	waitStateMigrationLock(t, ctx, observer, migrator.PgConn().PID(), "AccessExclusiveLock")
	_, err = worker.Exec(ctx, `INSERT INTO assets (id, kind, key, source, scope, zone, attrs, first_seen, last_seen, reporters)
		VALUES (4, 'hostname', 'writer.example.com', 'aws', 'owned', 'aws.example.com', '{"owned":true}', $1, $1, '{aws}')
		ON CONFLICT (kind, key) DO UPDATE SET attrs = EXCLUDED.attrs`, now)
	if err != nil {
		t.Fatalf("existing writer cannot finish before migration: %v", err)
	}
	if err := worker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	awaitStateMigration(t, ctx, done)
	if err := migration.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var correct bool
	if err := observer.QueryRow(ctx, `SELECT source_facts = '{"aws":{"zone":"aws.example.com","attrs":{"owned":true}}}' FROM assets WHERE id = 4`).Scan(&correct); err != nil || !correct {
		t.Fatalf("backfill missed committed writer: %v err=%v", correct, err)
	}
}

func TestSourceFactsConcurrentWritersRetainIndependentFacts(t *testing.T) {
	s := newMigratedStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	key := "overlap.example.com"
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	seed := store.AssetUpsert{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: key, Zone: "cf.example.com", Attrs: map[string]any{"provider": "cf"}}, Scope: model.ScopeOwned}
	if _, err := s.ApplySnapshot(ctx, "cf", []store.AssetUpsert{seed}, nil, now); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 3)
	for _, source := range []string{"cf", "aws", "k8s"} {
		go func() {
			<-start
			for i := range 10 {
				input := store.AssetUpsert{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: key, Zone: source + ".example.com", Attrs: map[string]any{"provider": source, "version": fmt.Sprint(i)}}, Scope: model.ScopeOwned}
				if _, err := s.UpsertSnapshot(ctx, source, []store.AssetUpsert{input}, nil, now.Add(time.Duration(i+1)*time.Minute)); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		}()
	}
	close(start)
	for range 3 {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	a, err := s.GetAssetByKey(ctx, model.KindHostname, key)
	if err != nil || a.Source != "cf" || a.Attrs["provider"] != "cf" || !reflect.DeepEqual(a.Reporters, []string{"aws", "cf", "k8s"}) || len(a.SourceFacts) != 3 {
		t.Fatalf("concurrent canonical/reporters: %+v err=%v", a, err)
	}
	for _, source := range a.Reporters {
		fact := a.SourceFacts[source]
		if fact.Zone != source+".example.com" || fact.Attrs["provider"] != source || fact.Attrs["version"] != "9" {
			t.Errorf("%s lost its final independent facts: %+v", source, fact)
		}
	}
}
