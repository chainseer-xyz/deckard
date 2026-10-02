package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
	"github.com/chainseer-xyz/deckard/internal/store/storetest"
)

// shared container, started lazily so tests skip cleanly without Docker.
var (
	pgOnce    sync.Once
	pgCtr     *tcpostgres.PostgresContainer
	pgAdmin   string // admin connection URL (postgres db)
	pgBase    string // URL prefix without db name
	pgErr     error
	dbCounter atomic.Int64
)

const templateDB = "deckard_template"

func TestMain(m *testing.M) {
	code := m.Run()
	if pgCtr != nil {
		_ = pgCtr.Terminate(context.Background())
	}
	os.Exit(code)
}

func startPG() {
	defer func() {
		if r := recover(); r != nil {
			pgErr = fmt.Errorf("docker unavailable: %v", r)
		}
	}()
	ctx := context.Background()
	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("postgres"),
		tcpostgres.WithUsername("deckard"),
		tcpostgres.WithPassword("deckard"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		pgErr = err
		return
	}
	pgCtr = ctr
	pgAdmin, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		pgErr = err
		return
	}
	host, err := ctr.Host(ctx)
	if err != nil {
		pgErr = err
		return
	}
	port, err := ctr.MappedPort(ctx, "5432/tcp")
	if err != nil {
		pgErr = err
		return
	}
	pgBase = fmt.Sprintf("postgres://deckard:deckard@%s:%s", host, port.Port())

	// Build a migrated template database once; every test clones it.
	if err := adminExec(ctx, "CREATE DATABASE "+templateDB); err != nil {
		pgErr = err
		return
	}
	s, err := postgres.New(ctx, dbURL(templateDB), 2)
	if err != nil {
		pgErr = err
		return
	}
	defer s.Close()
	pgErr = s.Migrate(ctx)
}

func adminExec(ctx context.Context, sql string) error {
	c, err := pgx.Connect(ctx, pgAdmin)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	_, err = c.Exec(ctx, sql)
	return err
}

func dbURL(name string) string { return pgBase + "/" + name + "?sslmode=disable" }

// freshDB returns the URL of a new empty database (no schema).
func freshDB(t *testing.T, template bool) string {
	t.Helper()
	pgOnce.Do(startPG)
	if pgErr != nil {
		t.Skipf("skipping: Postgres testcontainer unavailable (is Docker running?): %v", pgErr)
	}
	name := fmt.Sprintf("t%d_%d", os.Getpid(), dbCounter.Add(1))
	sql := "CREATE DATABASE " + name
	if template {
		sql += " TEMPLATE " + templateDB
	}
	if err := adminExec(context.Background(), sql); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() { _ = adminExec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	return dbURL(name)
}

func newMigratedStore(t *testing.T) store.Store {
	t.Helper()
	s, err := postgres.New(context.Background(), freshDB(t, true), 4)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestContract(t *testing.T) {
	storetest.Run(t, newMigratedStore)
}

func TestMigrateIdempotent(t *testing.T) {
	ctx := context.Background()
	s, err := postgres.New(ctx, freshDB(t, false), 4)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 3; i++ {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate #%d: %v", i, err)
		}
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateConcurrent(t *testing.T) {
	ctx := context.Background()
	url := freshDB(t, false)
	const replicas = 6
	stores := make([]*postgres.Store, replicas)
	for i := range stores {
		s, err := postgres.New(ctx, url, 3)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		stores[i] = s
	}
	errs := make(chan error, replicas)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, s := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.Migrate(ctx)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Migrate: %v", err)
		}
	}
	if _, _, err := stores[0].ListAssets(ctx, store.AssetFilter{}); err != nil {
		t.Errorf("schema not usable after concurrent migrate: %v", err)
	}
}

func TestApplySnapshotIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := newMigratedStore(t)
	good := store.AssetUpsert{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: "ok.x.io", Source: "cf"}, Scope: model.ScopeOwned}
	// NUL bytes are not valid in Postgres text, so this row fails mid-transaction.
	bad := store.AssetUpsert{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: "bad\x00.x.io", Source: "cf"}, Scope: model.ScopeOwned}
	if _, err := s.ApplySnapshot(ctx, "cf", []store.AssetUpsert{good, bad}, nil, time.Now()); err == nil {
		t.Fatal("expected error")
	}
	if _, err := s.GetAssetByKey(ctx, model.KindHostname, "ok.x.io"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("partial snapshot persisted: err = %v", err)
	}
	if _, err := s.ListEvents(ctx, time.Time{}, 0); err != nil {
		t.Fatal(err)
	}
	evs, _ := s.ListEvents(ctx, time.Time{}, 0)
	if len(evs) != 0 {
		t.Errorf("events leaked from rolled-back snapshot: %d", len(evs))
	}
}

func TestConcurrentReconcileSameAssetDoesNotDuplicate(t *testing.T) {
	ctx := context.Background()
	s := newMigratedStore(t)
	if _, err := s.ApplySnapshot(ctx, "cf", []store.AssetUpsert{{
		AssetInput: model.AssetInput{Kind: model.KindHostname, Key: "a.x.io", Source: "cf"}, Scope: model.ScopeOwned,
	}}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	a, _ := s.GetAssetByKey(ctx, model.KindHostname, "a.x.io")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ReconcileFindings(ctx, store.ReconcileInput{
				AssetID: a.ID, Check: "c", ResolveAfter: 1, Now: time.Now(),
				Findings: []model.FindingInput{{Check: "c", Key: "k", Severity: model.SeverityLow, Title: "t"}},
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	_, total, err := s.ListFindings(ctx, store.FindingFilter{})
	if err != nil || total != 1 {
		t.Errorf("total = %d, err = %v; want 1", total, err)
	}
}
