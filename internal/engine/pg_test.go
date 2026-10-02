package engine

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

// One lazily started Postgres container shared by the integration tests; every
// test gets its own database. Tests skip when Docker is unavailable. On the
// dev machine:
//
//	DOCKER_HOST=unix://$HOME/.colima/default/docker.sock \
//	TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
//	TESTCONTAINERS_RYUK_DISABLED=true go test ./internal/engine/...
var (
	pgOnce    sync.Once
	pgCtr     *tcpostgres.PostgresContainer
	pgAdmin   string
	pgBase    string
	pgErr     error
	dbCounter atomic.Int64
)

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
		tcpostgres.WithDatabase("postgres"), tcpostgres.WithUsername("deckard"), tcpostgres.WithPassword("deckard"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		pgErr = err
		return
	}
	pgCtr = ctr
	if pgAdmin, pgErr = ctr.ConnectionString(ctx, "sslmode=disable"); pgErr != nil {
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
}

// newDB creates an empty database and returns its URL.
func newDB(t *testing.T) string {
	t.Helper()
	pgOnce.Do(startPG)
	if pgErr != nil {
		t.Skipf("skipping: Postgres testcontainer unavailable (is Docker running? see pg_test.go): %v", pgErr)
	}
	name := fmt.Sprintf("e%d_%d", os.Getpid(), dbCounter.Add(1))
	adminExec(t, "CREATE DATABASE "+name)
	t.Cleanup(func() { adminExec(t, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	return pgBase + "/" + name + "?sslmode=disable"
}

func adminExec(t *testing.T, sql string) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, pgAdmin)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = c.Close(ctx) }()
	if _, err := c.Exec(ctx, sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// migratedDB returns a store with deckard's schema and a pool with River's.
func migratedDB(t *testing.T) (*postgres.Store, *pgxpool.Pool) {
	t.Helper()
	url := newDB(t)
	ctx := context.Background()
	st, err := postgres.New(ctx, url, 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 20
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return st, pool
}
