// Package pgtest provides a contract-verified Postgres store for tests of
// packages that need a real store (inventory, finding). It starts one
// testcontainers Postgres per test binary, migrates a template database once
// and clones it per test. Tests skip with a clear message when Docker is
// unavailable.
//
// On colima: DOCKER_HOST=unix:///Users/<you>/.colima/default/docker.sock
// TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock
// TESTCONTAINERS_RYUK_DISABLED=true
package pgtest

import (
	"context"
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

	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

const templateDB = "deckard_template"

var (
	once    sync.Once
	ctr     *tcpostgres.PostgresContainer
	admin   string
	base    string
	startup error
	counter atomic.Int64
)

// Main is a TestMain helper: it runs the tests and terminates the container.
//
//	func TestMain(m *testing.M) { pgtest.Main(m) }
func Main(m *testing.M) {
	code := m.Run()
	if ctr != nil {
		_ = ctr.Terminate(context.Background())
	}
	os.Exit(code)
}

func start() {
	defer func() {
		if r := recover(); r != nil {
			startup = fmt.Errorf("docker unavailable: %v", r)
		}
	}()
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("postgres"),
		tcpostgres.WithUsername("deckard"),
		tcpostgres.WithPassword("deckard"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		startup = err
		return
	}
	ctr = c
	if admin, err = c.ConnectionString(ctx, "sslmode=disable"); err != nil {
		startup = err
		return
	}
	host, err := c.Host(ctx)
	if err != nil {
		startup = err
		return
	}
	port, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		startup = err
		return
	}
	base = fmt.Sprintf("postgres://deckard:deckard@%s:%s", host, port.Port())
	if startup = adminExec(ctx, "CREATE DATABASE "+templateDB); startup != nil {
		return
	}
	s, err := postgres.New(ctx, url(templateDB), 2)
	if err != nil {
		startup = err
		return
	}
	defer s.Close()
	startup = s.Migrate(ctx)
}

func adminExec(ctx context.Context, sql string) error {
	c, err := pgx.Connect(ctx, admin)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close(ctx) }()
	_, err = c.Exec(ctx, sql)
	return err
}

func url(name string) string { return base + "/" + name + "?sslmode=disable" }

// NewURL returns the connection URL of a fresh database cloned from the
// migrated template (application schema only; job-queue tables are created by
// the code under test). It skips the test when Docker is not available.
func NewURL(t testing.TB) string {
	t.Helper()
	once.Do(start)
	if startup != nil {
		t.Skipf("skipping: Postgres testcontainer unavailable (is Docker running?): %v", startup)
	}
	name := fmt.Sprintf("t%d_%d", os.Getpid(), counter.Add(1))
	if err := adminExec(context.Background(), "CREATE DATABASE "+name+" TEMPLATE "+templateDB); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() { _ = adminExec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	return url(name)
}

// New returns a fresh migrated store, skipping the test when Docker is not
// available.
func New(t testing.TB) store.Store {
	t.Helper()
	s, err := postgres.New(context.Background(), NewURL(t), 4)
	if err != nil {
		t.Fatalf("postgres.New: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}
