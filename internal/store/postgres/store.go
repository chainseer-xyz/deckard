// Package postgres implements store.Store on PostgreSQL via pgx v5, with
// goose migrations embedded in the binary.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/chainseer-xyz/deckard/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store is the Postgres-backed store.Store.
type Store struct {
	pool *pgxpool.Pool
}

var _ store.Store = (*Store)(nil)

// New connects to Postgres. maxConns <= 0 keeps the pgx default.
func New(ctx context.Context, url string, maxConns int) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = int32(min(maxConns, math.MaxInt32))
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Migrate applies pending migrations. A Postgres session advisory lock makes
// concurrent replicas safe: one migrates, the rest wait and find nothing to do.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	db := stdlib.OpenDBFromPool(s.pool)
	defer db.Close()
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("migration locker: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, sub, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("goose provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// Ping checks connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Pool returns the underlying connection pool so other components (the job
// queue) can share it instead of opening a second one. The Store owns it:
// Close the Store, not the pool.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// querier is satisfied by both *pgxpool.Pool and pgx.Tx.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *Store) inTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// notFound maps pgx "no rows" and FK violations to store.ErrNotFound.
func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" { // foreign_key_violation
		return store.ErrNotFound
	}
	return err
}

// where builds a WHERE clause with positional parameters.
type where struct {
	conds []string
	args  []any
}

// add appends cond, replacing each "?" with the next $n placeholder.
func (w *where) add(cond string, args ...any) {
	for _, a := range args {
		w.args = append(w.args, a)
		cond = strings.Replace(cond, "?", fmt.Sprintf("$%d", len(w.args)), 1)
	}
	w.conds = append(w.conds, cond)
}

func (w *where) sql() string {
	if len(w.conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.conds, " AND ")
}

// likeEscape escapes LIKE wildcards in a user-supplied substring.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func nilIfEmpty(m map[string]any) map[string]any {
	if len(m) == 0 {
		return nil
	}
	return m
}
