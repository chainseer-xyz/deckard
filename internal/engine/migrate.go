package engine

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

// migrateLockKey is the Postgres advisory-lock key serialising River
// migrations across replicas (distinct from the app's goose lock).
const migrateLockKey int64 = 0x626c617274524956 // "deckardRIV"

// Migrate brings River's schema up to date. Call it from `deckard migrate` and
// at startup, next to the store's own Migrate. Concurrent callers (several
// replicas booting) are serialised by a session advisory lock held on one
// pooled connection, and River's migrations are themselves idempotent, so the
// second caller finds nothing to do.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("river migrate: acquire connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
		return fmt.Errorf("river migrate: lock: %w", err)
	}
	defer func() {
		// Unlock on a fresh context: ctx may already be cancelled.
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrateLockKey)
	}()

	m, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Logger: slog.Default()})
	if err != nil {
		return fmt.Errorf("river migrate: %w", err)
	}
	if _, err := m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("river migrate: %w", err)
	}
	return nil
}
