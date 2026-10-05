package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

func TestStateMigrationsDrainRowWriters(t *testing.T) {
	for _, version := range []int64{9, 10} {
		t.Run(fmt.Sprintf("migration_%d", version), func(t *testing.T) {
			testStateMigrationWithWriters(t, version)
		})
	}
}

func testStateMigrationWithWriters(t *testing.T, version int64) {
	t.Helper()
	url := freshDB(t, false)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	now := seedStateMigration(t, ctx, url, version)
	observer := stateMigrationConn(t, ctx, url)
	worker := stateMigrationTx(t, ctx, stateMigrationConn(t, ctx, url))
	var parentID int64
	if err := worker.QueryRow(ctx, `SELECT id FROM assets WHERE id = 1 FOR UPDATE`).Scan(&parentID); err != nil {
		t.Fatal(err)
	}
	migrator := stateMigrationConn(t, ctx, url)
	migration := stateMigrationTx(t, ctx, migrator)
	up := stateMigrationSQL(t, version)
	done := stateMigrationAsync(t, cancel, func() error {
		_, err := migration.Exec(ctx, up)
		return err
	})
	waitStateMigrationLock(t, ctx, observer, migrator.PgConn().PID(), "ExclusiveLock")
	// Match the old worker's parent FOR UPDATE -> discovered asset INSERT order.
	_, err := worker.Exec(ctx, `INSERT INTO assets (id, kind, key, source, scope, first_seen, last_seen, reporters)
		VALUES (4, 'hostname', 'worker.example.com', 'cf', 'owned', $1, $1, '{cf}')
		ON CONFLICT (kind, key) DO UPDATE SET last_seen = EXCLUDED.last_seen`, now)
	if err != nil {
		t.Fatalf("existing writer upsert: %v", err)
	}
	if err := worker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	awaitStateMigration(t, ctx, done)
	// Keep the migration transaction open, as goose does until the file finishes.
	late := stateMigrationConn(t, ctx, url)
	lateDone := stateMigrationAsync(t, cancel, func() error {
		_, err := late.Exec(ctx, `SELECT id FROM assets WHERE id = 2 FOR UPDATE`)
		return err
	})
	waitStateMigrationLock(t, ctx, observer, late.PgConn().PID(), "RowShareLock")
	assertStateMigrationReads(t, ctx, observer)
	if err := migration.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	awaitStateMigration(t, ctx, lateDone)
	assertStateMigrationBackfill(t, ctx, observer, version, now)
}

func seedStateMigration(t *testing.T, ctx context.Context, url string, version int64) time.Time {
	t.Helper()
	s, err := postgres.New(ctx, url, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := stdlib.OpenDBFromPool(s.Pool())
	defer func() { _ = db.Close() }()
	p, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, version-1); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	_, err = s.Pool().Exec(ctx, `INSERT INTO assets (id, kind, key, source, scope, first_seen, last_seen, reporters) VALUES
		(1, 'hostname', 'parent.example.com', 'cf', 'owned', $1, $1, '{cf}'),
		(2, 'service', 'parent.example.com:443', 'net.ports', 'owned', $1, $1, '{}'),
		(3, 'hostname', 'peer.example.com', 'cf', 'owned', $1, $1, '{cf}')`, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool().Exec(ctx, `INSERT INTO relations (from_id, to_id, type) VALUES
		(1, 2, 'exposes'), (1, 3, 'cname_to'), (2, 3, 'resolves_to');
		INSERT INTO derivations (child_id, parent_id, origin) VALUES (2, 1, 'net.ports')`); err != nil {
		t.Fatal(err)
	}
	_, err = s.Pool().Exec(ctx, `INSERT INTO scans (asset_id, check_name, tier, started_at, error) VALUES
		(1, 'dns.hygiene', 'passive', $1, ''), (1, 'dns.hygiene', 'passive', $2, 'timeout'),
		(2, 'net.ports', 'active', $3, $4)`, now, now.Add(time.Hour), now.Add(2*time.Hour), store.UnownedDestinationSkip+"shared destination")
	if err != nil {
		t.Fatal(err)
	}
	return now
}

func stateMigrationConn(t *testing.T, ctx context.Context, url string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := conn.Close(cleanup); err != nil {
			t.Errorf("close migration connection: %v", err)
		}
	})
	return conn
}

func stateMigrationTx(t *testing.T, ctx context.Context, conn *pgx.Conn) pgx.Tx {
	t.Helper()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) && !conn.IsClosed() {
			t.Errorf("rollback migration transaction: %v", err)
		}
	})
	return tx
}

func stateMigrationSQL(t *testing.T, version int64) string {
	t.Helper()
	name := map[int64]string{9: "relation_reporters", 10: "scan_state"}[version]
	raw, err := os.ReadFile(fmt.Sprintf("migrations/%05d_%s.sql", version, name))
	if err != nil {
		t.Fatal(err)
	}
	up, _, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("migration has no Down marker")
	}
	return up
}

func stateMigrationAsync(t *testing.T, cancel context.CancelFunc, run func() error) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		done <- run()
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Error("migration operation did not stop after cancellation")
		}
	})
	return done
}

func waitStateMigrationLock(t *testing.T, ctx context.Context, observer *pgx.Conn, pid uint32, want string) {
	t.Helper()
	for {
		var locktype, mode string
		var onAssets bool
		err := observer.QueryRow(ctx, `SELECT locktype, mode, COALESCE(relation = 'assets'::regclass, false)
			FROM pg_locks WHERE pid = $1 AND NOT granted LIMIT 1`, pid).Scan(&locktype, &mode, &onAssets)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // The server's lock queue is the barrier; elapsed time is not.
		}
		if err != nil {
			t.Fatalf("wait for %s: %v", want, err)
		}
		if locktype != "relation" || mode != want || !onAssets {
			t.Fatalf("pending lock: type=%s mode=%s assets=%t, want assets %s", locktype, mode, onAssets, want)
		}
		return
	}
}

func awaitStateMigration(t *testing.T, ctx context.Context, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("migration or writer failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("migration or writer timed out: %v", ctx.Err())
	}
}

func assertStateMigrationReads(t *testing.T, ctx context.Context, observer *pgx.Conn) {
	t.Helper()
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var count int
	if err := observer.QueryRow(readCtx, `SELECT count(*) FROM assets`).Scan(&count); err != nil {
		t.Fatalf("ordinary asset read blocked by migration: %v", err)
	}
	if count != 4 {
		t.Fatalf("assets after writer commit=%d, want 4", count)
	}
}

func assertStateMigrationBackfill(t *testing.T, ctx context.Context, observer *pgx.Conn, version int64, now time.Time) {
	t.Helper()
	if version == 9 {
		var source, check, discovered int
		err := observer.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE reporter = 'source:cf' AND parent_id IS NULL),
			count(*) FILTER (WHERE reporter = 'check:1:net.ports' AND parent_id = 1),
			count(*) FILTER (WHERE reporter = 'discovered' AND parent_id IS NULL)
			FROM relation_reporters`).Scan(&source, &check, &discovered)
		if err != nil {
			t.Fatal(err)
		}
		if source != 1 || check != 1 || discovered != 1 {
			t.Fatalf("relationship backfill: source=%d check=%d discovered=%d, want 1 each", source, check, discovered)
		}
		return
	}
	var attempt, success, skipped time.Time
	err := observer.QueryRow(ctx, `SELECT last_attempt, last_success,
		(SELECT last_success FROM scan_state WHERE asset_id = 2 AND check_name = 'net.ports')
		FROM scan_state WHERE asset_id = 1 AND check_name = 'dns.hygiene'`).Scan(&attempt, &success, &skipped)
	if err != nil {
		t.Fatal(err)
	}
	if !attempt.Equal(now.Add(time.Hour)) || !success.Equal(now) || !skipped.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("scan state backfill: attempt=%s success=%s skipped=%s", attempt, success, skipped)
	}
}
