package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func (s *Store) SaveObservation(ctx context.Context, assetID int64, o model.ObservationInput, now time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO observations (asset_id, check_name, data, observed_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (asset_id, check_name) DO UPDATE SET data = EXCLUDED.data, observed_at = EXCLUDED.observed_at`,
		assetID, o.Check, orEmpty(o.Data), now)
	return notFound(err)
}

func (s *Store) LatestObservations(ctx context.Context, assetID int64) ([]model.Observation, error) {
	rows, err := s.pool.Query(ctx, `SELECT asset_id, check_name, data, observed_at FROM observations WHERE asset_id = $1 ORDER BY check_name`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Observation
	for rows.Next() {
		var o model.Observation
		var data map[string]any
		if err := rows.Scan(&o.AssetID, &o.Check, &data, &o.ObservedAt); err != nil {
			return nil, err
		}
		o.Data = nilIfEmpty(data)
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) GetBaseline(ctx context.Context, assetID int64, check string) (*store.Baseline, error) {
	b := store.Baseline{AssetID: assetID, Check: check}
	var data map[string]any
	err := s.pool.QueryRow(ctx, `SELECT data, stable, consistent, updated_at FROM baselines WHERE asset_id = $1 AND check_name = $2`,
		assetID, check).Scan(&data, &b.Stable, &b.Consistent, &b.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	b.Data = nilIfEmpty(data)
	return &b, nil
}

func (s *Store) SaveBaseline(ctx context.Context, b store.Baseline) error {
	if b.UpdatedAt.IsZero() {
		b.UpdatedAt = time.Now()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO baselines (asset_id, check_name, data, stable, consistent, updated_at) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (asset_id, check_name) DO UPDATE
		SET data = EXCLUDED.data, stable = EXCLUDED.stable, consistent = EXCLUDED.consistent, updated_at = EXCLUDED.updated_at`,
		b.AssetID, b.Check, orEmpty(b.Data), b.Stable, b.Consistent, b.UpdatedAt)
	return notFound(err)
}

func (s *Store) RecordSync(ctx context.Context, st store.SyncStatus) error {
	var lastOK *time.Time
	if !st.LastOK.IsZero() {
		lastOK = &st.LastOK
	}
	// A failed run reports no LastOK; keep the previous success time.
	_, err := s.pool.Exec(ctx, `INSERT INTO syncs (source, type, last_run, last_ok, error, warning, asset_count, duration_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (source) DO UPDATE SET type = EXCLUDED.type, last_run = EXCLUDED.last_run,
			last_ok = COALESCE(EXCLUDED.last_ok, syncs.last_ok), error = EXCLUDED.error, warning = EXCLUDED.warning,
			asset_count = EXCLUDED.asset_count, duration_ms = EXCLUDED.duration_ms`,
		st.Source, st.Type, st.LastRun, lastOK, st.Error, st.Warning, st.AssetCount, st.DurationMS)
	return err
}

func (s *Store) ListSyncs(ctx context.Context) ([]store.SyncStatus, error) {
	rows, err := s.pool.Query(ctx, `SELECT source, type, last_run, last_ok, error, warning, asset_count, duration_ms FROM syncs ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.SyncStatus
	for rows.Next() {
		var st store.SyncStatus
		var lastOK *time.Time
		if err := rows.Scan(&st.Source, &st.Type, &st.LastRun, &lastOK, &st.Error, &st.Warning, &st.AssetCount, &st.DurationMS); err != nil {
			return nil, err
		}
		if lastOK != nil {
			st.LastOK = *lastOK
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) RecordScan(ctx context.Context, r store.ScanRun) error {
	var success *time.Time
	if r.Settled() {
		success = &r.StartedAt
	}
	// The history row and durable scheduling state commit together. Out-of-order
	// completions cannot move either watermark backwards.
	_, err := s.pool.Exec(ctx, `WITH recorded AS (
		INSERT INTO scans (asset_id, check_name, tier, started_at, duration_ms, error, findings)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING asset_id, check_name, started_at)
		INSERT INTO scan_state (asset_id, check_name, last_attempt, last_success)
		SELECT asset_id, check_name, started_at, $8::timestamptz FROM recorded
		ON CONFLICT (asset_id, check_name) DO UPDATE
		SET last_attempt = GREATEST(scan_state.last_attempt, EXCLUDED.last_attempt),
		    last_success = GREATEST(scan_state.last_success, EXCLUDED.last_success)`,
		r.AssetID, r.Check, r.Tier, r.StartedAt, r.DurationMS, r.Error, r.Findings, success)
	return err
}

func (s *Store) ListScans(ctx context.Context, limit int) ([]store.ScanRun, error) {
	q := `SELECT id, asset_id, check_name, tier, started_at, duration_ms, error, findings FROM scans ORDER BY started_at DESC, id DESC`
	var args []any
	if limit > 0 {
		q += ` LIMIT $1`
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.ScanRun
	for rows.Next() {
		var r store.ScanRun
		if err := rows.Scan(&r.ID, &r.AssetID, &r.Check, &r.Tier, &r.StartedAt, &r.DurationMS, &r.Error, &r.Findings); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LastScans: see store.Store.
func (s *Store) LastScans(ctx context.Context) ([]store.ScanLast, error) {
	rows, err := s.pool.Query(ctx, `SELECT asset_id, check_name, last_attempt, last_success
		FROM scan_state ORDER BY asset_id, check_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.ScanLast
	for rows.Next() {
		var l store.ScanLast
		var ok *time.Time
		if err := rows.Scan(&l.AssetID, &l.Check, &l.LastAttempt, &ok); err != nil {
			return nil, err
		}
		if ok != nil {
			l.LastSuccess = *ok
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// LastCleanScan returns when the most recent check run that completed
// without error finished (start plus duration), or the zero time if there is
// none. It reads one row from the newest end of scans_started_idx, so it is
// cheap however long the scan history is. The heartbeat uses it to tell a
// working scheduler from a wedged one.
func (s *Store) LastCleanScan(ctx context.Context) (time.Time, error) {
	var started time.Time
	var ms int64
	err := s.pool.QueryRow(ctx, `SELECT started_at, duration_ms FROM scans WHERE error = ''
		ORDER BY started_at DESC, id DESC LIMIT 1`).Scan(&started, &ms)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return started.Add(time.Duration(ms) * time.Millisecond), nil
}

// PruneScans: see store.Store.
func (s *Store) PruneScans(ctx context.Context, olderThan time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scans WHERE started_at < $1`, olderThan)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ListEvents returns events at or after since, newest first. limit <= 0 means
// no limit.
func (s *Store) ListEvents(ctx context.Context, since time.Time, limit int) ([]store.Event, error) {
	q := `SELECT id, type, subject, data, at FROM events WHERE at >= $1 ORDER BY at DESC, id DESC`
	args := []any{since}
	if since.IsZero() {
		args[0] = time.Unix(0, 0)
	}
	if limit > 0 {
		q += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Event
	for rows.Next() {
		var ev store.Event
		var data map[string]any
		if err := rows.Scan(&ev.ID, &ev.Type, &ev.Subject, &data, &ev.At); err != nil {
			return nil, err
		}
		ev.Data = nilIfEmpty(data)
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *Store) Stats(ctx context.Context) (store.Stats, error) {
	st := store.Stats{
		AssetsByKind: map[string]int{}, AssetsBySource: map[string]int{}, AssetsByScope: map[string]int{},
		FindingsBySev: map[string]int{}, FindingsByCheck: map[string]int{},
	}
	groups := []struct {
		dst *map[string]int
		sql string
	}{
		{&st.AssetsByKind, `SELECT kind, count(*) FROM assets WHERE removed_at IS NULL GROUP BY kind`},
		{&st.AssetsBySource, `SELECT source, count(*) FROM assets WHERE removed_at IS NULL GROUP BY source`},
		{&st.AssetsByScope, `SELECT scope, count(*) FROM assets WHERE removed_at IS NULL GROUP BY scope`},
		{&st.FindingsBySev, `SELECT severity, count(*) FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.status = 'open' AND a.removed_at IS NULL GROUP BY severity`},
		{&st.FindingsByCheck, `SELECT check_name, count(*) FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.status = 'open' AND a.removed_at IS NULL GROUP BY check_name`},
	}
	for _, g := range groups {
		if err := s.countBy(ctx, g.sql, *g.dst); err != nil {
			return st, err
		}
	}
	return st, nil
}

func (s *Store) countBy(ctx context.Context, sql string, dst map[string]int) error {
	rows, err := s.pool.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		dst[k] = n
	}
	return rows.Err()
}
