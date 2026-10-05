package postgres

import (
	"context"
	"errors"

	"github.com/chainseer-xyz/deckard/internal/store"
)

var _ store.ScanTriggerStore = (*Store)(nil)

func (s *Store) PutScanTrigger(ctx context.Context, trigger store.ScanTrigger) error {
	if trigger.Key == "" {
		return errors.New("scan trigger key is required")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO scan_triggers (key, kind, templates, cves, release)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (key) DO NOTHING`,
		trigger.Key, trigger.Kind, tagsOrEmpty(trigger.Templates), tagsOrEmpty(trigger.CVEs), trigger.Release)
	return err
}

func (s *Store) ListPendingScanTriggers(ctx context.Context, kind string) ([]store.ScanTrigger, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, kind, templates, cves, release FROM scan_triggers
		WHERE kind = $1 AND acknowledged_at IS NULL ORDER BY created_at, key`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var triggers []store.ScanTrigger
	for rows.Next() {
		var trigger store.ScanTrigger
		if err := rows.Scan(&trigger.Key, &trigger.Kind, &trigger.Templates, &trigger.CVEs, &trigger.Release); err != nil {
			return nil, err
		}
		triggers = append(triggers, trigger)
	}
	return triggers, rows.Err()
}

func (s *Store) AckScanTrigger(ctx context.Context, key string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE scan_triggers SET acknowledged_at = COALESCE(acknowledged_at, now()) WHERE key = $1`, key)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}
