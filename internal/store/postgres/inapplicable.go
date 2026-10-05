package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// ResolveInapplicableFindings retires findings because an enabled check no
// longer applies, rather than because a skipped probe observed a clean target.
// Compare the scheduler's asset snapshot under lock: an intervening source
// update must not let a stale applicability decision resolve current findings.
func (s *Store) ResolveInapplicableFindings(ctx context.Context, asset model.Asset, check string, now time.Time) (int, error) {
	if asset.RemovedAt != nil || asset.Scope != model.ScopeOwned {
		return 0, nil
	}
	resolved := 0
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var key string
		err := tx.QueryRow(ctx, `SELECT key FROM assets
			WHERE id = $1 AND kind = $2 AND key = $3 AND attrs = $4::jsonb
			  AND source = $5 AND scope = 'owned' AND removed_at IS NULL
			  AND EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = $1
			      AND f.check_name IN ($6, $7) AND f.status <> 'resolved')
			FOR UPDATE`, asset.ID, asset.Kind, asset.Key, orEmpty(asset.Attrs), asset.Source, check, "drift."+check).Scan(&key)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $3, suppressed_until = NULL
			WHERE asset_id = $1 AND check_name IN ($2, $4) AND status <> 'resolved' RETURNING id`, asset.ID, check, now, "drift."+check)
		if err != nil {
			return err
		}
		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			f, err := getFinding(ctx, tx, id)
			if err != nil {
				return err
			}
			data := findingEventData(f)
			data["reason"] = "no_longer_applicable"
			if err := addEvent(ctx, tx, "finding_resolved", key, data, now); err != nil {
				return err
			}
		}
		resolved = len(ids)
		return nil
	})
	return resolved, err
}
