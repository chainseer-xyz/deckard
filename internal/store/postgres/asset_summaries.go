package postgres

import (
	"context"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// AssetSummaries queries only the requested page's assets. The scan timestamp
// comes from durable scheduling state, independent of history retention.
func (s *Store) AssetSummaries(ctx context.Context, ids []int64) ([]store.AssetSummary, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT a.id, COALESCE(f.total, 0), COALESCE(f.top, 0), scans.last_scan
		FROM assets a
		LEFT JOIN LATERAL (SELECT count(*) AS total, max(severity_rank) AS top FROM findings
			WHERE asset_id = a.id AND status = 'open') f ON true
		LEFT JOIN LATERAL (SELECT max(last_attempt) AS last_scan FROM scan_state WHERE asset_id = a.id) scans ON true
		WHERE a.id = ANY($1::bigint[]) ORDER BY a.id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	severities := []model.Severity{model.SeverityInfo, model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical}
	var out []store.AssetSummary
	for rows.Next() {
		var v store.AssetSummary
		var top int
		if err := rows.Scan(&v.AssetID, &v.OpenFindings, &top, &v.LastScan); err != nil {
			return nil, err
		}
		v.TopSeverity = severities[top]
		out = append(out, v)
	}
	return out, rows.Err()
}
