package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

const findingCols = `f.id, f.fingerprint, f.check_name, f.asset_id, a.key, a.zone, a.source, f.severity, f.title, f.description,
	f.evidence, f.remediation, f.tags, f.status, f.first_seen, f.last_seen, f.resolved_at, f.missed_runs, f.reopened_count,
	f.suppressed_until, f.suppression_note`

const findingFrom = ` FROM findings f JOIN assets a ON a.id = f.asset_id`

func scanFinding(row pgx.Row) (model.Finding, error) {
	var f model.Finding
	var evidence map[string]any
	var tags []string
	err := row.Scan(&f.ID, &f.Fingerprint, &f.Check, &f.AssetID, &f.AssetKey, &f.Zone, &f.Source, &f.Severity, &f.Title, &f.Description,
		&evidence, &f.Remediation, &tags, &f.Status, &f.FirstSeen, &f.LastSeen, &f.ResolvedAt, &f.MissedRuns, &f.ReopenedCount,
		&f.SuppressedUntil, &f.SuppressionNote)
	f.Evidence = nilIfEmpty(evidence)
	if len(tags) > 0 {
		f.Tags = tags
	}
	return f, err
}

func collectFindings(rows pgx.Rows) ([]model.Finding, error) {
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func getFinding(ctx context.Context, q querier, id int64) (model.Finding, error) {
	return scanFinding(q.QueryRow(ctx, `SELECT `+findingCols+findingFrom+` WHERE f.id = $1`, id))
}

func tagsOrEmpty(t []string) []string {
	if t == nil {
		return []string{}
	}
	return t
}

// ReconcileFindings applies one check run to one asset's findings. The asset
// row is locked for the duration so concurrent runs cannot double-insert.
//
// Misses count against every unresolved finding, including suppressed and
// false-positive ones: a fixed-but-suppressed issue resolves after
// ResolveAfter misses instead of re-alerting when the suppression expires.
// The operator's suppression note stays on the resolved finding as history.
//
// A PartialRun input never counts misses and never resolves: it can only open,
// reopen and refresh findings.
func (s *Store) ReconcileFindings(ctx context.Context, in store.ReconcileInput) (store.ReconcileResult, error) {
	var res store.ReconcileResult
	resolveAfter := in.ResolveAfter
	if resolveAfter < 1 {
		resolveAfter = 1
	}
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var assetKey string
		if err := tx.QueryRow(ctx, `SELECT key FROM assets WHERE id = $1 FOR UPDATE`, in.AssetID).Scan(&assetKey); err != nil {
			return notFound(err)
		}

		rows, err := tx.Query(ctx, `SELECT `+findingCols+findingFrom+` WHERE f.asset_id = $1 AND f.check_name = $2 ORDER BY f.id FOR UPDATE OF f`, in.AssetID, in.Check)
		if err != nil {
			return err
		}
		existingList, err := collectFindings(rows)
		if err != nil {
			return err
		}
		existing := make(map[string]model.Finding, len(existingList))
		for _, f := range existingList {
			existing[f.Fingerprint] = f
		}

		present := make(map[string]bool, len(in.Findings))
		var order []model.FindingInput
		byFP := map[string]model.FindingInput{}
		for _, fi := range in.Findings {
			fp := model.Fingerprint(in.Check, assetKey, fi.Key)
			if _, dup := byFP[fp]; !dup {
				order = append(order, fi)
			}
			byFP[fp] = fi // last duplicate wins
		}

		for _, first := range order {
			fp := model.Fingerprint(in.Check, assetKey, first.Key)
			fi := byFP[fp]
			present[fp] = true
			old, ok := existing[fp]
			if !ok {
				var id int64
				err := tx.QueryRow(ctx, `INSERT INTO findings (fingerprint, check_name, asset_id, severity, severity_rank, title, description, evidence,
						remediation, tags, status, first_seen, last_seen)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'open', $11, $11) RETURNING id`,
					fp, in.Check, in.AssetID, fi.Severity, fi.Severity.Rank(), fi.Title, fi.Description, orEmpty(fi.Evidence),
					fi.Remediation, tagsOrEmpty(fi.Tags), in.Now).Scan(&id)
				if err != nil {
					return fmt.Errorf("insert finding: %w", err)
				}
				nf, err := getFinding(ctx, tx, id)
				if err != nil {
					return err
				}
				res.Opened = append(res.Opened, nf)
				if err := addEvent(ctx, tx, "finding_opened", nf.AssetKey, findingEventData(nf), in.Now); err != nil {
					return err
				}
				continue
			}

			status, reopened := old.Status, 0
			if old.Status == model.StatusResolved {
				status, reopened = model.StatusOpen, 1
			}
			if _, err := tx.Exec(ctx, `UPDATE findings SET severity = $2, severity_rank = $3, title = $4, description = $5, evidence = $6,
					remediation = $7, tags = $8, status = $9, last_seen = $10, missed_runs = 0,
					resolved_at = CASE WHEN $11 > 0 THEN NULL ELSE resolved_at END, reopened_count = reopened_count + $11
				WHERE id = $1`,
				old.ID, fi.Severity, fi.Severity.Rank(), fi.Title, fi.Description, orEmpty(fi.Evidence),
				fi.Remediation, tagsOrEmpty(fi.Tags), status, in.Now, reopened); err != nil {
				return fmt.Errorf("update finding: %w", err)
			}
			nf, err := getFinding(ctx, tx, old.ID)
			if err != nil {
				return err
			}
			switch {
			case reopened > 0:
				res.Reopened = append(res.Reopened, nf)
				if err := addEvent(ctx, tx, "finding_reopened", nf.AssetKey, findingEventData(nf), in.Now); err != nil {
					return err
				}
			case old.Status == model.StatusOpen:
				res.Updated = append(res.Updated, nf)
			}
		}

		for _, old := range existingList {
			if in.PartialRun {
				break // a partial run observes only a subset: absence proves nothing
			}
			if present[old.Fingerprint] || old.Status == model.StatusResolved {
				continue
			}
			missed := old.MissedRuns + 1
			if missed < resolveAfter {
				if _, err := tx.Exec(ctx, `UPDATE findings SET missed_runs = $2 WHERE id = $1`, old.ID, missed); err != nil {
					return err
				}
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE findings SET missed_runs = $2, status = 'resolved', resolved_at = $3,
				suppressed_until = NULL WHERE id = $1`, old.ID, missed, in.Now); err != nil {
				return err
			}
			nf, err := getFinding(ctx, tx, old.ID)
			if err != nil {
				return err
			}
			res.Resolved = append(res.Resolved, nf)
			if err := addEvent(ctx, tx, "finding_resolved", nf.AssetKey, findingEventData(nf), in.Now); err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}

func findingEventData(f model.Finding) map[string]any {
	return map[string]any{
		"finding_id": f.ID, "check": f.Check, "severity": string(f.Severity), "title": f.Title,
		"fingerprint": f.Fingerprint, "zone": f.Zone, "source": f.Source,
	}
}

func (s *Store) GetFinding(ctx context.Context, id int64) (*model.Finding, error) {
	f, err := getFinding(ctx, s.pool, id)
	if err != nil {
		return nil, notFound(err)
	}
	return &f, nil
}

func (s *Store) ListFindings(ctx context.Context, f store.FindingFilter) ([]model.Finding, int, error) {
	var w where
	if len(f.Statuses) > 0 {
		st := make([]string, len(f.Statuses))
		for i, x := range f.Statuses {
			st[i] = string(x)
		}
		w.add("f.status = ANY(?::text[])", st)
	}
	if f.MinSeverity != "" {
		w.add("f.severity_rank >= ?", f.MinSeverity.Rank())
	}
	if f.Check != "" {
		w.add("f.check_name = ?", f.Check)
	}
	if f.Zone != "" {
		w.add("a.zone = ?", f.Zone)
	}
	if f.Source != "" {
		w.add("a.source = ?", f.Source)
	}
	if f.AssetID != 0 {
		w.add("f.asset_id = ?", f.AssetID)
	}
	if f.Query != "" {
		w.add(`(f.title ILIKE ? ESCAPE '\' OR a.key ILIKE ? ESCAPE '\')`, "%"+likeEscape(f.Query)+"%", "%"+likeEscape(f.Query)+"%")
	}
	if !f.IncludeRemovedAssets && f.AssetID == 0 {
		w.add("(a.removed_at IS NULL OR f.status = 'resolved')")
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*)`+findingFrom+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT ` + findingCols + findingFrom + w.sql() + ` ORDER BY f.severity_rank DESC, f.last_seen DESC, f.id DESC`
	args := w.args
	if f.Limit > 0 {
		args = append(args, f.Limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	if f.Offset > 0 {
		args = append(args, f.Offset)
		q += fmt.Sprintf(" OFFSET $%d", len(args))
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := collectFindings(rows)
	return out, total, err
}

func (s *Store) ChangeFindingStatus(ctx context.Context, id int64, c store.StatusChange, now time.Time) error {
	var until *time.Time
	note := c.Note
	switch c.Status {
	case model.StatusSuppressed, model.StatusAcknowledged:
		until = c.Until
	case model.StatusOpen, model.StatusResolved:
		note = ""
	}
	tag, err := s.pool.Exec(ctx, `UPDATE findings SET status = $2, suppressed_until = $3, suppression_note = $4, status_actor = $5,
			resolved_at = CASE WHEN $2 = 'resolved' THEN $6::timestamptz ELSE NULL END
		WHERE id = $1`, id, string(c.Status), until, note, c.Actor, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) ExpireSuppressions(ctx context.Context, now time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE findings SET status = 'open', suppressed_until = NULL, suppression_note = '', status_actor = ''
		WHERE status IN ('suppressed', 'acknowledged') AND suppressed_until IS NOT NULL AND suppressed_until <= $1`, now)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) ResolvedSince(ctx context.Context, t time.Time) ([]model.Finding, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+findingCols+findingFrom+` WHERE f.status = 'resolved' AND f.resolved_at >= $1
		ORDER BY f.resolved_at, f.id`, t)
	if err != nil {
		return nil, err
	}
	return collectFindings(rows)
}
