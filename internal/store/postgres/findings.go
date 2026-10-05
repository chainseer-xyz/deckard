package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// findingSource is a finding's source label: its own (ingested findings) or
// else its asset's.
const findingSource = `COALESCE(NULLIF(f.source, ''), a.source)`

const findingCols = `f.id, f.fingerprint, f.check_name, f.asset_id, a.key, a.zone, ` + findingSource + `, f.severity, f.title, f.description,
	f.evidence, f.remediation, f.tags, f.status, f.first_seen, f.last_seen, f.resolved_at, f.missed_runs, f.reopened_count,
	f.suppressed_until, f.suppression_note, f.ingest_scope`

const findingFrom = ` FROM findings f JOIN assets a ON a.id = f.asset_id`

func scanFinding(row pgx.Row) (model.Finding, error) {
	var f model.Finding
	var evidence map[string]any
	var tags []string
	err := row.Scan(&f.ID, &f.Fingerprint, &f.Check, &f.AssetID, &f.AssetKey, &f.Zone, &f.Source, &f.Severity, &f.Title, &f.Description,
		&evidence, &f.Remediation, &tags, &f.Status, &f.FirstSeen, &f.LastSeen, &f.ResolvedAt, &f.MissedRuns, &f.ReopenedCount,
		&f.SuppressedUntil, &f.SuppressionNote, &f.IngestScope)
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
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var assetKey string
		if err := tx.QueryRow(ctx, `SELECT key FROM assets WHERE id = $1 FOR UPDATE`, in.AssetID).Scan(&assetKey); err != nil {
			return notFound(err)
		}
		rows, err := tx.Query(ctx, `SELECT `+findingCols+findingFrom+` WHERE f.asset_id = $1 AND f.check_name = $2 ORDER BY f.id FOR UPDATE OF f`, in.AssetID, in.Check)
		if err != nil {
			return err
		}
		existing, err := collectFindings(rows)
		if err != nil {
			return err
		}
		items := make([]reconcileItem, 0, len(in.Findings))
		for _, fi := range in.Findings {
			items = append(items, reconcileItem{fp: model.Fingerprint(in.Check, assetKey, fi.Key), assetID: in.AssetID, fi: fi})
		}
		res, _, err = reconcileTx(ctx, tx, reconcileSet{
			check: in.Check, existing: existing, items: items, partial: in.PartialRun,
			resolveAfter: in.ResolveAfter, now: in.Now,
		})
		return err
	})
	return res, err
}

// reconcileItem is one reported finding resolved to its fingerprint and the
// asset it attaches to.
type reconcileItem struct {
	fp      string
	assetID int64
	fi      model.FindingInput
}

// reconcileSet is one run over one reconciliation set: the findings the set
// already holds (locked FOR UPDATE by the caller) and what the run reported.
// A built-in check's set is (asset, check); an ingest's is (check, scope).
type reconcileSet struct {
	check        string
	existing     []model.Finding
	items        []reconcileItem
	partial      bool // open/reopen/refresh only: no misses, nothing resolves
	resolveAfter int
	now          time.Time
	// Written on insert; empty for built-in checks.
	ingestScope string
	source      string
}

// reconcileCounts are the transitions a ReconcileResult does not list.
type reconcileCounts struct {
	refreshed int // known findings seen again, whatever their status
	pending   int // absent findings that missed but did not resolve yet
}

// reconcileTx is the finding lifecycle shared by built-in checks and ingest:
// new fingerprints open, resolved ones reopen, known ones refresh (operator
// statuses are kept), and unless the run is partial every unresolved finding
// of the set that the run did not report accrues a miss and resolves after
// resolveAfter consecutive misses.
func reconcileTx(ctx context.Context, tx pgx.Tx, set reconcileSet) (store.ReconcileResult, reconcileCounts, error) {
	var res store.ReconcileResult
	var cnt reconcileCounts
	resolveAfter := set.resolveAfter
	if resolveAfter < 1 {
		resolveAfter = 1
	}
	existing := make(map[string]model.Finding, len(set.existing))
	for _, f := range set.existing {
		existing[f.Fingerprint] = f
	}

	var order []string
	byFP := map[string]reconcileItem{}
	for _, it := range set.items {
		if _, dup := byFP[it.fp]; !dup {
			order = append(order, it.fp)
		}
		byFP[it.fp] = it // last duplicate wins
	}

	present := make(map[string]bool, len(order))
	for _, fp := range order {
		it := byFP[fp]
		fi := it.fi
		present[fp] = true
		old, ok := existing[fp]
		if !ok {
			var id int64
			err := tx.QueryRow(ctx, `INSERT INTO findings (fingerprint, check_name, asset_id, severity, severity_rank, title, description, evidence,
					remediation, tags, status, first_seen, last_seen, ingest_scope, source)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'open', $11, $11, $12, $13) RETURNING id`,
				fp, set.check, it.assetID, fi.Severity, fi.Severity.Rank(), fi.Title, fi.Description, orEmpty(fi.Evidence),
				fi.Remediation, tagsOrEmpty(fi.Tags), set.now, set.ingestScope, set.source).Scan(&id)
			if err != nil {
				return res, cnt, fmt.Errorf("insert finding: %w", err)
			}
			nf, err := getFinding(ctx, tx, id)
			if err != nil {
				return res, cnt, err
			}
			res.Opened = append(res.Opened, nf)
			if err := addEvent(ctx, tx, "finding_opened", nf.AssetKey, findingEventData(nf), set.now); err != nil {
				return res, cnt, err
			}
			continue
		}

		cnt.refreshed++
		status, reopened := old.Status, 0
		if old.Status == model.StatusResolved {
			status, reopened = model.StatusOpen, 1
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET severity = $2, severity_rank = $3, title = $4, description = $5, evidence = $6,
				remediation = $7, tags = $8, status = $9, last_seen = $10, missed_runs = 0,
				resolved_at = CASE WHEN $11 > 0 THEN NULL ELSE resolved_at END, reopened_count = reopened_count + $11,
				asset_id = $12
			WHERE id = $1`,
			old.ID, fi.Severity, fi.Severity.Rank(), fi.Title, fi.Description, orEmpty(fi.Evidence),
			fi.Remediation, tagsOrEmpty(fi.Tags), status, set.now, reopened, it.assetID); err != nil {
			return res, cnt, fmt.Errorf("update finding: %w", err)
		}
		nf, err := getFinding(ctx, tx, old.ID)
		if err != nil {
			return res, cnt, err
		}
		switch {
		case reopened > 0:
			res.Reopened = append(res.Reopened, nf)
			if err := addEvent(ctx, tx, "finding_reopened", nf.AssetKey, findingEventData(nf), set.now); err != nil {
				return res, cnt, err
			}
		case old.Status == model.StatusOpen:
			res.Updated = append(res.Updated, nf)
		}
	}

	if set.partial {
		return res, cnt, nil // a partial run observes only a subset: absence proves nothing
	}
	for _, old := range set.existing {
		if present[old.Fingerprint] || old.Status == model.StatusResolved {
			continue
		}
		missed := old.MissedRuns + 1
		if missed < resolveAfter {
			if _, err := tx.Exec(ctx, `UPDATE findings SET missed_runs = $2 WHERE id = $1`, old.ID, missed); err != nil {
				return res, cnt, err
			}
			cnt.pending++
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET missed_runs = $2, status = 'resolved', resolved_at = $3,
			suppressed_until = NULL WHERE id = $1`, old.ID, missed, set.now); err != nil {
			return res, cnt, err
		}
		nf, err := getFinding(ctx, tx, old.ID)
		if err != nil {
			return res, cnt, err
		}
		res.Resolved = append(res.Resolved, nf)
		if err := addEvent(ctx, tx, "finding_resolved", nf.AssetKey, findingEventData(nf), set.now); err != nil {
			return res, cnt, err
		}
	}
	return res, cnt, nil
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

// These predicates mirror the dashboard triage rules, before pagination.
const findingKEV = `(f.evidence->'kev' = 'true'::jsonb OR EXISTS (SELECT 1 FROM unnest(f.tags) tag WHERE lower(tag) = 'kev'))`
const findingAttentionRank = `CASE WHEN 'takeover' = ANY(f.tags) OR f.check_name ~* 'takeover' THEN 0
	WHEN (f.check_name ~* 'cert' AND (f.evidence ? 'not_after' OR f.evidence ? 'days_remaining'))
		OR f.title ~* '\m(expired|expires|expiring|expiry)\M' THEN 1 ELSE 2 END`

func findingGroupColumn(by string) string {
	switch by {
	case "asset":
		return "a.key"
	case "check":
		return "f.check_name"
	case "zone":
		return "a.zone"
	default:
		return ""
	}
}

func findingWhere(f store.FindingFilter) where {
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
	if f.Severity != "" {
		w.add("f.severity = ?", string(f.Severity))
	}
	if f.Check != "" {
		w.add("f.check_name = ?", f.Check)
	}
	if f.Zone != "" {
		w.add("a.zone = ?", f.Zone)
	}
	if f.Source != "" {
		w.add(findingSource+" = ?", f.Source)
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
	if f.GroupKey != nil {
		if col := findingGroupColumn(f.GroupBy); col != "" {
			w.add(col+" = ?", *f.GroupKey)
		}
	}
	if f.AttentionOnly {
		w.add("f.status = 'open' AND (f.severity_rank >= 3 OR " + findingKEV + ")")
	}
	if !f.FirstSeenAfter.IsZero() {
		w.add("f.first_seen >= ?", f.FirstSeenAfter)
	}
	return w
}

func findingOrder(f store.FindingFilter) string {
	dir := "DESC"
	if f.Direction == "asc" {
		dir = "ASC"
	}
	switch f.Sort {
	case "last_seen":
		return "f.last_seen " + dir + ", f.severity_rank DESC, f.id ASC"
	case "first_seen":
		return "f.first_seen " + dir + ", f.severity_rank DESC, f.id ASC"
	case "attention":
		return findingAttentionRank + ", f.severity_rank DESC, COALESCE(" + findingKEV + ", false) DESC, f.first_seen ASC, f.id ASC"
	default:
		return "f.severity_rank " + dir + ", f.last_seen DESC, f.id ASC"
	}
}

func (s *Store) ListFindings(ctx context.Context, f store.FindingFilter) ([]model.Finding, int, error) {
	w := findingWhere(f)
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*)`+findingFrom+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT ` + findingCols + findingFrom + w.sql() + ` ORDER BY ` + findingOrder(f)
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

// ListFindingGroups aggregates the complete filtered set, then pages groups.
// Members are fetched separately with GroupKey so one large group cannot
// produce an unbounded response.
func (s *Store) ListFindingGroups(ctx context.Context, f store.FindingFilter) ([]store.FindingGroup, int, error) {
	col := findingGroupColumn(f.GroupBy)
	if col == "" {
		return nil, 0, fmt.Errorf("invalid finding group %q", f.GroupBy)
	}
	w := findingWhere(f)
	from := findingFrom + w.sql()
	var total int
	if err := s.pool.QueryRow(ctx, "SELECT count(DISTINCT "+col+")"+from, w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	order := "max(f.severity_rank) DESC, count(*) DESC, " + col + " ASC"
	if f.Sort == "count" {
		order = "count(*) DESC, " + col + " ASC"
	}
	q := "SELECT " + col + `, count(*), max(f.severity_rank),
		count(*) FILTER (WHERE f.severity = 'info'), count(*) FILTER (WHERE f.severity = 'low'),
		count(*) FILTER (WHERE f.severity = 'medium'), count(*) FILTER (WHERE f.severity = 'high'),
		count(*) FILTER (WHERE f.severity = 'critical')` + from + " GROUP BY " + col + " ORDER BY " + order
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
	defer rows.Close()
	var out []store.FindingGroup
	severities := []model.Severity{model.SeverityInfo, model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical}
	for rows.Next() {
		var g store.FindingGroup
		var top, info, low, medium, high, critical int
		if err := rows.Scan(&g.Key, &g.Total, &top, &info, &low, &medium, &high, &critical); err != nil {
			return nil, 0, err
		}
		g.Label, g.Top = g.Key, severities[top]
		if g.Label == "" {
			g.Label = "(no zone)"
		}
		g.Counts = map[string]int{"info": info, "low": low, "medium": medium, "high": high, "critical": critical}
		out = append(out, g)
	}
	return out, total, rows.Err()
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
