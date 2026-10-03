package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

const assetCols = `a.id, a.kind, a.key, a.source, a.scope, a.zone, a.attrs, a.first_seen, a.last_seen, a.removed_at`

func scanAsset(row pgx.Row) (model.Asset, error) {
	var a model.Asset
	var attrs map[string]any
	err := row.Scan(&a.ID, &a.Kind, &a.Key, &a.Source, &a.Scope, &a.Zone, &attrs, &a.FirstSeen, &a.LastSeen, &a.RemovedAt)
	a.Attrs = nilIfEmpty(attrs)
	return a, err
}

func collectAssets(rows pgx.Rows) ([]model.Asset, error) {
	defer rows.Close()
	var out []model.Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// defaultDiscoverySource owns assets handed to AddDiscovered without a source.
const defaultDiscoverySource = "discovered"

func (s *Store) ApplySnapshot(ctx context.Context, source string, assets []store.AssetUpsert, rels []model.RelationInput, now time.Time) (store.InventoryDiff, error) {
	return s.applySnapshot(ctx, source, assets, rels, now, true)
}

func (s *Store) UpsertSnapshot(ctx context.Context, source string, assets []store.AssetUpsert, rels []model.RelationInput, now time.Time) (store.InventoryDiff, error) {
	return s.applySnapshot(ctx, source, assets, rels, now, false)
}

func (s *Store) applySnapshot(ctx context.Context, source string, assets []store.AssetUpsert, rels []model.RelationInput, now time.Time, remove bool) (store.InventoryDiff, error) {
	var diff store.InventoryDiff
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		d, seen, err := upsertAssets(ctx, tx, modeSnapshot, source, assets, now)
		if err != nil {
			return err
		}
		diff = d
		if err := upsertRelations(ctx, tx, rels); err != nil {
			return err
		}
		if !remove {
			return nil
		}
		// Sources that stop reporting an asset drop out of its reporter set.
		// It is removed only when no source reports it any more; if the owner
		// stopped but another source still reports it, ownership moves to that
		// source (its next sync refreshes attrs).
		rows, err := tx.Query(ctx, `SELECT `+assetCols+`, a.reporters FROM assets a
			WHERE $1 = ANY(a.reporters) AND a.removed_at IS NULL AND a.id <> ALL($2::bigint[]) ORDER BY a.id FOR UPDATE`, source, seen)
		if err != nil {
			return err
		}
		var stale []model.Asset
		var staleRep [][]string
		for rows.Next() {
			var reps []string
			var attrs map[string]any
			var a model.Asset
			if err := rows.Scan(&a.ID, &a.Kind, &a.Key, &a.Source, &a.Scope, &a.Zone, &attrs, &a.FirstSeen, &a.LastSeen, &a.RemovedAt, &reps); err != nil {
				rows.Close()
				return err
			}
			a.Attrs = nilIfEmpty(attrs)
			stale = append(stale, a)
			staleRep = append(staleRep, reps)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		var gone []model.Asset
		for i, a := range stale {
			rest := withoutString(staleRep[i], source)
			if len(rest) == 0 {
				gone = append(gone, a)
				continue
			}
			sort.Strings(rest)
			newSource := a.Source
			if newSource == source {
				newSource = rest[0]
			}
			if _, err := tx.Exec(ctx, `UPDATE assets SET reporters = $2, source = $3 WHERE id = $1`, a.ID, rest, newSource); err != nil {
				return err
			}
		}
		removed, err := removeAssets(ctx, tx, gone, now)
		if err != nil {
			return err
		}
		diff.Removed = removed
		return nil
	})
	return diff, err
}

func (s *Store) AddDiscovered(ctx context.Context, assets []store.AssetUpsert, rels []model.RelationInput, now time.Time) (store.InventoryDiff, error) {
	var diff store.InventoryDiff
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		d, _, err := upsertAssets(ctx, tx, modeDiscover, "", assets, now)
		if err != nil {
			return err
		}
		diff = d
		return upsertRelations(ctx, tx, rels)
	})
	return diff, err
}

// removeAssets marks the given live assets removed, records asset_removed
// events and resolves their open/acknowledged findings, all in tx.
// Suppressed and false_positive findings keep their status (the operator's
// decision survives) but ListFindings hides them while the asset is removed.
func removeAssets(ctx context.Context, tx pgx.Tx, in []model.Asset, now time.Time) ([]model.Asset, error) {
	if len(in) == 0 {
		return nil, nil
	}
	ids := make([]int64, len(in))
	for i, a := range in {
		ids[i] = a.ID
	}
	rows, err := tx.Query(ctx, `UPDATE assets a SET removed_at = $2, reporters = '{}' WHERE a.id = ANY($1::bigint[]) AND a.removed_at IS NULL
		RETURNING `+assetCols, ids, now)
	if err != nil {
		return nil, err
	}
	removed, err := collectAssets(rows)
	if err != nil {
		return nil, err
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i].ID < removed[j].ID })
	for _, a := range removed {
		if err := addEvent(ctx, tx, "asset_removed", a.Key, assetEventData(a), now); err != nil {
			return nil, err
		}
	}
	if err := resolveFindings(ctx, tx, ids, now); err != nil {
		return nil, err
	}

	// Derivation registrations die with the asset: a removed asset is never
	// scanned again, so ReplaceDerived can never drop or confirm what it
	// registered — without this its derived children would stay live (and
	// keep being scheduled) forever, and the stale rows would veto the
	// orphan GC when another parent drops the same child. Children left
	// without any registration are orphans and are removed recursively,
	// exactly as a live parent dropping them would remove them.
	drows, err := tx.Query(ctx, `DELETE FROM derivations WHERE parent_id = ANY($1::bigint[]) OR child_id = ANY($1::bigint[])
		RETURNING child_id`, ids)
	if err != nil {
		return nil, err
	}
	children := map[int64]bool{}
	for drows.Next() {
		var id int64
		if err := drows.Scan(&id); err != nil {
			drows.Close()
			return nil, err
		}
		children[id] = true
	}
	drows.Close()
	if err := drows.Err(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		delete(children, id) // already removed above
	}
	if len(children) == 0 {
		return removed, nil
	}
	cids := make([]int64, 0, len(children))
	for id := range children {
		cids = append(cids, id)
	}
	orows, err := tx.Query(ctx, `SELECT `+assetCols+` FROM assets a
		WHERE a.id = ANY($1::bigint[]) AND a.removed_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM derivations d WHERE d.child_id = a.id)
		ORDER BY a.id FOR UPDATE`, cids)
	if err != nil {
		return nil, err
	}
	cands, err := collectAssets(orows)
	if err != nil {
		return nil, err
	}
	var orphans []model.Asset
	for _, a := range cands {
		if store.IsDerivedSource(a.Source) {
			orphans = append(orphans, a)
		}
	}
	if len(orphans) == 0 {
		return removed, nil
	}
	cascade, err := removeAssets(ctx, tx, orphans, now)
	if err != nil {
		return nil, err
	}
	return append(removed, cascade...), nil
}

// resolveFindings resolves open findings when an asset is no longer in the
// operator's owned scope. A partial source sync cannot cause this transition,
// because it retains the previous ownership registrations and never calls this
// with an incomplete asset classification.
func resolveFindings(ctx context.Context, tx pgx.Tx, ids []int64, now time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	fr, err := tx.Query(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, suppressed_until = NULL, suppression_note = ''
		WHERE asset_id = ANY($1::bigint[]) AND status IN ('open', 'acknowledged') RETURNING id`, ids, now)
	if err != nil {
		return err
	}
	var fids []int64
	for fr.Next() {
		var id int64
		if err := fr.Scan(&id); err != nil {
			fr.Close()
			return err
		}
		fids = append(fids, id)
	}
	fr.Close()
	if err := fr.Err(); err != nil {
		return err
	}
	sort.Slice(fids, func(i, j int) bool { return fids[i] < fids[j] })
	for _, id := range fids {
		nf, err := getFinding(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := addEvent(ctx, tx, "finding_resolved", nf.AssetKey, findingEventData(nf), now); err != nil {
			return err
		}
	}
	return nil
}

// ReplaceDerived: see store.Store.
func (s *Store) ReplaceDerived(ctx context.Context, assetID int64, origin string, assets []store.AssetUpsert, rels []model.RelationInput, now time.Time) (store.InventoryDiff, error) {
	var diff store.InventoryDiff
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var parentRemoved bool
		if err := tx.QueryRow(ctx, `SELECT removed_at IS NOT NULL FROM assets WHERE id = $1 FOR UPDATE`, assetID).Scan(&parentRemoved); err != nil {
			return notFound(err)
		}
		if parentRemoved {
			// A scan that started before its parent was removed: what it saw
			// must not revive children the removal just took down, since a
			// removed parent is never scanned again to take them back down.
			return nil
		}
		ups := make([]store.AssetUpsert, len(assets))
		for i, a := range assets {
			if a.Source == "" {
				a.Source = origin
			}
			ups[i] = a
		}
		d, seen, err := upsertAssets(ctx, tx, modeDiscover, "", ups, now)
		if err != nil {
			return err
		}
		diff = d
		if err := upsertRelations(ctx, tx, rels); err != nil {
			return err
		}
		keep := make([]int64, 0, len(seen))
		for _, id := range seen {
			if id != assetID {
				keep = append(keep, id)
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO derivations (child_id, parent_id, origin)
			SELECT unnest($1::bigint[]), $2, $3 ON CONFLICT DO NOTHING`, keep, assetID, origin); err != nil {
			return err
		}
		// Registrations this (parent, origin) no longer observes.
		drows, err := tx.Query(ctx, `DELETE FROM derivations WHERE parent_id = $1 AND origin = $2 AND child_id <> ALL($3::bigint[])
			RETURNING child_id`, assetID, origin, keep)
		if err != nil {
			return err
		}
		var dropped []int64
		for drows.Next() {
			var id int64
			if err := drows.Scan(&id); err != nil {
				drows.Close()
				return err
			}
			dropped = append(dropped, id)
		}
		drows.Close()
		if err := drows.Err(); err != nil {
			return err
		}
		if len(dropped) == 0 {
			return nil
		}
		// Orphans: live, still derived, observed by nobody else.
		rows, err := tx.Query(ctx, `SELECT `+assetCols+` FROM assets a
			WHERE a.id = ANY($1::bigint[]) AND a.removed_at IS NULL
			  AND NOT EXISTS (SELECT 1 FROM derivations d WHERE d.child_id = a.id)
			ORDER BY a.id FOR UPDATE`, dropped)
		if err != nil {
			return err
		}
		cands, err := collectAssets(rows)
		if err != nil {
			return err
		}
		var orphans []model.Asset
		for _, a := range cands {
			if store.IsDerivedSource(a.Source) {
				orphans = append(orphans, a)
			}
		}
		if len(orphans) == 0 {
			return nil
		}
		oids := make([]int64, len(orphans))
		for i, a := range orphans {
			oids[i] = a.ID
		}
		if _, err := tx.Exec(ctx, `DELETE FROM relations WHERE from_id = ANY($1::bigint[]) OR to_id = ANY($1::bigint[])`, oids); err != nil {
			return err
		}
		removed, err := removeAssets(ctx, tx, orphans, now)
		if err != nil {
			return err
		}
		diff.Removed = removed
		return nil
	})
	return diff, err
}

// PruneRelations: see store.Store.
func (s *Store) PruneRelations(ctx context.Context, olderThan time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM relations r WHERE EXISTS (
		SELECT 1 FROM assets a WHERE a.id IN (r.from_id, r.to_id) AND a.removed_at IS NOT NULL AND a.removed_at < $1)`, olderThan)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func assetEventData(a model.Asset) map[string]any {
	return map[string]any{"kind": string(a.Kind), "source": a.Source, "scope": string(a.Scope), "zone": a.Zone}
}

// normalizeAttrs round-trips through JSON so comparisons match what Postgres
// returns (numbers become float64, nil becomes empty).
func normalizeAttrs(m map[string]any) (map[string]any, error) {
	b, err := json.Marshal(orEmpty(m))
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

type upsertMode int

const (
	modeSnapshot upsertMode = iota // a source's complete sync; snap is the source
	modeDiscover                   // checks/expansion; each asset's own Source is the writer
)

func withoutString(in []string, drop string) []string {
	out := make([]string, 0, len(in))
	for _, x := range in {
		if x != drop {
			out = append(out, x)
		}
	}
	return out
}

func withString(in []string, add string) []string {
	for _, x := range in {
		if x == add {
			return in
		}
	}
	return append(append([]string{}, in...), add)
}

// mergeAttrs overlays in onto old per key; keys the writer does not supply are
// kept.
func mergeAttrs(old, in map[string]any) map[string]any {
	out := make(map[string]any, len(old)+len(in))
	for k, v := range old {
		out[k] = v
	}
	for k, v := range in {
		out[k] = v
	}
	return out
}

// upsertAssets writes assets inside tx and returns the diff (without
// removals) plus every touched asset id. Assets are processed in (kind,key)
// order to give concurrent writers a consistent lock order.
//
// Ownership rules (see store.IsDerivedSource):
//   - snapshot of source S: inserts are owned by S; S claims a derived asset
//     (taking source and attrs) and revives removed ones; the owner replaces
//     attrs; another source's asset is left alone and S is only recorded as an
//     additional reporter.
//   - discovery by writer W: inserts are owned by W; a derived asset merges
//     attrs per key and keeps its source; a source-owned asset is never taken
//     over or changed (except by its own source), and a source-owned asset
//     that was removed is not revived (counted in diff.Ignored).
func upsertAssets(ctx context.Context, tx pgx.Tx, mode upsertMode, snap string, in []store.AssetUpsert, now time.Time) (store.InventoryDiff, []int64, error) {
	var diff store.InventoryDiff
	type key struct {
		kind model.AssetKind
		key  string
	}
	last := make(map[key]store.AssetUpsert, len(in))
	for _, a := range in {
		last[key{a.Kind, a.Key}] = a
	}
	items := make([]store.AssetUpsert, 0, len(last))
	for _, a := range last {
		items = append(items, a)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Key < items[j].Key
	})

	seen := make([]int64, 0, len(items))
	for _, it := range items {
		writer := snap
		if mode == modeDiscover {
			if writer = it.Source; writer == "" {
				writer = defaultDiscoverySource
			}
		}
		reports := mode == modeSnapshot || !store.IsDerivedSource(writer)
		attrs, err := normalizeAttrs(it.Attrs)
		if err != nil {
			return diff, nil, fmt.Errorf("asset %s attrs: %w", it.Key, err)
		}
		insReps := []string{}
		if reports {
			insReps = []string{writer}
		}

		cur, err := scanAsset(tx.QueryRow(ctx, `INSERT INTO assets AS a (kind, key, source, scope, zone, attrs, first_seen, last_seen, reporters)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)
			ON CONFLICT (kind, key) DO NOTHING RETURNING `+assetCols,
			it.Kind, it.Key, writer, it.Scope, it.Zone, attrs, now, insReps))
		if err == nil {
			seen = append(seen, cur.ID)
			diff.Added = append(diff.Added, cur)
			if err := addEvent(ctx, tx, "asset_added", cur.Key, assetEventData(cur), now); err != nil {
				return diff, nil, err
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return diff, nil, fmt.Errorf("insert asset %s: %w", it.Key, err)
		}

		var oldReps []string
		var oldAttrs map[string]any
		var old model.Asset
		if err := tx.QueryRow(ctx, `SELECT `+assetCols+`, a.reporters FROM assets a WHERE a.kind = $1 AND a.key = $2 FOR UPDATE`, it.Kind, it.Key).
			Scan(&old.ID, &old.Kind, &old.Key, &old.Source, &old.Scope, &old.Zone, &oldAttrs, &old.FirstSeen, &old.LastSeen, &old.RemovedAt, &oldReps); err != nil {
			return diff, nil, fmt.Errorf("lock asset %s: %w", it.Key, err)
		}
		old.Attrs = nilIfEmpty(oldAttrs)

		revived := old.RemovedAt != nil
		oldDerived := store.IsDerivedSource(old.Source)
		newSource, newZone, newAttrs, reps := old.Source, old.Zone, orEmpty(old.Attrs), oldReps
		take := func() { newSource, newZone, newAttrs, reps = writer, it.Zone, attrs, []string{writer} }
		switch mode {
		case modeSnapshot:
			switch {
			case revived || oldDerived: // nobody owns it, or a source claims a derived asset
				take()
			case old.Source == writer:
				newZone, newAttrs, reps = it.Zone, attrs, withString(reps, writer)
			default:
				reps = withString(reps, writer)
			}
		case modeDiscover:
			switch {
			case revived && !oldDerived:
				diff.Ignored++
				continue
			case revived:
				newZone, newAttrs = it.Zone, attrs // fresh: stale keys from before removal are gone
			case oldDerived:
				newAttrs = mergeAttrs(old.Attrs, attrs)
				if it.Zone != "" {
					newZone = it.Zone
				}
			case old.Source == writer:
				newZone, newAttrs, reps = it.Zone, attrs, withString(reps, writer)
			}
		}
		if reps == nil {
			reps = []string{}
		}
		changed := !revived && (old.Scope != it.Scope || newSource != old.Source || !reflect.DeepEqual(orEmpty(old.Attrs), newAttrs))

		upd, err := scanAsset(tx.QueryRow(ctx, `UPDATE assets a SET source = $2, scope = $3, zone = $4, attrs = $5, last_seen = $6, removed_at = NULL, reporters = $7
			WHERE a.id = $1 RETURNING `+assetCols, old.ID, newSource, it.Scope, newZone, newAttrs, now, reps))
		if err != nil {
			return diff, nil, fmt.Errorf("update asset %s: %w", it.Key, err)
		}
		seen = append(seen, upd.ID)
		switch {
		case revived:
			diff.Revived = append(diff.Revived, upd)
			err = addEvent(ctx, tx, "asset_revived", upd.Key, assetEventData(upd), now)
		case changed:
			diff.Changed = append(diff.Changed, upd)
			err = addEvent(ctx, tx, "asset_changed", upd.Key, assetEventData(upd), now)
		}
		if err != nil {
			return diff, nil, err
		}
		if old.Scope == model.ScopeOwned && it.Scope != model.ScopeOwned {
			if err := resolveFindings(ctx, tx, []int64{upd.ID}, now); err != nil {
				return diff, nil, fmt.Errorf("resolve out-of-scope findings for %s: %w", it.Key, err)
			}
		}
	}
	return diff, seen, nil
}

// upsertRelations links existing assets. Relations whose endpoints are not in
// the inventory are skipped.
func upsertRelations(ctx context.Context, tx pgx.Tx, rels []model.RelationInput) error {
	if len(rels) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, r := range rels {
		b.Queue(`INSERT INTO relations (from_id, to_id, type)
			SELECT f.id, t.id, $5 FROM assets f, assets t
			WHERE f.kind = $1 AND f.key = $2 AND t.kind = $3 AND t.key = $4
			ON CONFLICT DO NOTHING`, r.FromKind, r.FromKey, r.ToKind, r.ToKey, r.Type)
	}
	br := tx.SendBatch(ctx, b)
	for range rels {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return fmt.Errorf("upsert relation: %w", err)
		}
	}
	return br.Close()
}

func addEvent(ctx context.Context, q querier, typ, subject string, data map[string]any, at time.Time) error {
	_, err := q.Exec(ctx, `INSERT INTO events (type, subject, data, at) VALUES ($1, $2, $3, $4)`, typ, subject, orEmpty(data), at)
	return err
}

func (s *Store) GetAsset(ctx context.Context, id int64) (*model.Asset, error) {
	a, err := scanAsset(s.pool.QueryRow(ctx, `SELECT `+assetCols+` FROM assets a WHERE a.id = $1`, id))
	if err != nil {
		return nil, notFound(err)
	}
	return &a, nil
}

func (s *Store) GetAssetByKey(ctx context.Context, kind model.AssetKind, key string) (*model.Asset, error) {
	a, err := scanAsset(s.pool.QueryRow(ctx, `SELECT `+assetCols+` FROM assets a WHERE a.kind = $1 AND a.key = $2`, kind, key))
	if err != nil {
		return nil, notFound(err)
	}
	return &a, nil
}

func (s *Store) ListAssets(ctx context.Context, f store.AssetFilter) ([]model.Asset, int, error) {
	var w where
	if f.Kind != "" {
		w.add("a.kind = ?", f.Kind)
	}
	if f.Source != "" {
		w.add("a.source = ?", f.Source)
	}
	if f.Scope != "" {
		w.add("a.scope = ?", f.Scope)
	}
	if f.Zone != "" {
		w.add("a.zone = ?", f.Zone)
	}
	if f.Query != "" {
		w.add(`a.key ILIKE ? ESCAPE '\'`, "%"+likeEscape(f.Query)+"%")
	}
	if !f.IncludeRemoved {
		w.add("a.removed_at IS NULL")
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM assets a`+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT ` + assetCols + ` FROM assets a` + w.sql() + ` ORDER BY a.kind COLLATE "C", a.key COLLATE "C"`
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
	out, err := collectAssets(rows)
	return out, total, err
}

func (s *Store) Edges(ctx context.Context, assetID int64) ([]store.Edge, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+assetCols+`, r.type, true FROM relations r JOIN assets a ON a.id = r.to_id WHERE r.from_id = $1
		UNION ALL
		SELECT `+assetCols+`, r.type, false FROM relations r JOIN assets a ON a.id = r.from_id WHERE r.to_id = $1
		ORDER BY 12 DESC, 11, 3`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Edge
	for rows.Next() {
		var e store.Edge
		var attrs map[string]any
		a := &e.Other
		if err := rows.Scan(&a.ID, &a.Kind, &a.Key, &a.Source, &a.Scope, &a.Zone, &attrs, &a.FirstSeen, &a.LastSeen, &a.RemovedAt, &e.Type, &e.Outbound); err != nil {
			return nil, err
		}
		a.Attrs = nilIfEmpty(attrs)
		out = append(out, e)
	}
	return out, rows.Err()
}
