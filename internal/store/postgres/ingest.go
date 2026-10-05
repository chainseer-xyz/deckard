package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// ingestTxAttempts bounds retries of an ingest transaction that Postgres
// aborted as a deadlock victim or a serialization failure (an ingest locks
// many asset rows, so it can collide with a source snapshot).
const ingestTxAttempts = 3

// IngestFindings applies one externally reported run for (Tool, Scope); see
// store.IngestInput for the contract. A transaction-scoped advisory lock on
// (tool, scope) serialises concurrent requests for the same pair; requests for
// other pairs run concurrently. Everything (assets, findings, events and the
// scope state) commits together or not at all.
func (s *Store) IngestFindings(ctx context.Context, in store.IngestInput) (store.IngestResult, error) {
	if in.ObservedAt.IsZero() {
		in.ObservedAt = in.Now
	}
	var res store.IngestResult
	var err error
	for attempt := 1; attempt <= ingestTxAttempts; attempt++ {
		res = store.IngestResult{}
		err = s.inTx(ctx, func(tx pgx.Tx) error { return ingestTx(ctx, tx, in, &res) })
		if !retryable(err) {
			break
		}
	}
	return res, err
}

func retryable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && (pe.Code == "40P01" || pe.Code == "40001")
}

func ingestTx(ctx context.Context, tx pgx.Tx, in store.IngestInput, res *store.IngestResult) error {
	// tool matches ^[a-z0-9][a-z0-9-]+$, so "|" cannot occur in it and the
	// lock key is unambiguous.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "deckard.ingest|"+in.Tool+"|"+in.Scope); err != nil {
		return fmt.Errorf("ingest lock: %w", err)
	}

	var lastDigest string
	var lastObserved time.Time
	known := true
	err := tx.QueryRow(ctx, `SELECT last_digest, observed_at FROM ingest_scopes WHERE tool = $1 AND scope = $2 FOR UPDATE`,
		in.Tool, in.Scope).Scan(&lastDigest, &lastObserved)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		known = false
	case err != nil:
		return fmt.Errorf("ingest state: %w", err)
	}
	if known && in.Digest != "" && in.Digest == lastDigest {
		res.Replay = true
		return nil
	}

	complete := in.Complete
	if complete && known && !in.ObservedAt.After(lastObserved) {
		complete, res.NotCompleteReason = false, "observed_at is not after the newest run already accepted for this tool and scope"
	}

	assetIDs, rejected, err := ingestAssets(ctx, tx, in)
	if err != nil {
		return err
	}
	res.Rejected = rejected
	if complete && len(rejected) > 0 {
		complete, res.NotCompleteReason = false, fmt.Sprintf("%d item(s) rejected", len(rejected))
	}
	res.Complete = complete

	rows, err := tx.Query(ctx, `SELECT `+findingCols+findingFrom+` WHERE f.check_name = $1 AND f.ingest_scope = $2 ORDER BY f.id FOR UPDATE OF f`,
		in.Check, in.Scope)
	if err != nil {
		return err
	}
	existing, err := collectFindings(rows)
	if err != nil {
		return err
	}
	items := make([]reconcileItem, 0, len(in.Items))
	for _, it := range in.Items {
		id, ok := assetIDs[it.Index]
		if !ok {
			continue // rejected
		}
		items = append(items, reconcileItem{fp: model.Fingerprint(in.Check, in.Scope, it.Finding.Key), assetID: id, fi: it.Finding})
	}
	rr, cnt, err := reconcileTx(ctx, tx, reconcileSet{
		check: in.Check, existing: existing, items: items, partial: !complete,
		resolveAfter: in.ResolveAfter, now: in.Now, ingestScope: in.Scope, source: in.Source,
	})
	if err != nil {
		return err
	}
	res.ReconcileResult, res.Refreshed, res.Pending = rr, cnt.refreshed, cnt.pending

	_, err = tx.Exec(ctx, `INSERT INTO ingest_scopes AS s (tool, scope, created_at, last_at, complete_at, observed_at, last_digest)
		VALUES ($1, $2, $3, $3, CASE WHEN $4::boolean THEN $3::timestamptz END, $5, $6)
		ON CONFLICT (tool, scope) DO UPDATE SET last_at = EXCLUDED.last_at,
			complete_at = COALESCE(EXCLUDED.complete_at, s.complete_at),
			observed_at = GREATEST(s.observed_at, EXCLUDED.observed_at),
			last_digest = EXCLUDED.last_digest`,
		in.Tool, in.Scope, in.Now, complete, in.ObservedAt, in.Digest)
	if err != nil {
		return fmt.Errorf("ingest state: %w", err)
	}
	return nil
}

// ingestAssets resolves every item's asset and returns the asset id per item
// index plus the rejected items. Assets are visited in (kind, key) order so
// concurrent writers lock rows in a consistent order.
//
//   - Ref items need an existing, live, owned asset; anything else rejects
//     the item. The row is locked FOR SHARE so it cannot be removed before
//     commit.
//   - Other items use the asset if it exists. A live asset of another source
//     is attached to untouched; one this ingest source created has its
//     last_seen refreshed and its scope class set to in.AssetScope (the
//     operator may have changed ingest.tools.<tool>.owned); a removed one is
//     revived and claimed for in.Source. A missing asset is created with
//     source in.Source and in.Source as its only reporter, so no inventory
//     source snapshot can ever remove it.
func ingestAssets(ctx context.Context, tx pgx.Tx, in store.IngestInput) (map[int]int64, []store.IngestRejection, error) {
	type akey struct {
		kind model.AssetKind
		key  string
	}
	type group struct {
		create bool
		items  []store.IngestItem
	}
	groups := map[akey]*group{}
	for _, it := range in.Items {
		k := akey{it.AssetKind, it.AssetKey}
		g := groups[k]
		if g == nil {
			g = &group{}
			groups[k] = g
		}
		g.create = g.create || !it.Ref
		g.items = append(g.items, it)
	}
	keys := make([]akey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].key < keys[j].key
	})

	ids := make(map[int]int64, len(in.Items))
	var rejected []store.IngestRejection
	reps := []string{in.Source}
	for _, k := range keys {
		g := groups[k]
		var a model.Asset
		var found bool
		if g.create {
			cur, err := scanAsset(tx.QueryRow(ctx, `INSERT INTO assets AS a (kind, key, source, scope, zone, attrs, first_seen, last_seen, reporters)
				VALUES ($1, $2, $3, $4, '', '{}'::jsonb, $5, $5, $6)
				ON CONFLICT (kind, key) DO NOTHING RETURNING `+assetCols,
				k.kind, k.key, in.Source, in.AssetScope, in.Now, reps))
			switch {
			case err == nil:
				a, found = cur, true
				if err := addEvent(ctx, tx, "asset_added", a.Key, assetEventData(a), in.Now); err != nil {
					return nil, nil, err
				}
			case !errors.Is(err, pgx.ErrNoRows):
				return nil, nil, fmt.Errorf("insert asset %s: %w", k.key, err)
			default:
				old, err := scanAsset(tx.QueryRow(ctx, `SELECT `+assetCols+` FROM assets a WHERE a.kind = $1 AND a.key = $2 FOR UPDATE`, k.kind, k.key))
				if err != nil {
					return nil, nil, fmt.Errorf("lock asset %s: %w", k.key, err)
				}
				a, found = old, true
				switch {
				case old.RemovedAt != nil:
					a, err = scanAsset(tx.QueryRow(ctx, `UPDATE assets a SET source = $2, scope = $3, last_seen = $4, removed_at = NULL, reporters = $5, source_facts = '{}'
						WHERE a.id = $1 RETURNING `+assetCols, old.ID, in.Source, in.AssetScope, in.Now, reps))
					if err == nil {
						err = addEvent(ctx, tx, "asset_revived", a.Key, assetEventData(a), in.Now)
					}
				case old.Source == in.Source:
					a, err = scanAsset(tx.QueryRow(ctx, `UPDATE assets a SET scope = $2, last_seen = $3 WHERE a.id = $1 RETURNING `+assetCols,
						old.ID, in.AssetScope, in.Now))
					if err == nil && a.Scope != old.Scope {
						err = addEvent(ctx, tx, "asset_changed", a.Key, assetEventData(a), in.Now)
					}
				}
				if err != nil {
					return nil, nil, fmt.Errorf("claim asset %s: %w", k.key, err)
				}
			}
		} else {
			cur, err := scanAsset(tx.QueryRow(ctx, `SELECT `+assetCols+` FROM assets a WHERE a.kind = $1 AND a.key = $2 FOR SHARE`, k.kind, k.key))
			switch {
			case err == nil:
				a, found = cur, true
			case !errors.Is(err, pgx.ErrNoRows):
				return nil, nil, fmt.Errorf("lock asset %s: %w", k.key, err)
			}
		}
		for _, it := range g.items {
			if reason := refProblem(it, a, found); reason != "" {
				rejected = append(rejected, store.IngestRejection{Index: it.Index, Reason: reason})
				continue
			}
			ids[it.Index] = a.ID
		}
	}
	sort.Slice(rejected, func(i, j int) bool { return rejected[i].Index < rejected[j].Index })
	return ids, rejected, nil
}

// refProblem says why a Ref item cannot attach to asset a ("" when it can).
// Non-ref items always attach.
func refProblem(it store.IngestItem, a model.Asset, found bool) string {
	switch {
	case !it.Ref:
		return ""
	case !found:
		return "asset.ref: no such asset"
	case a.RemovedAt != nil:
		return "asset.ref: asset is removed from the inventory"
	case a.Scope != model.ScopeOwned:
		return "asset.ref: asset is not owned"
	}
	return ""
}

// ListIngestScopes implements store.Store.
func (s *Store) ListIngestScopes(ctx context.Context) ([]store.IngestScope, error) {
	rows, err := s.pool.Query(ctx, `SELECT s.tool, s.scope, s.created_at, s.last_at, s.complete_at, s.observed_at,
			(SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id
			  WHERE f.check_name = $1 || s.tool AND f.ingest_scope = s.scope AND f.status = 'open' AND a.removed_at IS NULL)
		FROM ingest_scopes s ORDER BY s.tool, s.created_at, s.scope`, model.IngestCheckPrefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.IngestScope
	for rows.Next() {
		var sc store.IngestScope
		var complete *time.Time
		if err := rows.Scan(&sc.Tool, &sc.Scope, &sc.CreatedAt, &sc.LastAt, &complete, &sc.ObservedAt, &sc.Open); err != nil {
			return nil, err
		}
		if complete != nil {
			sc.CompleteAt = *complete
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}
