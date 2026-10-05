package postgres

import (
	"context"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/model"
)

type relationReporter struct {
	name     string
	parentID *int64
}

func checkRelationReporter(parentID int64, origin string) relationReporter {
	return relationReporter{name: fmt.Sprintf("check:%d:%s", parentID, origin), parentID: &parentID}
}

// A removed parent cannot confirm its checks' edges again. Retire their
// registrations so a later revival cannot resurrect stale relationships to
// children kept live by another inventory source.
func dropCheckRelations(ctx context.Context, tx pgx.Tx, parents []int64) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT reporter FROM relation_reporters WHERE parent_id = ANY($1::bigint[])`, parents)
	if err != nil {
		return err
	}
	var reporters []string
	for rows.Next() {
		var reporter string
		if err := rows.Scan(&reporter); err != nil {
			rows.Close()
			return err
		}
		reporters = append(reporters, reporter)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, reporter := range reporters {
		if err := syncRelations(ctx, tx, relationReporter{name: reporter}, nil, true); err != nil {
			return err
		}
	}
	return nil
}

// syncRelations replaces one reporter's set on complete results. Partial
// snapshots and parentless discoveries only add registrations. Other reporters
// retain the relationships they still observe.
func syncRelations(ctx context.Context, tx pgx.Tx, reporter relationReporter, rels []model.RelationInput, replace bool) error {
	var from, to []int64
	var types []string
	if replace {
		rows, err := tx.Query(ctx, `DELETE FROM relation_reporters WHERE reporter = $1 RETURNING from_id, to_id, type`, reporter.name)
		if err != nil {
			return err
		}
		for rows.Next() {
			var f, t int64
			var typ string
			if err := rows.Scan(&f, &t, &typ); err != nil {
				rows.Close()
				return err
			}
			from, to, types = append(from, f), append(to, t), append(types, typ)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	if err := upsertRelations(ctx, tx, rels, reporter); err != nil {
		return err
	}
	if len(from) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `DELETE FROM relations r USING unnest($1::bigint[], $2::bigint[], $3::text[]) AS dropped(from_id, to_id, type)
		WHERE r.from_id = dropped.from_id AND r.to_id = dropped.to_id AND r.type = dropped.type
		AND NOT EXISTS (SELECT 1 FROM relation_reporters p
		    WHERE p.from_id = r.from_id AND p.to_id = r.to_id AND p.type = r.type)`, from, to, types)
	return err
}

// upsertRelations links live assets and records each observer. Sort lock
// acquisition across sources to avoid inverted order.
func upsertRelations(ctx context.Context, tx pgx.Tx, rels []model.RelationInput, reporter relationReporter) error {
	if len(rels) == 0 {
		return nil
	}
	ordered := append([]model.RelationInput(nil), rels...)
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.FromKind != b.FromKind {
			return a.FromKind < b.FromKind
		}
		if a.FromKey != b.FromKey {
			return a.FromKey < b.FromKey
		}
		if a.ToKind != b.ToKind {
			return a.ToKind < b.ToKind
		}
		if a.ToKey != b.ToKey {
			return a.ToKey < b.ToKey
		}
		return a.Type < b.Type
	})
	b := &pgx.Batch{}
	for _, r := range ordered {
		b.Queue(`INSERT INTO relations (from_id, to_id, type)
			SELECT f.id, t.id, $5 FROM assets f, assets t
			WHERE f.kind = $1 AND f.key = $2 AND t.kind = $3 AND t.key = $4
			  AND f.removed_at IS NULL AND t.removed_at IS NULL
			ON CONFLICT DO NOTHING`, r.FromKind, r.FromKey, r.ToKind, r.ToKey, r.Type)
		b.Queue(`INSERT INTO relation_reporters (from_id, to_id, type, reporter, parent_id)
			SELECT f.id, t.id, $5, $6, $7 FROM assets f, assets t
			WHERE f.kind = $1 AND f.key = $2 AND t.kind = $3 AND t.key = $4
			  AND f.removed_at IS NULL AND t.removed_at IS NULL
			ON CONFLICT DO NOTHING`, r.FromKind, r.FromKey, r.ToKind, r.ToKey, r.Type, reporter.name, reporter.parentID)
	}
	br := tx.SendBatch(ctx, b)
	for range len(ordered) * 2 {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return fmt.Errorf("upsert relation: %w", err)
		}
	}
	return br.Close()
}
