package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/identity"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Runtime incidents retain their own stable metadata attachment. A Pod's
// retirement cannot resolve or hide an incident. Association is additive and
// uses the same inventory identity lock as all native/source mutations.
func runtimeRelations(ctx context.Context, tx pgx.Tx, in store.IngestInput) ([]model.RelationInput, error) {
	if !model.IsRuntimeTool(in.Tool) || len(in.Items) == 0 {
		return nil, nil
	}
	clusters, uids := []string{}, []string{}
	for _, item := range in.Items {
		cluster, _ := item.Finding.Evidence["runtime_cluster_id"].(string)
		uid, _ := item.Finding.Evidence["runtime_pod_uid"].(string)
		if cluster != "" && uid != "" {
			clusters, uids = append(clusters, cluster), append(uids, uid)
		}
	}
	if len(clusters) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+assetCols+` FROM assets a
		WHERE a.kind = 'workload' AND a.removed_at IS NULL
		AND EXISTS (SELECT 1 FROM jsonb_each(a.source_facts) f
			WHERE f.value->'attrs'->>'cluster_id' = ANY($1::text[]) AND f.value->'attrs'->>'uid' = ANY($2::text[]))
		ORDER BY a.id FOR SHARE OF a`, clusters, uids)
	if err != nil {
		return nil, fmt.Errorf("runtime identity candidates: %w", err)
	}
	assets, err := collectAssets(rows)
	if err != nil {
		return nil, err
	}
	index := identity.NewRuntimeIndex(assets)
	byID := make(map[int64]model.Asset, len(assets))
	for _, asset := range assets {
		byID[asset.ID] = asset
	}
	var relations []model.RelationInput
	for _, item := range in.Items {
		if item.Ref || item.AssetKind != model.KindCloudResource {
			continue
		}
		if id, found := index.Resolve(in.Scope, item.Finding.Evidence); found {
			relations = append(relations, model.RelationInput{FromKind: item.AssetKind, FromKey: item.AssetKey,
				ToKind: model.KindWorkload, ToKey: byID[id].Key, Type: model.RelTargets})
		}
	}
	return relations, nil
}
