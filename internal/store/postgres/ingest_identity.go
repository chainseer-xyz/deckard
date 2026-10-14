package postgres

import (
	"context"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/identity"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Inventory facts and exact-identity attachment share one lock. Without it, a
// new conflicting claimant could arrive after an ingest's candidate query.
// Discovery network calls happen outside this database critical section.
func lockInventoryIdentity(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('deckard.inventory.identity', 0))`)
	if err != nil {
		return fmt.Errorf("inventory identity lock: %w", err)
	}
	return nil
}

// correlateIngest joins only exact, unambiguous authoritative ARNs. Native
// keys, IDs, source facts and scope remain untouched. Fingerprints still use
// the producer's stable finding key, so the next report can reattach a finding
// imported before native inventory arrived without losing its lifecycle.
func correlateIngest(ctx context.Context, tx pgx.Tx, in store.IngestInput) (store.IngestInput, []model.RelationInput, error) {
	arns := map[string]bool{}
	for _, item := range in.Items {
		if item.Ref || item.AssetKind != model.KindCloudResource {
			continue
		}
		if arn, ok := identity.FromProwler(item.AssetKey, item.Finding.Evidence); ok {
			arns[arn.String()] = true
		}
	}
	if len(arns) == 0 {
		return in, nil, nil
	}
	keys := make([]string, 0, len(arns))
	for key := range arns {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	// Lock candidates until commit. Facts cannot change between identity
	// resolution and attachment. The normal ingest retry covers lock inversions
	// with a concurrently writing inventory snapshot.
	rows, err := tx.Query(ctx, `SELECT `+assetCols+` FROM assets a
		WHERE a.kind = 'cloud_resource' AND a.removed_at IS NULL
		AND EXISTS (SELECT 1 FROM jsonb_each(a.source_facts) f WHERE f.value->'attrs'->>'arn' = ANY($1::text[]))
		ORDER BY a.id FOR UPDATE OF a`, keys)
	if err != nil {
		return in, nil, fmt.Errorf("identity candidates: %w", err)
	}
	assets, err := collectAssets(rows)
	if err != nil {
		return in, nil, err
	}
	index := identity.NewIndex(assets)
	byID := make(map[int64]model.Asset, len(assets))
	for _, asset := range assets {
		byID[asset.ID] = asset
	}
	in.Items = append([]store.IngestItem(nil), in.Items...)
	var aliases []model.RelationInput
	for i, item := range in.Items {
		if item.Ref || item.AssetKind != model.KindCloudResource {
			continue
		}
		arn, ok := identity.FromProwler(item.AssetKey, item.Finding.Evidence)
		if !ok {
			continue
		}
		id, ok := index.Resolve(arn)
		if !ok || byID[id].Key == item.AssetKey {
			continue
		}
		in.Items[i].AssetKey = byID[id].Key
		aliases = append(aliases, model.RelationInput{FromKind: model.KindCloudResource, FromKey: item.AssetKey,
			ToKind: model.KindCloudResource, ToKey: byID[id].Key, Type: model.RelAliasTo})
	}
	return in, aliases, nil
}
