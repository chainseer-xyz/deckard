package postgres

import (
	"context"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// copySourceFacts isolates the map before a writer replaces its own entry.
// Existing entries are not mutated, so their nested attributes need no copy.
func copySourceFacts(in map[string]model.SourceFact) map[string]model.SourceFact {
	out := make(map[string]model.SourceFact, len(in))
	for source, fact := range in {
		out[source] = fact
	}
	return out
}

// dropSourceFacts requires a locked live asset with another reporter. Legacy
// secondary reporters have unknown facts: promotion clears metadata rather
// than attributing the former owner's fields to the remaining authority.
func dropSourceFacts(ctx context.Context, tx pgx.Tx, a model.Asset, source string, now time.Time) (model.Asset, error) {
	rest := withoutString(a.Reporters, source)
	sort.Strings(rest)
	facts := copySourceFacts(a.SourceFacts)
	delete(facts, source)
	if a.Source == source {
		a.Source = rest[0]
		fact := facts[a.Source]
		a.Zone, a.Attrs = fact.Zone, fact.Attrs
	}
	updated, err := scanAsset(tx.QueryRow(ctx, `UPDATE assets a SET reporters = $2, source = $3, zone = $4, attrs = $5, source_facts = $6
		WHERE a.id = $1 RETURNING `+assetCols, a.ID, rest, a.Source, a.Zone, orEmpty(a.Attrs), facts))
	if err != nil {
		return model.Asset{}, err
	}
	err = addEvent(ctx, tx, "asset_changed", updated.Key, assetEventData(updated), now)
	return updated, err
}
