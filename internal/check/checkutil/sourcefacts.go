package checkutil

import (
	"slices"

	"github.com/chainseer-xyz/deckard/internal/model"
)

type attributedFact struct {
	source string
	model.SourceFact
}

// assetFacts returns current reporters' facts in a deterministic order. Only
// the canonical source can fall back to legacy attributes. Unknown secondary
// metadata must never inherit another source's claims.
func assetFacts(a model.Asset) []attributedFact {
	sources := append([]string(nil), a.Reporters...)
	slices.Sort(sources)
	if len(sources) == 0 || slices.Contains(sources, a.Source) {
		sources = append([]string{a.Source}, sources...)
	}
	seen := make(map[string]bool, len(sources))
	facts := make([]attributedFact, 0, len(sources))
	for _, source := range sources {
		if seen[source] {
			continue
		}
		seen[source] = true
		fact, ok := a.SourceFacts[source]
		if !ok {
			if source != a.Source {
				continue
			}
			fact = model.SourceFact{Zone: a.Zone, Attrs: a.Attrs}
		}
		facts = append(facts, attributedFact{source: source, SourceFact: fact})
	}
	return facts
}

// BoolAttribute returns an agreed boolean and a source that reported it.
// Conflicting source values remain unknown rather than depending on arrival order.
// Conflicts differ from absent facts: callers must not treat them as clean evidence.
// This is metadata, not an ownership decision.
func BoolAttribute(a model.Asset, key string) (value bool, source string, known, conflict bool) {
	for _, fact := range assetFacts(a) {
		v, ok := fact.Attrs[key].(bool)
		if !ok {
			continue
		}
		if known && v != value {
			return false, "", false, true
		}
		if !known {
			value, source, known = v, fact.source, true
		}
	}
	return value, source, known, false
}

// AnyAttributeTrue reports positive evidence from any current source. Callers
// must independently enforce scope; this must not establish ownership.
func AnyAttributeTrue(a model.Asset, key string) bool {
	for _, fact := range assetFacts(a) {
		if v, _ := fact.Attrs[key].(bool); v {
			return true
		}
	}
	return false
}

// AssetZone returns the most specific reported zone containing a hostname.
// Non-hostname assets retain their canonical zone.
func AssetZone(a model.Asset) string {
	if a.Kind != model.KindHostname {
		return a.Zone
	}
	zones := make([]string, 0, len(a.Reporters)+1)
	for _, fact := range assetFacts(a) {
		zones = append(zones, fact.Zone)
	}
	return ZoneOf(a.Key, zones)
}
