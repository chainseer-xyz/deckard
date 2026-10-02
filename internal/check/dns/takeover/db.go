package takeover

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"go.yaml.in/yaml/v3"
)

// fingerprints_community.yaml is the generated snapshot of the community
// database (cmd/refdata-snapshot). fingerprints.yaml stays hand-curated and
// always wins on provider-name conflicts.
//
//go:embed fingerprints_community.yaml
var embeddedCommunity []byte

// Curated returns the hand-curated embedded entries.
func Curated() []Fingerprint {
	fps, err := Load(embedded)
	if err != nil {
		panic(err) // embedded file is validated by tests
	}
	return fps
}

// CommunitySnapshot returns the embedded snapshot of converted community
// entries.
func CommunitySnapshot() []Fingerprint {
	fps, err := Load(embeddedCommunity)
	if err != nil {
		panic(err) // embedded file is validated by tests
	}
	return fps
}

// Default returns the embedded fingerprint database: the curated entries plus
// the community snapshot.
func Default() []Fingerprint { return Merge(Curated(), CommunitySnapshot()) }

// Merge returns base followed by the entries of extra whose provider name
// (case-insensitive) is not already present in base, so curated data (and its
// default_cert lists) wins on conflicts while new providers are added. Base
// entries match first in MatchCNAME. Inputs are not modified.
func Merge(base, extra []Fingerprint) []Fingerprint {
	out := make([]Fingerprint, 0, len(base)+len(extra))
	out = append(out, base...)
	seen := make(map[string]bool, len(base))
	for _, f := range base {
		seen[strings.ToLower(f.Provider)] = true
	}
	for _, f := range extra {
		if seen[strings.ToLower(f.Provider)] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Marshal renders fingerprints in the YAML schema Load reads.
func Marshal(fps []Fingerprint) ([]byte, error) {
	if fps == nil {
		fps = []Fingerprint{}
	}
	b, err := yaml.Marshal(fps)
	if err != nil {
		return nil, fmt.Errorf("takeover: marshal fingerprints: %w", err)
	}
	return b, nil
}

var (
	defaultOnce = sync.OnceValue(Default)
	liveDB      atomic.Pointer[[]Fingerprint]
)

// Fingerprints returns the live database used by checks built with New: the
// embedded data until SetFingerprints installs a refreshed one. The returned
// slice must be treated as read-only.
func Fingerprints() []Fingerprint {
	if p := liveDB.Load(); p != nil {
		return *p
	}
	return defaultOnce()
}

// SetFingerprints atomically swaps the live database. Running checks pick it
// up on their next execution. An empty set is ignored so a bad refresh can
// never leave the check without any provider.
func SetFingerprints(fps []Fingerprint) {
	if len(fps) == 0 {
		return
	}
	cp := append([]Fingerprint(nil), fps...)
	liveDB.Store(&cp)
}
