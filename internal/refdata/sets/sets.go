// Package sets defines deckard's concrete refreshable datasets and wires them
// to their consumers: the dns.takeover fingerprint database and the scope
// guard's shared-infrastructure ranges.
package sets

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check/dns/takeover"
	"github.com/chainseer-xyz/deckard/internal/refdata"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

// Dataset names (metric label and persisted file name).
const (
	TakeoverFingerprints = "takeover_fingerprints"
	SharedRanges         = "shared_ranges"
)

// Names lists every known dataset.
var Names = []string{TakeoverFingerprints, SharedRanges}

// Minimum number of entries a download must carry (counted before merging with
// the curated embedded data).
const (
	minRefreshedFingerprints = 10
	minRefreshedRanges       = 20
)

// SharedSetter is the slice of *scope.Guard the shared-ranges dataset needs.
type SharedSetter interface {
	SetSharedRanges([]netip.Prefix)
}

// Config selects and wires the datasets.
type Config struct {
	// Dir is the persistence directory ("" disables persistence).
	Dir     string
	Timeout time.Duration
	// Takeover and Shared enable the respective dataset.
	Takeover bool
	Shared   bool
	// Guard receives refreshed shared ranges (required when Shared is set).
	Guard     SharedSetter
	UserAgent string
	// Client overrides the HTTP transport (tests); redirects stay https-only.
	Client *http.Client
	Log    *slog.Logger
	Rec    refdata.Recorder
	Now    func() time.Time
	// Backoff overrides the retry base delay (tests).
	Backoff time.Duration
}

// Build returns a manager for the enabled datasets. Call Manager.Init before
// anything reads the data; it installs the persisted or embedded copy offline.
func Build(c Config) (*refdata.Manager, error) {
	f := &refdata.Fetcher{Client: c.Client, UserAgent: c.UserAgent, Timeout: c.Timeout, Backoff: c.Backoff}
	opts := refdata.Options{Dir: c.Dir, Fetcher: f, Log: c.Log, Rec: c.Rec, Now: c.Now}
	var us []refdata.Updater
	if c.Takeover {
		r, err := refdata.NewRunner(TakeoverDataset(takeover.SetFingerprints), opts)
		if err != nil {
			return nil, err
		}
		us = append(us, r)
	}
	if c.Shared {
		if c.Guard == nil {
			return nil, fmt.Errorf("sets: %s needs a scope guard", SharedRanges)
		}
		r, err := refdata.NewRunner(SharedDataset(c.Guard.SetSharedRanges), opts)
		if err != nil {
			return nil, err
		}
		us = append(us, r)
	}
	return refdata.NewManager(us...), nil
}

// How many entries of the embedded data came from a refreshable source; the
// shrink guard's baseline until the first refresh. Variables so tests can use
// small recorded fixtures.
var (
	embeddedTakeoverSourced = func() int { return len(takeover.CommunitySnapshot()) }
	embeddedSharedSourced   = func() int { n, _ := scope.EmbeddedSnapshotSize(); return n }
)

// TakeoverSet is the takeover dataset value: the merged database plus how many
// of its entries came from the refreshable community list. The shrink guard
// and minimum compare Sourced, so the (large, constant) curated part cannot
// mask a truncated download.
type TakeoverSet struct {
	Fingerprints []takeover.Fingerprint
	Sourced      int
}

// TakeoverDataset refreshes the takeover fingerprint database from the
// community list, merged with the curated embedded entries (curated wins).
func TakeoverDataset(apply func([]takeover.Fingerprint)) refdata.Dataset[TakeoverSet] {
	return refdata.Dataset[TakeoverSet]{
		Name: TakeoverFingerprints,
		URLs: []string{takeover.CommunityURL},
		Parse: func(b map[string][]byte) (TakeoverSet, error) {
			body, ok := b[takeover.CommunityURL]
			if !ok {
				return TakeoverSet{}, fmt.Errorf("community fingerprints not available")
			}
			conv, err := takeover.ConvertCommunity(body)
			if err != nil {
				return TakeoverSet{}, err
			}
			return TakeoverSet{takeover.Merge(takeover.Curated(), conv), len(conv)}, nil
		},
		Count: func(s TakeoverSet) int { return s.Sourced },
		Apply: func(s TakeoverSet) error { apply(s.Fingerprints); return nil },
		Embedded: func() (TakeoverSet, error) {
			return TakeoverSet{takeover.Default(), embeddedTakeoverSourced()}, nil
		},
		MinEntries: minRefreshedFingerprints,
	}
}

// SharedSet is the shared-ranges dataset value: the merged prefixes plus how
// many ranges came from the refreshable provider documents.
type SharedSet struct {
	Prefixes []netip.Prefix
	Sourced  int
}

// SharedDataset refreshes the shared-infrastructure ranges from the published
// provider lists, merged with the embedded list.
func SharedDataset(apply func([]netip.Prefix)) refdata.Dataset[SharedSet] {
	return refdata.Dataset[SharedSet]{
		Name: SharedRanges,
		URLs: scope.SharedSourceURLs,
		Parse: func(b map[string][]byte) (SharedSet, error) {
			ls, err := scope.ParseSharedSources(b)
			if err != nil {
				return SharedSet{}, err
			}
			emb, err := scope.EmbeddedSharedPrefixes()
			if err != nil {
				return SharedSet{}, err
			}
			return SharedSet{scope.MergeShared(emb, scope.Prefixes(ls)), len(ls)}, nil
		},
		Count: func(s SharedSet) int { return s.Sourced },
		Apply: func(s SharedSet) error { apply(s.Prefixes); return nil },
		Embedded: func() (SharedSet, error) {
			emb, err := scope.EmbeddedSharedPrefixes()
			if err != nil {
				return SharedSet{}, err
			}
			return SharedSet{scope.MergeShared(emb, nil), embeddedSharedSourced()}, nil
		},
		MinEntries: minRefreshedRanges,
	}
}
