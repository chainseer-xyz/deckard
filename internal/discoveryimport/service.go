// Package discoveryimport admits remote BBOT discovery only for configured sources.
package discoveryimport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/chainseer-xyz/deckard/internal/source"
	"github.com/chainseer-xyz/deckard/internal/source/bbot"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type Inventory interface {
	Sync(context.Context, source.Source) (store.InventoryDiff, error)
}

const MaxBodyBytes = 10 << 20

// Receipt acknowledges only this source's delivery. Canonical inventory metadata
// must never be returned to a write-only producer credential.
type Receipt struct {
	Source  string `json:"source"`
	Partial bool   `json:"partial"`
	Status  string `json:"status"`
	Added   int    `json:"added"`
	Changed int    `json:"changed"`
	Revived int    `json:"revived"`
	Ignored int    `json:"ignored"`
}

var (
	ErrUnknownSource = errors.New("discovery source is not configured for remote BBOT imports")
	ErrTooLarge      = errors.New("discovery import exceeds the 10 MiB body limit")
	ErrUnavailable   = errors.New("discovery import service is unavailable")
	ErrInvalidReport = errors.New("invalid native BBOT report")
)

type Service struct {
	inventory Inventory
	allowed   map[string]bool
}

// New admits only names selected from configured remote BBOT sources by the
// application. Request data cannot create a source or impersonate an authority.
func New(inv Inventory, names []string) (*Service, error) {
	if inv == nil {
		return nil, ErrUnavailable
	}
	s := &Service{inventory: inv, allowed: make(map[string]bool, len(names))}
	for _, name := range names {
		if name == "" || len(name) > 200 || strings.TrimSpace(name) != name || !utf8.ValidString(name) || strings.HasPrefix(name, "ingest:") || s.allowed[name] {
			return nil, errors.New("discovery import source names must be unique, bounded, non-reserved identities")
		}
		for _, r := range name {
			if unicode.IsControl(r) {
				return nil, errors.New("discovery import source name contains a control character")
			}
		}
		s.allowed[name] = true
	}
	return s, nil
}

// Import uses the ordinary inventory path, including guard classification,
// per-source facts, partial-snapshot retention, and source-health recording.
func (s *Service) Import(ctx context.Context, name string, raw []byte) (store.InventoryDiff, error) {
	if err := ctx.Err(); err != nil {
		return store.InventoryDiff{}, err
	}
	if s == nil || s.inventory == nil {
		return store.InventoryDiff{}, ErrUnavailable
	}
	if !s.allowed[name] {
		return store.InventoryDiff{}, ErrUnknownSource
	}
	if len(raw) > MaxBodyBytes {
		return store.InventoryDiff{}, ErrTooLarge
	}
	return s.inventory.Sync(ctx, &remoteSource{name: name, raw: bytes.Clone(raw)})
}

type remoteSource struct {
	name string
	raw  []byte
}

func (s *remoteSource) Name() string { return s.name }
func (*remoteSource) Type() string   { return "bbot" }

func (s *remoteSource) Discover(ctx context.Context) (*source.Discovery, error) {
	d, err := bbot.Parse(ctx, bytes.NewReader(s.raw), s.name)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidReport, err)
	}
	// Reports cannot establish authoritative zones or prove absence. Keep the
	// wrapper non-authoritative even if the local parser grows new features.
	d.Partial = true
	d.Zones = nil
	return d, nil
}
