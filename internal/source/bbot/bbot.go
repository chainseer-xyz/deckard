// Package bbot imports a local BBOT JSONL report as non-authoritative discovery.
// It never runs BBOT, contacts destinations, or declares ownership.
package bbot

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/source"
)

const (
	maxReportBytes = 64 << 20
	maxEvents      = 100000
)

// Source rereads one operator-configured local report on each discovery.
type Source struct {
	name     string
	file     string
	openFile func(string) (*os.File, error)
}

// New validates configuration without opening the report or starting a scan.
func New(cfg config.SourceConfig) (*Source, error) {
	if strings.TrimSpace(cfg.DiscoveryFile) == "" {
		return nil, errors.New("bbot: discovery_file is required")
	}
	return &Source{name: cfg.Name, file: cfg.DiscoveryFile, openFile: openReport}, nil
}

// Constructor implements the standard source registry constructor contract.
func Constructor(cfg config.SourceConfig, _ config.ScopeConfig, _ func(string) string, _ *slog.Logger) (source.Source, error) {
	return New(cfg)
}

func (s *Source) Name() string { return s.name }
func (s *Source) Type() string { return "bbot" }

// Discover is atomic from the caller's perspective: invalid or oversized input
// returns no Discovery, including assets parsed before the failure.
func (s *Source) Discover(ctx context.Context) (*source.Discovery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	openFile := s.openFile
	if openFile == nil {
		openFile = openReport
	}
	f, err := openFile(s.file)
	if err != nil {
		return nil, errors.New("bbot: cannot open discovery_file")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxReportBytes {
		return nil, errors.New("bbot: discovery_file changed or exceeds 64 MiB")
	}
	return readReport(ctx, f, s.name)
}

type event struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Module    json.RawMessage `json:"module"`
	Scan      json.RawMessage `json:"scan"`
	ID        json.RawMessage `json:"id"`
	Parent    json.RawMessage `json:"parent_uuid"`
	Timestamp json.RawMessage `json:"timestamp"`
}

func readReport(ctx context.Context, input io.Reader, name string) (*source.Discovery, error) {
	limited := &io.LimitedReader{R: input, N: maxReportBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64<<10), maxReportBytes+1)
	assets := map[string]model.AssetInput{}
	line, count := 0, 0
	for scanner.Scan() {
		line++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(strings.TrimSpace(scanner.Text())) == 0 {
			continue
		}
		count++
		if count > maxEvents {
			return nil, errors.New("bbot: report exceeds 100000 events")
		}
		a, supported, err := parseEvent(scanner.Bytes(), name)
		if err != nil {
			return nil, fmt.Errorf("bbot: invalid event at line %d", line)
		}
		if supported {
			id := string(a.Kind) + "\x00" + a.Key
			if _, exists := assets[id]; !exists {
				assets[id] = a
			}
		}
	}
	if scanner.Err() != nil || limited.N == 0 {
		return nil, errors.New("bbot: cannot read report or report exceeds 64 MiB")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return discovery(assets), nil
}

func discovery(assets map[string]model.AssetInput) *source.Discovery {
	d := &source.Discovery{Partial: true, PartialReasons: []string{
		"BBOT report import is non-authoritative; absence cannot remove assets or resolve findings",
	}}
	for _, a := range assets {
		d.Assets = append(d.Assets, a)
	}
	sort.Slice(d.Assets, func(i, j int) bool {
		if d.Assets[i].Kind != d.Assets[j].Kind {
			return d.Assets[i].Kind < d.Assets[j].Kind
		}
		return d.Assets[i].Key < d.Assets[j].Key
	})
	return d
}
