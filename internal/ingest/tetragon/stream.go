package tetragon

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
)

// MaxEventBytes bounds one native NDJSON record independently of transport and
// normalized envelope limits. Raw records are discarded after native parsing.
const MaxEventBytes = 1 << 20

// Accumulator combines native events from concurrent sensor streams. Any failed
// stream permanently invalidates the batch; no prefix findings can be returned.
// Its memory holds only one bounded record per reader and bounded incident/dedup
// state. Call Findings after all AddStream calls have returned successfully.
type Accumulator struct {
	mu      sync.Mutex // protects all batch state, including the sticky error
	options ingest.ParseOptions
	groups  map[string]*incidentGroup
	events  int
	err     error
}

func NewAccumulator(options ingest.ParseOptions) (*Accumulator, error) {
	if options.Scope == "" || len(options.Scope) > ingest.MaxScopeLen || ingest.Line(options.Scope, ingest.MaxScopeLen) != options.Scope {
		return nil, fmt.Errorf("%s requires a bounded operator-supplied scope", Tool)
	}
	return &Accumulator{options: options, groups: map[string]*incidentGroup{}}, nil
}

// AddStream consumes native NDJSON, not a JSON array. The reader must unblock
// when ctx is canceled (Kubernetes HTTP streams do). No raw read error is echoed.
func (a *Accumulator) AddStream(ctx context.Context, reader io.Reader) error {
	if err := a.preflight(ctx, reader); err != nil {
		return err
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 32<<10), MaxEventBytes+2)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return a.fail(err)
		}
		if len(scanner.Bytes()) > MaxEventBytes {
			return a.fail(errors.New("tetragon event record exceeds the limit"))
		}
		raw := bytes.Trim(scanner.Bytes(), " \t\r") // Only JSON whitespace; not form feeds or Unicode spaces.
		if len(raw) != 0 {
			if err := a.add(raw); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return a.fail(err)
	}
	if scanner.Err() != nil {
		return a.fail(errors.New("tetragon stream read failed or event record exceeds the limit"))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

func (a *Accumulator) preflight(ctx context.Context, reader io.Reader) error {
	if a == nil {
		return errors.New("tetragon event accumulator is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return a.fail(err)
	}
	if reader == nil {
		return a.fail(errors.New("tetragon event stream is unavailable"))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.groups == nil && a.err == nil {
		a.err = errors.New("tetragon event accumulator is not initialized")
	}
	return a.err
}

func (a *Accumulator) fail(err error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err == nil {
		a.err = err
	}
	return a.err
}

func (a *Accumulator) add(raw []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	if a.groups == nil {
		a.err = errors.New("tetragon event accumulator is not initialized")
		return a.err
	}
	a.events++ // Includes ordinary telemetry and duplicate records across sensors.
	if a.events > maxEvents {
		a.err = errors.New("tetragon event count exceeds the limit")
		return a.err
	}
	observed, err := parseEvent(raw, a.options)
	if err != nil {
		a.err = fmt.Errorf("tetragon event %d: %w", a.events, err)
		return a.err
	}
	if observed.finding.Key == "" {
		return nil
	}
	group := a.groups[observed.finding.Key]
	if group == nil {
		if len(a.groups) >= ingest.MaxFindings {
			a.err = errors.New("tetragon incident count exceeds the ingest limit")
			return a.err
		}
		group = &incidentGroup{finding: observed.finding, first: observed.at, last: observed.at, counts: map[string]int64{}}
		a.groups[observed.finding.Key] = group
	}
	if observed.at.Before(group.first) {
		group.first = observed.at
	}
	if observed.at.After(group.last) {
		group.last = observed.at
	}
	if observed.finding.Severity.Rank() > group.finding.Severity.Rank() {
		group.finding.Severity = observed.finding.Severity
	}
	if observed.count > group.counts[observed.id] {
		group.counts[observed.id] = observed.count
	}
	return nil
}

func (a *Accumulator) Findings() ([]ingest.Finding, error) {
	if a == nil {
		return nil, errors.New("tetragon event accumulator is unavailable")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return nil, a.err
	}
	if a.groups == nil {
		return nil, errors.New("tetragon event accumulator is not initialized")
	}
	out := make([]ingest.Finding, 0, len(a.groups))
	for _, group := range a.groups {
		var count int64
		for _, n := range group.counts {
			count += n
		}
		if count > 1000000000 {
			a.err = errors.New("tetragon batch count exceeds the limit")
			return nil, a.err
		}
		finding := group.finding
		finding.Tags = append([]string(nil), finding.Tags...)
		finding.Evidence = make(map[string]any, len(group.finding.Evidence))
		for key, value := range group.finding.Evidence {
			finding.Evidence[key] = value // Native evidence contains only scalars.
		}
		finding.Evidence["runtime_batch_count"] = count
		finding.Evidence["runtime_first_seen"] = group.first.UTC().Format(time.RFC3339Nano)
		finding.Evidence["runtime_last_seen"] = group.last.UTC().Format(time.RFC3339Nano)
		out = append(out, finding)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
