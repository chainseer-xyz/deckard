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
	"unicode"
	"unicode/utf8"

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
	return a.AddStreamFrom(ctx, reader, "")
}

// AddStreamFrom attributes the first batch failure to bounded sensor metadata.
// source must contain metadata only, never event data or provider responses.
func (a *Accumulator) AddStreamFrom(ctx context.Context, reader io.Reader, source string) error {
	if err := a.preflight(ctx, reader, source); err != nil {
		return err
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 32<<10), MaxEventBytes+2)
	var position recordPosition
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		advance, token, err := bufio.ScanLines(data, atEOF)
		position.newline = advance > 0 && data[advance-1] == '\n'
		return advance, token, err
	})
	for scanner.Scan() {
		// Scanner can emit buffered data after a non-EOF reader error. Check
		// that error before parsing or cancellation can hide its original cause.
		if err := scanner.Err(); err != nil {
			return a.failFrom(source, &streamReadError{cause: err})
		}
		if err := ctx.Err(); err != nil {
			return a.failFrom(source, err)
		}
		if len(scanner.Bytes()) > MaxEventBytes {
			return a.failFrom(source, errors.New("tetragon event record exceeds the limit"))
		}
		position.line++
		raw := bytes.Trim(scanner.Bytes(), " \t\r") // Only JSON whitespace; not form feeds or Unicode spaces.
		if len(raw) != 0 {
			position.record++
			if err := a.addFrom(raw, source, position); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return a.failFrom(source, &streamReadError{cause: err})
	}
	if err := ctx.Err(); err != nil {
		return a.failFrom(source, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

// Preserve machine-readable causes without echoing provider response bodies or
// process data in CLI errors. Callers can distinguish their own bounded errors.
type streamReadError struct{ cause error }

func (e *streamReadError) Error() string {
	var limit *ReadLimitError
	if errors.As(e.cause, &limit) {
		return limit.Error()
	}
	if errors.Is(e.cause, bufio.ErrTooLong) {
		return "tetragon event record exceeds the limit"
	}
	if errors.Is(e.cause, io.ErrUnexpectedEOF) {
		return "tetragon log transport ended unexpectedly"
	}
	return "tetragon stream read failed"
}

func (e *streamReadError) Unwrap() error { return e.cause }

// ReadLimitError carries a transport budget without printing its hidden cause.
// Aggregate identifies the shared batch budget, not volume from one sensor.
type ReadLimitError struct {
	LimitBytes int64
	Aggregate  bool
	Cause      error
}

func (e *ReadLimitError) Error() string {
	if e.Aggregate {
		return fmt.Sprintf("tetragon aggregate log bound exceeded (%d bytes, across all selected sensors)", e.LimitBytes)
	}
	return fmt.Sprintf("tetragon per-pod log bound exceeded (%d bytes)", e.LimitBytes)
}

func (e *ReadLimitError) Unwrap() error { return e.Cause }

// SourceError preserves the first failing stream and its machine-readable cause.
// Error deliberately prints only a safe message and quoted metadata.
type SourceError struct {
	Source  string
	message string
	cause   error
}

func (e *SourceError) Error() string {
	if e.Source == "" {
		return e.message
	}
	return fmt.Sprintf("%s (source=%q)", e.message, e.Source)
}

func (e *SourceError) Unwrap() error { return e.cause }

// RejectFrom poisons the batch on failures before a stream opens. safeMessage
// must be fixed, non-sensitive diagnostic text; cause.Error is never rendered.
// Every caller receives the identical first error, including canceled siblings.
func (a *Accumulator) RejectFrom(source, safeMessage string, cause error) error {
	if a == nil {
		return errors.New("tetragon event accumulator is unavailable")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rejectLocked(source, safeMessage, cause)
}

func boundedDiagnostic(value string) bool {
	if len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

// Caller holds mu. Source attribution happens only when the first error is set.
func (a *Accumulator) rejectLocked(source, message string, cause error) error {
	if a.err == nil {
		if !boundedDiagnostic(source) {
			source, message = "", "tetragon stream source is invalid"
		} else if message == "" || !boundedDiagnostic(message) {
			message = "tetragon stream failed"
		}
		a.err = &SourceError{Source: source, message: message, cause: cause}
	}
	return a.err
}

func (a *Accumulator) preflight(ctx context.Context, reader io.Reader, source string) error {
	if a == nil {
		return errors.New("tetragon event accumulator is unavailable")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	var err error
	switch {
	case !boundedDiagnostic(source):
		err = errors.New("tetragon stream source is invalid")
	case ctx.Err() != nil:
		err = ctx.Err()
	case reader == nil:
		err = errors.New("tetragon event stream is unavailable")
	case a.groups == nil:
		err = errors.New("tetragon event accumulator is not initialized")
	}
	if err != nil {
		return a.rejectLocked(source, err.Error(), err)
	}
	return nil
}

// Only package-owned safe errors enter here; raw reader errors use streamReadError.
func (a *Accumulator) failFrom(source string, err error) error {
	return a.RejectFrom(source, err.Error(), err)
}

func (a *Accumulator) add(raw []byte) error {
	return a.addFrom(raw, "", recordPosition{})
}

func (a *Accumulator) addFrom(raw []byte, source string, position recordPosition) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	if a.groups == nil {
		return a.rejectLocked(source, "tetragon event accumulator is not initialized", nil)
	}
	a.events++ // Includes ordinary telemetry and duplicate records across sensors.
	if a.events > maxEvents {
		return a.rejectLocked(source, "tetragon event count exceeds the limit across all selected sensors", nil)
	}
	observed, err := parseEvent(raw, a.options)
	if err != nil {
		var malformed *malformedRecordError
		if errors.As(err, &malformed) {
			malformed.position = position
		}
		return a.rejectLocked(source, fmt.Sprintf("tetragon event %d: %s", a.events, err), err)
	}
	if observed.finding.Key == "" {
		return nil
	}
	group := a.groups[observed.finding.Key]
	if group == nil {
		if len(a.groups) >= ingest.MaxFindings {
			return a.rejectLocked(source, "tetragon incident count exceeds the ingest limit across all selected sensors", nil)
		}
		group = &incidentGroup{finding: observed.finding, first: observed.at, last: observed.at, counts: map[string]int64{}}
		a.groups[observed.finding.Key] = group
	}
	group.observePodName(observed.finding.Evidence)
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
