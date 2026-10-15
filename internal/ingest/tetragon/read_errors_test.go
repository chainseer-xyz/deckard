package tetragon

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
)

type erroredReadChunk struct {
	data string
	err  error
}

// A Reader may return bytes and a non-EOF error together. Keep that boundary
// intact rather than using MultiReader, which can defer the error to a new Read.
type erroredChunkReader struct{ chunks []erroredReadChunk }

func (r *erroredChunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := &r.chunks[0]
	n := copy(p, chunk.data)
	chunk.data = chunk.data[n:]
	if chunk.data != "" {
		return n, nil
	}
	err := chunk.err
	r.chunks = r.chunks[1:]
	return n, err
}

func TestAccumulatorReadErrorPreservesCauseAndDiscardsWholeBatch(t *testing.T) {
	transportErr := errors.New("SECRET reader transport detail")
	partial := `{"process_kprobe":{"process":{"arguments":"SECRET-RAW`
	for _, tc := range []struct {
		name   string
		chunks []erroredReadChunk
		cause  error
	}{
		{
			name:   "complete prefix and partial tail in same failed Read",
			chunks: []erroredReadChunk{{data: policyEvent + "\n" + partial, err: transportErr}},
			cause:  transportErr,
		},
		{
			name: "partial tail arrives in second failed Read",
			chunks: []erroredReadChunk{
				{data: policyEvent + "\n"},
				{data: partial, err: transportErr},
			},
			cause: transportErr,
		},
		{
			name:   "single partial record has no newline",
			chunks: []erroredReadChunk{{data: partial, err: transportErr}},
			cause:  transportErr,
		},
		{
			name:   "final valid record and transport error arrive together",
			chunks: []erroredReadChunk{{data: policyEvent, err: transportErr}},
			cause:  transportErr,
		},
		{
			name:   "newline terminated valid record still has failed transport",
			chunks: []erroredReadChunk{{data: policyEvent + "\n", err: transportErr}},
			cause:  transportErr,
		},
		{
			name:   "unexpected EOF preserves its identity before partial JSON parsing",
			chunks: []erroredReadChunk{{data: policyEvent + "\n" + partial, err: io.ErrUnexpectedEOF}},
			cause:  io.ErrUnexpectedEOF,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accumulator, err := NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
			if err != nil {
				t.Fatal(err)
			}
			// Previously successful sensors must be invalidated as well.
			if err := accumulator.AddStream(context.Background(), strings.NewReader(policyEvent)); err != nil {
				t.Fatal(err)
			}
			err = accumulator.AddStream(context.Background(), &erroredChunkReader{chunks: tc.chunks})
			assertStickyReadFailure(t, accumulator, err, tc.cause)
		})
	}
}

func assertStickyReadFailure(t *testing.T, accumulator *Accumulator, err, cause error) {
	t.Helper()
	if err == nil {
		t.Fatal("failed native stream accepted")
	}
	if !errors.Is(err, cause) {
		t.Error("AddStream lost the original reader cause")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Error("AddStream echoed sensitive reader or record contents")
	}
	findings, batchErr := accumulator.Findings()
	if findings != nil || !errors.Is(batchErr, cause) {
		t.Error("Findings must discard the whole batch and preserve the sticky cause")
	}
	if batchErr != nil && strings.Contains(batchErr.Error(), "SECRET") {
		t.Error("Findings echoed sensitive reader or record contents")
	}
	laterErr := accumulator.AddStream(context.Background(), strings.NewReader(policyEvent))
	if !errors.Is(laterErr, cause) {
		t.Error("later successful stream cleared or replaced the original failure")
	}
	if findings, finalErr := accumulator.Findings(); findings != nil || !errors.Is(finalErr, cause) {
		t.Error("later stream did not preserve the failed-batch contract")
	}
}

func TestAccumulatorRecordLimitPreservesScannerCause(t *testing.T) {
	accumulator, err := NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
	if err != nil {
		t.Fatal(err)
	}
	if err := accumulator.AddStream(context.Background(), strings.NewReader(policyEvent)); err != nil {
		t.Fatal(err)
	}
	// Just over one bounded record, not a large aggregate-log fixture.
	oversize := `{"process_exec":{"process":{"arguments":"SECRET-` + strings.Repeat("x", MaxEventBytes) + `"}}}`
	err = accumulator.AddStream(context.Background(), strings.NewReader(oversize))
	assertStickyReadFailure(t, accumulator, err, bufio.ErrTooLong)
	if err != nil && !strings.Contains(err.Error(), "record") {
		t.Error("record overflow was not classified separately from transport failure")
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		t.Error("record overflow was mislabeled as truncated transport")
	}
}

func TestAccumulatorDataAndEOFRemainsSuccessful(t *testing.T) {
	accumulator, err := NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
	if err != nil {
		t.Fatal(err)
	}
	err = accumulator.AddStream(context.Background(), &erroredChunkReader{chunks: []erroredReadChunk{{data: policyEvent, err: io.EOF}}})
	if err != nil {
		t.Fatal("ordinary EOF after a valid final record became a transport failure")
	}
	findings, err := accumulator.Findings()
	if err != nil || len(findings) != 1 {
		t.Fatal("ordinary EOF discarded a valid incident")
	}
}
