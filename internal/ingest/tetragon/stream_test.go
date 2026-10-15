package tetragon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
)

func TestAccumulatorStreamsMatchNativeBatchAcrossConcurrentSensors(t *testing.T) {
	options := ingest.ParseOptions{Scope: "k8s:uid:cluster-123"}
	first := strings.Replace(policyEvent, `"node_name"`, `"aggregation_info":{"count":"3"},"node_name"`, 1)
	later := strings.ReplaceAll(policyEvent, "12:00:00Z", "12:01:00Z")
	later = strings.ReplaceAll(later, "KPROBE_ACTION_POST", "KPROBE_ACTION_SIGKILL")
	want, err := Parse([]byte(first+"\n"+later), options)
	if err != nil {
		t.Fatal(err)
	}
	accumulator, err := NewAccumulator(options)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			if err := accumulator.AddStream(context.Background(), strings.NewReader(later+"\n"+first+"\n")); err != nil {
				t.Errorf("stream failed: %v", err)
			}
		})
	}
	workers.Wait()
	got, err := accumulator.Findings()
	if err != nil || !reflect.DeepEqual(got, want) || got[0].Evidence["runtime_batch_count"] != int64(4) {
		t.Fatalf("streaming changed native parsing/deduplication: %+v %v", got, err)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "SECRET") {
		t.Fatal("stream accumulator retained raw event data")
	}
}

type failedStream struct{}

func (failedStream) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type unexpectedRead struct{ t *testing.T }

func (r unexpectedRead) Read([]byte) (int, error) {
	r.t.Error("canceled or already failed accumulator read another stream")
	return 0, io.EOF
}

func TestAccumulatorPreflightRejectsCanceledOrUnavailableStreams(t *testing.T) {
	options := ingest.ParseOptions{Scope: "k8s:uid:cluster-123"}
	t.Run("already canceled", func(t *testing.T) {
		accumulator, _ := NewAccumulator(options)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := accumulator.AddStream(ctx, unexpectedRead{t}); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled stream was accepted")
		}
	})
	t.Run("missing stream poisons prefix", func(t *testing.T) {
		accumulator, _ := NewAccumulator(options)
		if err := accumulator.AddStream(context.Background(), strings.NewReader(policyEvent)); err != nil {
			t.Fatal(err)
		}
		if err := accumulator.AddStream(context.Background(), nil); err == nil {
			t.Fatal("missing stream accepted")
		}
		if findings, err := accumulator.Findings(); err == nil || findings != nil {
			t.Fatal("missing stream did not invalidate prefix findings")
		}
		if err := accumulator.AddStream(context.Background(), unexpectedRead{t}); err == nil {
			t.Fatal("unavailable stream failure was cleared")
		}
	})
}

func TestAccumulatorLateFailuresPoisonWholeBatch(t *testing.T) {
	for name, suffix := range map[string]io.Reader{
		"invalid JSON":    strings.NewReader(`{"process_exec":SECRET`),
		"dropped events":  strings.NewReader(`{"rate_limit_info":{"number_of_dropped_process_events":"1"}}`),
		"throttle":        strings.NewReader(`{"process_throttle":{"type":"THROTTLE_START"}}`),
		"transport error": failedStream{},
	} {
		t.Run(name, func(t *testing.T) {
			accumulator, err := NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
			if err != nil {
				t.Fatal(err)
			}
			if err := accumulator.AddStream(context.Background(), io.MultiReader(strings.NewReader(policyEvent+"\n"), suffix)); err == nil || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("late failure was accepted or exposed raw input: %v", err)
			}
			if findings, err := accumulator.Findings(); err == nil || findings != nil {
				t.Fatal("failed stream exposed prefix findings")
			}
			if err := accumulator.AddStream(context.Background(), strings.NewReader(policyEvent)); err == nil {
				t.Fatal("later valid stream cleared a prior failure")
			}
		})
	}
}

func TestAccumulatorRejectsWhitespaceThatIsNotValidJSON(t *testing.T) {
	for _, raw := range []string{"\f", "\v", "\u00a0", "\f" + policyEvent, policyEvent + "\v"} {
		accumulator, err := NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
		if err != nil {
			t.Fatal(err)
		}
		if err := accumulator.AddStream(context.Background(), strings.NewReader(raw)); err == nil {
			t.Fatal("non-JSON whitespace silently accepted")
		}
		if findings, err := accumulator.Findings(); err == nil || findings != nil {
			t.Fatal("invalid whitespace exposed accepted findings")
		}
	}
}

func TestAccumulatorRecordLimitIncludesJSONWhitespace(t *testing.T) {
	accumulator, err := NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
	if err != nil {
		t.Fatal(err)
	}
	if err := accumulator.AddStream(context.Background(), strings.NewReader(strings.Repeat(" ", MaxEventBytes))); err != nil {
		t.Fatalf("exact record bound rejected: %v", err)
	}
	if err := accumulator.AddStream(context.Background(), strings.NewReader(strings.Repeat(" ", MaxEventBytes+1))); err == nil {
		t.Fatal("oversized whitespace-only record bypassed the raw record bound")
	}
	if findings, err := accumulator.Findings(); err == nil || findings != nil {
		t.Fatal("oversized whitespace record exposed an accepted batch")
	}
}

func TestAccumulatorRecordLimitIncludesTelemetryFromEveryStream(t *testing.T) {
	accumulator, err := NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
	if err != nil {
		t.Fatal(err)
	}
	telemetry := `{"process_exec":{"process":{}}}` + "\n"
	for range 2 {
		if err := accumulator.AddStream(context.Background(), strings.NewReader(strings.Repeat(telemetry, 50000))); err != nil {
			t.Fatalf("100000-record exact boundary rejected: %v", err)
		}
	}
	if findings, err := accumulator.Findings(); err != nil || findings == nil || len(findings) != 0 {
		t.Fatal("ordinary telemetry changed incident coverage")
	}
	if err := accumulator.AddStream(context.Background(), strings.NewReader(telemetry)); err == nil || !strings.Contains(err.Error(), "event count") {
		t.Fatalf("global record cap was reset for a new sensor: %v", err)
	}
	if findings, err := accumulator.Findings(); err == nil || findings != nil {
		t.Fatal("overflow exposed an accepted batch")
	}
}

func TestAccumulatorIncidentLimitIsGlobalAcrossSensors(t *testing.T) {
	accumulator, err := NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
	if err != nil {
		t.Fatal(err)
	}
	for sensor := range 2 {
		var stream strings.Builder
		for i := range 2500 {
			stream.WriteString(strings.ReplaceAll(policyEvent, "sensitive-file-write", fmt.Sprintf("rule-%d", sensor*2500+i)))
			stream.WriteByte('\n')
		}
		if err := accumulator.AddStream(context.Background(), strings.NewReader(stream.String())); err != nil {
			t.Fatalf("5000-incident exact boundary rejected: %v", err)
		}
	}
	if findings, err := accumulator.Findings(); err != nil || len(findings) != 5000 {
		t.Fatalf("bounded incidents lost: count=%d err=%v", len(findings), err)
	}
	if err := accumulator.AddStream(context.Background(), strings.NewReader(policyEvent)); err == nil || !strings.Contains(err.Error(), "incident count") {
		t.Fatalf("global incident cap was reset for a new sensor: %v", err)
	}
	if findings, err := accumulator.Findings(); err == nil || findings != nil {
		t.Fatal("overflow exposed prefix incidents")
	}
}

func TestAccumulatorBoundsOneRecordAndPreservesCancellation(t *testing.T) {
	accumulator, err := NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
	if err != nil {
		t.Fatal(err)
	}
	oversize := `{"process_exec":{"process":{"arguments":"SECRET` + strings.Repeat("x", MaxEventBytes) + `"}}}`
	if err := accumulator.AddStream(context.Background(), strings.NewReader(policyEvent+"\n"+oversize)); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unbounded record accepted or echoed: %v", err)
	}
	if findings, err := accumulator.Findings(); err == nil || findings != nil {
		t.Fatal("oversized event exposed prefix findings")
	}
	accumulator, _ = NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := accumulator.AddStream(ctx, strings.NewReader(policyEvent)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if findings, err := accumulator.Findings(); !errors.Is(err, context.Canceled) || findings != nil {
		t.Fatal("canceled stream exposed an accepted batch")
	}
}

func TestAccumulatorReturnedFindingsDoNotAliasState(t *testing.T) {
	accumulator, err := NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
	if err != nil {
		t.Fatal(err)
	}
	if err := accumulator.AddStream(context.Background(), strings.NewReader(policyEvent)); err != nil {
		t.Fatal(err)
	}
	first, _ := accumulator.Findings()
	first[0].Evidence["runtime_rule"] = "changed"
	first[0].Tags[0] = "changed"
	second, err := accumulator.Findings()
	if err != nil || second[0].Evidence["runtime_rule"] != "sensitive-file-write" || second[0].Tags[0] == "changed" {
		t.Fatal("caller mutated accumulator state")
	}
}

func FuzzAccumulatorNativeStreams(f *testing.F) {
	for _, seed := range []string{policyEvent, policyEvent + "\n" + policyEvent, "", "{}", `{"process_throttle":{}}`, `{"process_exec":{"process":{}}}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxEventBytes {
			return
		}
		options := ingest.ParseOptions{Scope: "k8s:uid:cluster-123"}
		accumulator, _ := NewAccumulator(options)
		streamErr := accumulator.AddStream(context.Background(), strings.NewReader(string(data)))
		findings, err := accumulator.Findings()
		if streamErr != nil {
			if err == nil || findings != nil {
				t.Fatal("failed native stream exposed a prefix report")
			}
			return
		}
		want, parseErr := Parse(data, options)
		if err != nil || parseErr != nil || !reflect.DeepEqual(findings, want) {
			t.Fatalf("native stream differs from standalone parser: stream=%v parse=%v", err, parseErr)
		}
	})
}
