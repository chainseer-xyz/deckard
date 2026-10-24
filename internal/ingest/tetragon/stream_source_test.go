package tetragon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/ingest"
)

func attributedAccumulator(t *testing.T) *Accumulator {
	t.Helper()
	a, err := NewAccumulator(ingest.ParseOptions{Scope: "k8s:uid:cluster-123"})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func identicalFailure(got, want error) bool {
	return got == want //nolint:errorlint // This contract requires the same object, not a wrapper with the same cause.
}

func TestStreamFirstOriginSurvivesSiblingCancellationAndFailure(t *testing.T) {
	a := attributedAccumulator(t)
	if err := a.AddStreamFrom(context.Background(), strings.NewReader(policyEvent), "namespace=tetragon pod=good container=export-stdout"); err != nil {
		t.Fatal(err)
	}
	source := "namespace=tetragon pod=first container=export-stdout"
	first := a.AddStreamFrom(context.Background(), strings.NewReader(`{"SECRET":`), source)
	if first == nil || !strings.Contains(first.Error(), "not valid JSON") || !strings.Contains(first.Error(), source) || strings.Contains(first.Error(), "SECRET") {
		t.Fatalf("malformed event lost its safe first origin: %v", first)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			if got := a.AddStreamFrom(ctx, unexpectedRead{t}, "pod=sibling"); !identicalFailure(got, first) {
				t.Errorf("canceled sibling replaced first failure: %v", got)
			}
			if got := a.RejectFrom("pod=other", "tetragon pod log request failed (forbidden)", errors.New("SECRET provider response")); !identicalFailure(got, first) {
				t.Errorf("HTTP sibling replaced first failure: %v", got)
			}
		})
	}
	workers.Wait()
	if findings, err := a.Findings(); findings != nil || !identicalFailure(err, first) {
		t.Fatal("first failure did not discard the whole batch")
	}
}

func TestStreamReaderCauseIsPreservedWithoutSensitiveText(t *testing.T) {
	a := attributedAccumulator(t)
	cause := errors.New("SECRET transport response")
	err := a.AddStreamFrom(context.Background(), &erroredChunkReader{chunks: []erroredReadChunk{{data: policyEvent + "\nSECRET", err: cause}}}, "pod=first")
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "pod=first") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("read failure lost origin/cause or leaked data: %v", err)
	}
	if findings, final := a.Findings(); findings != nil || !identicalFailure(final, err) {
		t.Fatal("reader failure did not remain the identical batch failure")
	}
}

func TestRequestFirstOriginWinsConcurrentRejections(t *testing.T) {
	a := attributedAccumulator(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	causes := []error{errors.New("SECRET first body"), errors.New("SECRET second body")}
	for i, source := range []string{"pod=a", "pod=b"} {
		go func() {
			<-start
			results <- a.RejectFrom(source, "tetragon pod log request failed (forbidden)", causes[i])
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first == nil || !identicalFailure(second, first) || strings.Contains(first.Error(), "SECRET") {
		t.Fatalf("simultaneous failures were relabeled or leaked causes: %v / %v", first, second)
	}
	for i, source := range []string{"pod=a", "pod=b"} {
		if strings.Contains(first.Error(), source) != errors.Is(first, causes[i]) {
			t.Fatal("winning source does not match winning cause")
		}
	}
	if findings, err := a.Findings(); findings != nil || !identicalFailure(err, first) {
		t.Fatal("concurrent request failure did not poison the batch")
	}
}

func TestStreamRejectsUnsafeSourceWithoutEchoingIt(t *testing.T) {
	for _, source := range []string{"SECRET\nforged", "SECRET\tforged", "SECRET\x00", "SECRET\xff", "SECRET\u2028forged", "SECRET\u2029forged", strings.Repeat("SECRET", 100)} {
		t.Run("invalid metadata", func(t *testing.T) {
			a := attributedAccumulator(t)
			err := a.AddStreamFrom(context.Background(), unexpectedRead{t}, source)
			if err == nil || !strings.Contains(err.Error(), "source is invalid") || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("unsafe metadata was read or echoed: %v", err)
			}
			if findings, final := a.Findings(); findings != nil || !identicalFailure(final, err) {
				t.Fatal("invalid source did not poison batch")
			}
		})
	}
}

func TestStreamQuotesBoundedSourceAndPoisonsNilReader(t *testing.T) {
	a := attributedAccumulator(t)
	source := `pod="quoted"\sensor`
	err := a.AddStreamFrom(context.Background(), nil, source)
	if err == nil || !strings.Contains(err.Error(), `source="pod=\"quoted\"\\sensor"`) {
		t.Fatalf("sensor metadata was not safely quoted: %v", err)
	}
	if findings, final := a.Findings(); findings != nil || !identicalFailure(final, err) {
		t.Fatal("nil reader did not poison the whole batch")
	}
}

type cancelingLimitReader struct {
	cancel context.CancelFunc
	cause  error
}

func (r cancelingLimitReader) Read(p []byte) (int, error) {
	r.cancel()
	return copy(p, `{"SECRET":`), r.cause
}

func TestBudgetReadFailureSurvivesConcurrentContextCancellation(t *testing.T) {
	a := attributedAccumulator(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cause := errors.New("SECRET hidden budget cause")
	limit := &ReadLimitError{LimitBytes: 1234, Cause: cause}
	err := a.AddStreamFrom(ctx, cancelingLimitReader{cancel: cancel, cause: limit}, "pod=first")
	var attributed *SourceError
	if !errors.Is(err, cause) || !errors.As(err, &attributed) || attributed.Source != "pod=first" || !strings.Contains(err.Error(), "1234 bytes") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("cancellation replaced the available budget failure: %v", err)
	}
	if got := a.RejectFrom("pod=sibling", "other failure", errors.New("other")); !identicalFailure(got, err) {
		t.Fatal("sibling replaced the original budget cap or sensor")
	}
	if findings, final := a.Findings(); findings != nil || !identicalFailure(final, err) {
		t.Fatal("budget/cancellation failure exposed prefix findings")
	}
}

func TestStreamSourceUsesExactByteBound(t *testing.T) {
	for _, size := range []int{512, 513} {
		a := attributedAccumulator(t)
		err := a.AddStreamFrom(context.Background(), strings.NewReader(policyEvent), strings.Repeat("a", size))
		if size == 512 && err != nil || size == 513 && err == nil {
			t.Fatalf("wrong source byte bound at %d: %v", size, err)
		}
	}
}
