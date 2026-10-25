package tetragon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestMalformedStreamReportsOnlyRecordStructure(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		syntax            bool
	}{
		{"unfinished object with CRLF", policyEvent + "\n\n \t{\"SECRET\": \r\n", "bytes=10 offset=10 start=object_open end=other stream_line=3 stream_record=2 newline=true", true},
		{"unfinished object at EOF", `{"SECRET":`, "bytes=10 offset=10 start=object_open end=other stream_line=1 stream_record=1 newline=false", true},
		{"suffix shaped record", "\"SECRET\"}}\n", "bytes=10 offset=9 start=quote end=object_close stream_line=1 stream_record=1 newline=true", true},
		{"invalid object interior", "{\"SECRET\":!}\n", "bytes=12 offset=11 start=object_open end=object_close stream_line=1 stream_record=1 newline=true", true},
		{"array is not an event object", "[\"SECRET\"]\n", "bytes=10 offset=0 start=array_open end=array_close stream_line=1 stream_record=1 newline=true", false},
		{"null is not an event object", "null\n", "bytes=4 offset=0 start=other end=other stream_line=1 stream_record=1 newline=true", false},
		{"operational text is still rejected", "tail: SECRET\n", "bytes=12 offset=2 start=other end=other stream_line=1 stream_record=1 newline=true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := attributedAccumulator(t)
			const source = "namespace=tetragon pod=first container=export-stdout"
			err := a.AddStreamFrom(context.Background(), strings.NewReader(tc.input), source)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), source) {
				t.Fatalf("missing safe record diagnostics: %v", err)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("record diagnostics exposed an input key or value")
			}
			var syntax *json.SyntaxError
			if errors.As(err, &syntax) != tc.syntax {
				t.Fatal("record diagnostics lost the JSON syntax cause")
			}
			if findings, final := a.Findings(); findings != nil || !identicalFailure(final, err) {
				t.Fatal("malformed record exposed prefix findings or changed the first failure")
			}
		})
	}
}

func TestMalformedStreamPositionIgnoresReadBoundaries(t *testing.T) {
	a := attributedAccumulator(t)
	reader := &erroredChunkReader{chunks: []erroredReadChunk{
		{data: policyEvent}, {data: "\n\r"}, {data: "\n{\"SEC"},
		{data: "RET\":"}, {data: "\r"}, {data: "\n"},
	}}
	err := a.AddStreamFrom(context.Background(), reader, "pod=first")
	if err == nil || !strings.Contains(err.Error(), "bytes=10 offset=10 start=object_open end=other stream_line=3 stream_record=2 newline=true") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("reader chunk boundaries changed record diagnostics: %v", err)
	}
}

func TestMalformedStreamTypedCausesRetainNoPayloadText(t *testing.T) {
	const sensitiveNumber = "1234567890123456789012345678901234567890"
	a := attributedAccumulator(t)
	err := a.AddStream(context.Background(), strings.NewReader(sensitiveNumber))
	var mismatch *json.UnmarshalTypeError
	if !errors.As(err, &mismatch) || strings.Contains(mismatch.Error(), sensitiveNumber) {
		t.Fatal("typed non-object cause retained a raw payload value")
	}
	a = attributedAccumulator(t)
	err = a.AddStream(context.Background(), strings.NewReader(`{"SECRET":!}`))
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) || syntax.Offset != 11 || syntax.Error() != "" {
		t.Fatal("typed syntax cause must retain only its offset, not input-derived text")
	}
}

func TestConcurrentMalformedStreamsKeepWinningRecordPosition(t *testing.T) {
	a := attributedAccumulator(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for source, input := range map[string]string{
		"pod=a": "\n{\"SECRET\":\n",
		"pod=b": policyEvent + "\n\n{\"SECRET\":",
	} {
		go func() {
			<-start
			results <- a.AddStreamFrom(context.Background(), strings.NewReader(input), source)
		}()
	}
	close(start)
	first, second := <-results, <-results
	var source *SourceError
	if first == nil || !identicalFailure(first, second) || !errors.As(first, &source) {
		t.Fatal("concurrent malformed streams changed the first error identity")
	}
	want := map[string]string{
		"pod=a": "stream_line=2 stream_record=1 newline=true",
		"pod=b": "stream_line=3 stream_record=2 newline=false",
	}[source.Source]
	if want == "" || !strings.Contains(first.Error(), want) || strings.Contains(first.Error(), "SECRET") {
		t.Fatalf("winning source and record position disagree: %v", first)
	}
}
