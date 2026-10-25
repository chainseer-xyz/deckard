package tetragon

import (
	"encoding/json"
	"errors"
	"fmt"
)

// These positions belong to one sensor stream, unlike the batch's interleaved
// event counter. A final record without a newline does not prove truncation.
type recordPosition struct {
	line, record int
	newline      bool
}

// Keep typed parser details without retaining its input-derived error text.
// This error retains no payload, keys, excerpts or content-derived identifiers.
type malformedRecordError struct {
	size, offset int64
	start, end   string
	position     recordPosition
	cause        error
}

func malformedRecord(data []byte, cause error) *malformedRecordError {
	e := &malformedRecordError{size: int64(len(data)), start: "empty", end: "empty"}
	if len(data) != 0 {
		e.start, e.end = boundaryClass(data[0]), boundaryClass(data[len(data)-1])
	}
	var syntax *json.SyntaxError
	if errors.As(cause, &syntax) {
		e.offset = syntax.Offset // One-based byte offset; zero means unavailable.
		e.cause = &json.SyntaxError{Offset: syntax.Offset}
	} else {
		var mismatch *json.UnmarshalTypeError
		if errors.As(cause, &mismatch) {
			e.cause = &json.UnmarshalTypeError{Value: "non-object", Type: mismatch.Type, Offset: mismatch.Offset}
		}
	}
	return e
}

func (e *malformedRecordError) Error() string {
	structure := fmt.Sprintf("bytes=%d offset=%d start=%s end=%s", e.size, e.offset, e.start, e.end)
	if e.position.line != 0 {
		structure += fmt.Sprintf(" stream_line=%d stream_record=%d newline=%t", e.position.line, e.position.record, e.position.newline)
	}
	return "tetragon event is not valid JSON (" + structure + ")"
}

func (e *malformedRecordError) Unwrap() error { return e.cause }

// Categories describe only the first/last byte. Balanced endpoints do not prove
// valid JSON, and a closing endpoint alone does not prove a rotated fragment.
func boundaryClass(b byte) string {
	switch b {
	case '{':
		return "object_open"
	case '}':
		return "object_close"
	case '[':
		return "array_open"
	case ']':
		return "array_close"
	case '"':
		return "quote"
	default:
		return "other"
	}
}
