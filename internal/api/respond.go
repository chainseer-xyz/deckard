package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/chainseer-xyz/deckard/internal/store"
)

// errorBody is the JSON error envelope.
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type listResponse[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

func newList[T any](items []T, total, limit, offset int) listResponse[T] {
	if items == nil {
		items = []T{}
	}
	return listResponse[T]{Items: items, Total: total, Limit: limit, Offset: offset}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: msg}})
}

// storeError maps persistence errors to HTTP responses without leaking
// internals.
func (s *Server) storeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, "timeout", "request timed out")
	case errors.Is(err, context.Canceled):
		// client went away; nothing useful to send
		writeError(w, http.StatusServiceUnavailable, "canceled", "request canceled")
	default:
		s.log.Error("store error", "request_id", requestIDFrom(r.Context()), "path", r.URL.Path, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

var errEmptyBody = errors.New("empty body")

type strictDecoder struct{ *json.Decoder }

func newStrictDecoder(r *http.Request) *strictDecoder {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return &strictDecoder{d}
}

// Decode wraps json.Decoder.Decode, mapping a wholly empty body to errEmptyBody.
func (d *strictDecoder) Decode(v any) error {
	err := d.Decoder.Decode(v)
	if errors.Is(err, io.EOF) {
		return errEmptyBody
	}
	return err
}
