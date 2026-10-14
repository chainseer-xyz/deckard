package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/discoveryimport"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/go-chi/chi/v5"
)

type DiscoveryImporter interface {
	Import(context.Context, string, []byte) (store.InventoryDiff, error)
}

func (s *Server) importDiscovery(w http.ResponseWriter, r *http.Request) {
	if !s.d.Ingest.Enabled {
		writeError(w, 403, "ingest_disabled", "ingest is disabled")
		return
	}
	if s.d.Discovery == nil {
		writeError(w, 501, "not_implemented", "remote discovery is not configured")
		return
	}
	if newQuery(r).reject(w) {
		return
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.HasPrefix(ct, "application/json") && !strings.HasPrefix(ct, "application/x-ndjson") {
		writeError(w, 415, "unsupported_media_type", "use application/x-ndjson or application/json")
		return
	}
	if wait, ok := s.ing.limit.allow(identityFrom(r.Context()).Actor(), s.clock.Now()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeError(w, 429, "rate_limited", "too many producer requests")
		return
	}
	select {
	case s.ing.sem <- struct{}{}:
		defer func() { <-s.ing.sem }()
	default:
		writeError(w, 429, "busy", "too many producer requests in progress")
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, 413, "too_large", "discovery report exceeds 10 MiB")
			return
		}
		s.storeError(w, r, err)
		return
	}
	diff, err := s.d.Discovery.Import(r.Context(), chi.URLParam(r, "source"), raw)
	switch {
	case errors.Is(err, discoveryimport.ErrUnknownSource):
		writeError(w, 404, "unknown_source", "source is not configured for remote discovery")
	case errors.Is(err, discoveryimport.ErrTooLarge):
		writeError(w, 413, "too_large", "discovery report exceeds 10 MiB")
	case errors.Is(err, discoveryimport.ErrInvalidReport):
		writeError(w, 422, "invalid_report", "invalid native BBOT report; nothing was imported")
	case err != nil:
		s.storeError(w, r, err)
	default:
		writeJSON(w, 200, discoveryimport.Receipt{Source: chi.URLParam(r, "source"), Partial: true, Status: "accepted", Added: len(diff.Added), Changed: len(diff.Changed), Revived: len(diff.Revived), Ignored: diff.Ignored})
	}
}
