package api

import (
	"net/http"
	"sort"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

type collectorState struct {
	Tool                    string     `json:"tool"`
	Scope                   string     `json:"scope"`
	LastReport              *time.Time `json:"last_report,omitempty"`
	LastComplete            *time.Time `json:"last_complete,omitempty"`
	ExpectedIntervalSeconds float64    `json:"expected_interval_seconds"`
	Health                  string     `json:"health"`
	Coverage                string     `json:"coverage"`
	OpenFindings            int        `json:"open_findings"`
}

type producerKey struct{ tool, scope string }

func (s *Server) listCollectors(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r, "limit", "offset")
	limit, offset := q.limit(), q.offset()
	if q.reject(w) {
		return
	}
	rows, err := s.d.Store.ListIngestScopes(r.Context())
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	known := make(map[producerKey]store.IngestScope, len(rows))
	for _, row := range rows {
		known[producerKey{row.Tool, row.Scope}] = row
	}
	for _, grant := range s.d.Ingest.Credentials {
		for _, tool := range grant.Tools {
			for _, scope := range grant.Scopes {
				key := producerKey{tool, scope}
				if _, exists := known[key]; !exists {
					known[key] = store.IngestScope{Tool: tool, Scope: scope}
				}
			}
		}
	}
	items := make([]collectorState, 0, len(known))
	now := s.clock.Now()
	for _, row := range known {
		items = append(items, collectorStatus(row, s.d.Ingest.Tools[row.Tool].ExpectedReportInterval, now))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Tool != items[j].Tool {
			return items[i].Tool < items[j].Tool
		}
		return items[i].Scope < items[j].Scope
	})
	lo := min(offset, len(items))
	hi := min(lo+limit, len(items))
	writeJSON(w, http.StatusOK, newList(items[lo:hi], len(items), limit, offset))
}

func collectorStatus(row store.IngestScope, expected time.Duration, now time.Time) collectorState {
	state := collectorState{Tool: row.Tool, Scope: row.Scope, ExpectedIntervalSeconds: expected.Seconds(), Health: "never", Coverage: "never", OpenFindings: row.Open}
	if model.IsRuntimeTool(row.Tool) {
		state.Coverage = "event_only"
	} else if !row.CompleteAt.IsZero() {
		at := row.CompleteAt.UTC()
		state.LastComplete = &at
	}
	if row.LastAt.IsZero() {
		return state
	}
	at := row.LastAt.UTC()
	state.LastReport = &at
	state.Health = "reporting"
	if expected > 0 {
		state.Health = "healthy"
		if now.After(row.LastAt.Add(expected).Add(expected)) {
			state.Health = "stale"
		}
	}
	if !model.IsRuntimeTool(row.Tool) {
		state.Coverage = "incomplete"
		if !row.CompleteAt.IsZero() && !row.CompleteAt.Before(row.LastAt) {
			state.Coverage = "complete"
		}
	}
	return state
}
