package api

import (
	"github.com/chainseer-xyz/deckard/internal/store"
	"sort"
)

type sourceState struct {
	store.SyncStatus
	RemoteOnly              bool    `json:"remote_only,omitempty"`
	ExpectedIntervalSeconds float64 `json:"expected_interval_seconds,omitempty"`
}

func (s *Server) sourceStates(rows []store.SyncStatus) []sourceState {
	byName := map[string]sourceState{}
	var ordered, missing []string
	for _, row := range rows {
		if _, seen := byName[row.Source]; !seen {
			ordered = append(ordered, row.Source)
		}
		byName[row.Source] = sourceState{SyncStatus: row}
	}
	for _, cfg := range s.d.Sources {
		if _, seen := byName[cfg.Name]; !seen {
			missing = append(missing, cfg.Name)
		}
		state := byName[cfg.Name]
		state.Source, state.Type = cfg.Name, cfg.Type
		state.RemoteOnly = cfg.RemoteOnly
		state.ExpectedIntervalSeconds = cfg.ExpectedInterval(s.d.SyncInterval).Seconds()
		byName[cfg.Name] = state
	}
	all := make([]sourceState, 0, len(byName))
	sort.Strings(missing)
	for _, name := range append(ordered, missing...) {
		all = append(all, byName[name])
	}
	return all
}
