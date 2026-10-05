package fakestore

import (
	"context"
	"sort"
	"time"

	"github.com/chainseer-xyz/deckard/internal/store"
)

// ListEventsAfter matches the ascending ID pagination used by event streams.
func (s *Store) ListEventsAfter(_ context.Context, since time.Time, afterID int64, limit int) ([]store.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventsCalls++
	if s.EventsErr != nil {
		return nil, s.EventsErr
	}
	var out []store.Event
	for _, event := range s.Events {
		if event.ID > afterID && !event.At.Before(since) {
			out = append(out, event)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
