package postgres

import (
	"context"
	"time"

	"github.com/chainseer-xyz/deckard/internal/store"
)

// ListEventsAfter pages event streams by ascending ID, independently of the
// newest-first ListEvents query used for the recent changes view.
func (s *Store) ListEventsAfter(ctx context.Context, since time.Time, afterID int64, limit int) ([]store.Event, error) {
	if since.IsZero() {
		since = time.Unix(0, 0)
	}
	query := `SELECT id, type, subject, data, at FROM events WHERE at >= $1 AND id > $2 ORDER BY id ASC`
	args := []any{since, afterID}
	if limit > 0 {
		query += ` LIMIT $3`
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []store.Event
	for rows.Next() {
		var event store.Event
		var data map[string]any
		if err := rows.Scan(&event.ID, &event.Type, &event.Subject, &data, &event.At); err != nil {
			return nil, err
		}
		event.Data = nilIfEmpty(data)
		events = append(events, event)
	}
	return events, rows.Err()
}
