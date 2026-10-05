package postgres_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/api/fakestore"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

func eventStore(t *testing.T, events []store.Event) store.Store {
	t.Helper()
	ctx := context.Background()
	url := freshDB(t, true)
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	rows := make([][]any, 0, len(events))
	for _, event := range events {
		rows = append(rows, []any{event.ID, event.Type, event.Subject, event.At})
	}
	if _, err := conn.CopyFrom(ctx, pgx.Identifier{"events"}, []string{"id", "type", "subject", "at"}, pgx.CopyFromRows(rows)); err != nil {
		t.Fatal(err)
	}
	s, err := postgres.New(ctx, url, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestEventQueryContractsMatchFakeStore(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	events := []store.Event{
		{ID: 1, Type: "asset_added", Subject: "old", At: at.Add(-time.Hour)},
		{ID: 2, Type: "asset_added", Subject: "same", At: at},
		{ID: 3, Type: "asset_added", Subject: "newest", At: at.Add(time.Minute)},
		{ID: 4, Type: "asset_added", Subject: "same-later-id", At: at},
	}
	fake := fakestore.New()
	fake.Events = events
	for name, s := range map[string]store.Store{"postgres": eventStore(t, events), "fake": fake} {
		t.Run(name, func(t *testing.T) {
			got, err := s.ListEvents(context.Background(), at, 3)
			assertEventIDs(t, got, err, 3, 4, 2)
			got, err = s.ListEventsAfter(context.Background(), at, 1, 2)
			assertEventIDs(t, got, err, 2, 3)
			got, err = s.ListEventsAfter(context.Background(), at, 3, 2)
			assertEventIDs(t, got, err, 4)
			got, err = s.ListEventsAfter(context.Background(), time.Time{}, 0, 0)
			assertEventIDs(t, got, err, 1, 2, 3, 4)
		})
	}
}

func assertEventIDs(t *testing.T, events []store.Event, err error, want ...int64) {
	t.Helper()
	if err != nil || len(events) != len(want) {
		t.Fatalf("events=%v err=%v, want IDs %v", events, err, want)
	}
	for i, event := range events {
		if event.ID != want[i] {
			t.Fatalf("event %d ID=%d, want %d", i, event.ID, want[i])
		}
	}
}

func TestSSEPostgresReplaysAndResumesLargeBatches(t *testing.T) {
	now := time.Now().UTC()
	for _, sameTimestamp := range []bool{false, true} {
		t.Run(fmt.Sprintf("same_timestamp=%v", sameTimestamp), func(t *testing.T) {
			events := make([]store.Event, 1200)
			for i := range events {
				at := now.Add(-time.Minute)
				if !sameTimestamp {
					at = at.Add(time.Duration(i) * time.Millisecond)
				}
				events[i] = store.Event{ID: int64(i + 1), Type: "asset_added", Subject: "replay", At: at}
			}
			s := eventStore(t, events)
			srv := api.New(api.Deps{
				Store: s, Authenticator: auth.NewToken("events-test-token"), SSEPollInterval: 20 * time.Millisecond,
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			hs := httptest.NewServer(srv.Handler())
			t.Cleanup(hs.Close)
			t.Run("full replay", func(t *testing.T) {
				readSSEIDs(t, hs.URL+"/api/v1/events?since="+now.Add(-time.Hour).Format(time.RFC3339), 0, 1200)
			})
			t.Run("resume within a batch", func(t *testing.T) {
				readSSEIDs(t, hs.URL+"/api/v1/events", 600, 1200)
			})
		})
	}
}

func readSSEIDs(t *testing.T, url string, afterID, lastID int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer events-test-token")
	if afterID > 0 {
		req.Header.Set("Last-Event-ID", strconv.FormatInt(afterID, 10))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events status %d", resp.StatusCode)
	}
	want := afterID + 1
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "id: ") {
			id, err := strconv.ParseInt(line[4:], 10, 64)
			if err != nil || id != want {
				t.Fatalf("event ID %q, want %d", line, want)
			}
			want++
			if id == lastID {
				return
			}
		}
	}
	t.Fatalf("stream stopped before event %d: %v", want, scanner.Err())
}
