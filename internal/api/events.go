package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/chainseer-xyz/deckard/internal/store"
)

const (
	sseBatch      = 500
	maxDrainPages = 20 // at most sseBatch*maxDrainPages events per drain
)

// cursor tracks what a stream has delivered. Events are de-duplicated by ID;
// the time bound only narrows the store query, and keeps a margin so events
// sharing a timestamp with the last one delivered are never skipped.
type cursor struct {
	id    int64
	since time.Time
}

// events streams the change feed as server-sent events.
//
// Resume: Last-Event-ID (an event id) replays events from the last
// SSEReplayWindow with a larger id; otherwise ?since=RFC3339 replays from
// that time; with neither, only new events are delivered. The store is the
// source of truth: it is polled every SSEPollInterval and immediately when
// the Broadcaster signals, so a dropped or reordered hint costs latency only.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r, "since")
	since, haveSince := q.timeParam("since")
	var lastID int64
	hdr := r.Header.Get("Last-Event-ID")
	if hdr != "" {
		n, err := strconv.ParseInt(hdr, 10, 64)
		if err != nil || n < 0 {
			q.fail("Last-Event-ID must be a non-negative integer")
		}
		lastID = n
	}
	if q.reject(w) {
		return
	}
	// Admission control: bounded streams globally and per identity.
	key := "anonymous"
	if id := identityFrom(r.Context()); id != nil {
		key = id.Method + ":" + id.Subject
	}
	release, ok := s.sse.acquire(key)
	if !ok {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "too_many_streams", "too many open event streams; retry shortly")
		return
	}
	defer release()

	// Replay is always bounded by SSEReplayWindow and never reaches the future,
	// so ?since=1970 cannot force a scan of the whole event table.
	now := s.clock.Now()
	floor := now.Add(-s.d.SSEReplayWindow)
	cur := cursor{id: lastID}
	switch {
	case hdr != "":
		cur.since = floor
		if haveSince && since.After(cur.since) {
			cur.since = since
		}
	case haveSince:
		cur.since = since
		if cur.since.Before(floor) {
			cur.since = floor
		}
	default:
		cur.since = now
	}
	if cur.since.After(now) {
		cur.since = now
	}

	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache, no-transform")
	h.Set("X-Accel-Buffering", "no")
	h.Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprint(w, "retry: 5000\n: connected\n\n"); err != nil {
		return
	}
	if err := rc.Flush(); err != nil {
		return
	}

	var wake <-chan store.Event
	if s.d.Broadcaster != nil {
		ch, cancel := s.d.Broadcaster.Subscribe()
		defer cancel()
		wake = ch
	}
	poll := time.NewTicker(s.d.SSEPollInterval)
	defer poll.Stop()
	beat := time.NewTicker(s.d.SSEHeartbeat)
	defer beat.Stop()

	ctx := r.Context()
	flush := func() bool { return rc.Flush() == nil }
	drain := func() bool {
		if err := s.pushEvents(ctx, w, &cur); err != nil {
			if ctx.Err() == nil {
				s.log.Warn("sse poll failed", "err", err)
			}
			return ctx.Err() == nil // transient store errors keep the stream open
		}
		return flush()
	}
	if !drain() {
		return
	}
	// Broadcaster wake-ups are coalesced: at most one store read per
	// SSEMinDrainInterval per stream, however fast the engine publishes.
	lastDrain := time.Now()
	var deferred <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
		case _, ok := <-wake:
			if !ok {
				wake = nil
			}
			if wait := s.d.SSEMinDrainInterval - time.Since(lastDrain); wait > 0 {
				if deferred == nil {
					deferred = time.After(wait)
				}
				continue
			}
		case <-deferred:
		case <-beat.C:
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil || !flush() {
				return
			}
			continue
		}
		deferred = nil
		lastDrain = time.Now()
		if !drain() {
			return
		}
	}
}

// pushEvents writes every store event newer than the cursor. A write error
// means the client is gone.
func (s *Server) pushEvents(ctx context.Context, w http.ResponseWriter, cur *cursor) error {
	// qsince pages through a backlog larger than one batch. The persistent
	// cursor keeps a 1s margin (so same-timestamp events are never skipped
	// between polls); paging within one drain advances to the batch's newest
	// timestamp instead, otherwise a burst wider than one batch inside that
	// margin would be re-read forever.
	qsince := cur.since
	// Bounded work per drain: a huge backlog is delivered over successive
	// drains (the cursor persists) instead of in one unbounded burst.
	for page := 0; page < maxDrainPages; page++ {
		qctx, cancel := context.WithTimeout(ctx, s.d.RequestTimeout)
		evs, err := s.d.Store.ListEvents(qctx, qsince, sseBatch)
		cancel()
		if err != nil {
			return err
		}
		sort.Slice(evs, func(i, j int) bool { return evs[i].ID < evs[j].ID })
		var maxAt time.Time
		for _, e := range evs {
			if e.At.After(maxAt) {
				maxAt = e.At
			}
			if e.ID <= cur.id {
				continue
			}
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "id: %d\nevent: change\ndata: %s\n\n", e.ID, data); err != nil {
				return err
			}
			cur.id = e.ID
			if t := e.At.Add(-time.Second); t.After(cur.since) {
				cur.since = t
			}
		}
		if len(evs) < sseBatch || !maxAt.After(qsince) {
			return nil
		}
		qsince = maxAt
	}
	// Page budget spent: resume from the newest timestamp reached so the next
	// drain does not re-read what this one already delivered.
	if qsince.After(cur.since) {
		cur.since = qsince
	}
	return nil
}
