package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultLimit = 50
	maxLimit     = 500
	maxTextParam = 256
	maxOffset    = 1_000_000
)

// query is a strict query-string reader: unknown and duplicated parameters,
// malformed numbers, and out-of-range values are all collected as errors and
// reported together as a single 400.
type query struct {
	v    url.Values
	errs []string
}

func newQuery(r *http.Request, allowed ...string) *query {
	q := &query{v: r.URL.Query()}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range q.v {
		if !ok[k] {
			q.fail("unknown parameter %q", k)
		}
	}
	return q
}

func (q *query) fail(format string, args ...any) {
	q.errs = append(q.errs, fmt.Sprintf(format, args...))
}

// reject writes a 400 and returns true when any validation failed.
func (q *query) reject(w http.ResponseWriter) bool {
	if len(q.errs) == 0 {
		return false
	}
	writeError(w, http.StatusBadRequest, "invalid_query", strings.Join(q.errs, "; "))
	return true
}

// single returns the sole value of name, or "" if absent.
func (q *query) single(name string) (string, bool) {
	vals := q.v[name]
	switch len(vals) {
	case 0:
		return "", false
	case 1:
		return vals[0], true
	}
	q.fail("parameter %q may be given only once", name)
	return "", false
}

func (q *query) str(name string) string {
	return q.strMax(name, maxTextParam)
}

func (q *query) strMax(name string, max int) string {
	s, ok := q.single(name)
	if !ok {
		return ""
	}
	if len(s) > max {
		q.fail("parameter %q longer than %d characters", name, max)
		return ""
	}
	return s
}

// enum validates against an allow-list predicate.
func (q *query) enum(name string, valid func(string) bool) string {
	s, ok := q.single(name)
	if !ok {
		return ""
	}
	if !valid(s) {
		q.fail("invalid value %q for %q", truncate(s), name)
		return ""
	}
	return s
}

// enums is the repeatable variant of enum.
func (q *query) enums(name string, valid func(string) bool) []string {
	var out []string
	for _, s := range q.v[name] {
		if !valid(s) {
			q.fail("invalid value %q for %q", truncate(s), name)
			continue
		}
		out = append(out, s)
	}
	return out
}

func (q *query) boolean(name string) bool {
	s, ok := q.single(name)
	if !ok {
		return false
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		q.fail("parameter %q must be true or false", name)
	}
	return b
}

func (q *query) posInt64(name string) int64 {
	s, ok := q.single(name)
	if !ok {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		q.fail("parameter %q must be a positive integer", name)
		return 0
	}
	return n
}

func (q *query) limit() int {
	s, ok := q.single("limit")
	if !ok {
		return defaultLimit
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > maxLimit {
		q.fail("limit must be an integer between 1 and %d", maxLimit)
		return defaultLimit
	}
	return n
}

func (q *query) offset() int {
	s, ok := q.single("offset")
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > maxOffset {
		q.fail("offset must be an integer between 0 and %d", maxOffset)
		return 0
	}
	return n
}

func (q *query) depth() int {
	s, ok := q.single("depth")
	if !ok {
		return 1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 3 {
		q.fail("depth must be an integer between 1 and 3")
		return 1
	}
	return n
}

func (q *query) timeParam(name string) (time.Time, bool) {
	s, ok := q.single(name)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		q.fail("parameter %q must be an RFC3339 timestamp", name)
		return time.Time{}, false
	}
	return t, true
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
