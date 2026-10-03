package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/chainseer-xyz/deckard/internal/inventory/expand"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func ct502(zone string) error {
	return fmt.Errorf("ct %s: %w", zone, &expand.UnavailableError{Err: errors.New("ct: status 502")})
}

type logLine struct {
	Level string `json:"level"`
	Msg   string `json:"msg"`
	Zone  string `json:"zone"`
}

func logLines(t *testing.T, buf *bytes.Buffer) []logLine {
	t.Helper()
	var out []logLine
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var r logLine
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("log %q: %v", l, err)
		}
		out = append(out, r)
	}
	return out
}

// A CT source that is merely down (502) is routine: one WARN per zone per
// hour, DEBUG otherwise, the partial result is still added, nothing is
// removed, and the run reports a transient error for the worker to snooze on.
func TestRunExpandTransientCTWarnsHourly(t *testing.T) {
	z1, z2 := zoneAsset(1, "example.com"), zoneAsset(2, "example.org")
	fx := &fakeExpander{res: ExpandResult{DNS: cand("example.com", "dns_bruteforce", "mail.example.com")}, err: ct502("example.com")}
	h := newHarness(expCfg(true, true), []model.Asset{z1, z2})
	h.r.Expander = fx
	var buf bytes.Buffer
	h.r.log = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	run := func(id int64) {
		t.Helper()
		err := h.r.runExpand(ctx, id)
		if _, ok := err.(*transientExpandError); !ok { //nolint:errorlint // the worker checks the exact type
			t.Fatalf("want a transientExpandError, got %T %v", err, err)
		}
		if !strings.Contains(err.Error(), "ct: status 502") {
			t.Fatalf("error lost its cause: %v", err)
		}
	}
	run(1)
	h.now = h.now.Add(10 * time.Minute)
	run(1)
	run(2) // another zone warns on its own
	h.now = h.now.Add(30 * time.Minute)
	run(1)
	h.now = h.now.Add(25 * time.Minute) // 65m after the first warning
	run(1)

	var levels []string
	for _, l := range logLines(t, &buf) {
		switch {
		case strings.HasPrefix(l.Msg, "expansion incomplete: CT source unavailable"):
			levels = append(levels, l.Zone+"="+l.Level)
		case l.Msg == "expansion incomplete":
			t.Errorf("a transient CT failure must not log the generic WARN: %+v", l)
		case l.Msg == "expansion complete" && l.Level != "DEBUG":
			t.Errorf("per-attempt completion line must be DEBUG while CT is down: %+v", l)
		}
	}
	want := "example.com=WARN,example.com=DEBUG,example.org=WARN,example.com=DEBUG,example.com=WARN"
	if got := strings.Join(levels, ","); got != want {
		t.Fatalf("levels\n got  %s\n want %s", got, want)
	}
	if n := len(h.inv.discOrig); n != 5 {
		t.Fatalf("partial DNS result added %d times, want every attempt (5)", n)
	}
	if len(h.st.runs()) != 0 {
		t.Fatal("expansion touched scan history")
	}
}

// A non-transient failure, or a transient one joined with a real error,
// stays an ordinary error (River retries and reports it).
func TestRunExpandRealFailuresStayErrors(t *testing.T) {
	z := zoneAsset(1, "example.com")
	for name, xerr := range map[string]error{
		"decode error":   errors.New("ct example.com: ct: decode response: bad json"),
		"mixed":          errors.Join(ct502("example.com"), errors.New("wildcard probe: SERVFAIL")),
		"unexpected 404": errors.New("ct example.com: ct: unexpected status 404"),
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(expCfg(true, true), []model.Asset{z})
			h.r.Expander = &fakeExpander{err: xerr}
			err := h.r.runExpand(context.Background(), 1)
			if err == nil {
				t.Fatal("error swallowed")
			}
			if _, ok := err.(*transientExpandError); ok { //nolint:errorlint // exact type
				t.Fatalf("%v must not be treated as transient", err)
			}
		})
	}
	// Transient CT, but the inventory write failed: the write error must win.
	h := newHarness(expCfg(true, true), []model.Asset{z})
	h.r.Expander = &fakeExpander{res: ExpandResult{DNS: cand("example.com", "dns_bruteforce", "a.example.com")}, err: ct502("example.com")}
	h.inv.discErr = errors.New("db down")
	w := &expandWorker{r: h.r}
	err := w.Work(context.Background(), &river.Job[ExpandZoneArgs]{JobRow: &rivertype.JobRow{}, Args: ExpandZoneArgs{AssetID: 1}})
	var sn *rivertype.JobSnoozeError
	if errors.As(err, &sn) || err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("an inventory failure must be retried as an error, got %v", err)
	}
}

// The worker snoozes a transient failure with growing, capped backoff
// instead of erroring ("Job errored; retrying" on every attempt).
func TestExpandWorkerSnoozesTransientCT(t *testing.T) {
	z := zoneAsset(1, "example.com")
	h := newHarness(expCfg(true, false), []model.Asset{z})
	h.r.Expander = &fakeExpander{err: ct502("example.com")}
	w := &expandWorker{r: h.r}
	for _, tc := range []struct {
		meta string
		want time.Duration
	}{
		{`{}`, 5 * time.Minute},
		{`{"snoozes":1}`, 10 * time.Minute},
		{`{"snoozes":3}`, 40 * time.Minute},
		{`{"snoozes":9}`, time.Hour},
		{`not json`, 5 * time.Minute},
	} {
		err := w.Work(context.Background(), &river.Job[ExpandZoneArgs]{JobRow: &rivertype.JobRow{Metadata: []byte(tc.meta)}, Args: ExpandZoneArgs{AssetID: 1}})
		var sn *rivertype.JobSnoozeError
		if !errors.As(err, &sn) || sn.Duration != tc.want {
			t.Errorf("metadata %s: got %v, want a %v snooze", tc.meta, err, tc.want)
		}
	}
	// Any other failure is returned as is.
	h.r.Expander = &fakeExpander{err: errors.New("ct example.com: ct: decode response: x")}
	err := w.Work(context.Background(), &river.Job[ExpandZoneArgs]{JobRow: &rivertype.JobRow{}, Args: ExpandZoneArgs{AssetID: 1}})
	var sn *rivertype.JobSnoozeError
	if err == nil || errors.As(err, &sn) {
		t.Fatalf("non-transient: %v", err)
	}
}

func TestCTRetryDelay(t *testing.T) {
	for _, tc := range []struct {
		n        int
		interval time.Duration
		want     time.Duration
	}{
		{0, 6 * time.Hour, 5 * time.Minute},
		{2, 6 * time.Hour, 20 * time.Minute},
		{4, 6 * time.Hour, time.Hour},
		{50, 6 * time.Hour, time.Hour},
		{3, 30 * time.Minute, 30 * time.Minute},
		{0, 0, 5 * time.Minute},
	} {
		if got := ctRetryDelay(tc.n, tc.interval); got != tc.want {
			t.Errorf("ctRetryDelay(%d, %v) = %v, want %v", tc.n, tc.interval, got, tc.want)
		}
	}
}

// The production expander keeps the CT error's type through its wrapping.
func TestDefaultExpanderKeepsCTUnavailableType(t *testing.T) {
	e := &DefaultExpander{CT: &fakeCT{err: &expand.UnavailableError{Err: errors.New("ct: status 503")}}}
	_, err := e.Expand(context.Background(), ExpandRequest{Zone: "example.com", CT: true, Resolver: &fakeResolver{}})
	if err == nil || !onlyCTUnavailable(err) {
		t.Fatalf("err = %v, want a transient CT failure", err)
	}
	if onlyCTUnavailable(errors.New("x")) || onlyCTUnavailable(errors.Join()) {
		t.Fatal("ordinary errors are not transient")
	}
}
