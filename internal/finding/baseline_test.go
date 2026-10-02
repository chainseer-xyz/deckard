package finding

import (
	"reflect"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func obs(ports ...int) map[string]any {
	ps := make([]any, len(ports))
	for i, p := range ports {
		ps[i] = p
	}
	return map[string]any{"open_ports": ps, "rtt_ms": 12, "observed_at": "now"}
}

func TestNormalize(t *testing.T) {
	a := Normalize(map[string]any{"open_ports": []int{443, 80}, "rtt_ms": 3, "n": map[string]any{"latency": 1, "x": []string{"b", "a"}}}, ignoreSet(nil))
	b := Normalize(map[string]any{"open_ports": []any{float64(80), float64(443)}, "rtt_ms": 99, "n": map[string]any{"x": []any{"a", "b"}}}, ignoreSet(nil))
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("%v != %v", a, b)
	}
	if got := Normalize(nil, nil); len(got) != 0 {
		t.Fatal(got)
	}
	if got := Normalize(map[string]any{"c": make(chan int)}, nil); len(got) != 0 {
		t.Fatal("unmarshalable must degrade to empty")
	}
	// per-check ignore, case-insensitive
	c := Normalize(map[string]any{"Banner": "x", "a": 1}, ignoreSet([]string{"banner"}))
	if !reflect.DeepEqual(c, map[string]any{"a": float64(1)}) {
		t.Fatal(c)
	}
}

// run feeds a sequence of observations through Step and returns each result.
func run(stableAfter int, seq ...map[string]any) []StepResult {
	var prev *store.Baseline
	var out []StepResult
	for i, o := range seq {
		r := Step(prev, 1, "net.ports", o, LearnParams{StableAfter: stableAfter}, t0.Add(time.Duration(i)*time.Minute))
		out = append(out, r)
		b := r.Baseline
		prev = &b
	}
	return out
}

func TestStepLearning(t *testing.T) {
	rs := run(3, obs(80), obs(80), obs(80))
	for i, want := range []struct {
		n      int
		stable bool
	}{{1, false}, {2, false}, {3, true}} {
		if rs[i].Baseline.Consistent != want.n || rs[i].Baseline.Stable != want.stable || len(rs[i].Drift) != 0 {
			t.Errorf("step %d: %+v", i, rs[i])
		}
	}
	// A differing observation while learning restarts the candidate, no drift.
	rs = run(3, obs(80), obs(80), obs(80, 22), obs(80, 22), obs(80, 22))
	if rs[2].Baseline.Consistent != 1 || rs[2].Baseline.Stable || len(rs[2].Drift) != 0 {
		t.Fatalf("restart: %+v", rs[2])
	}
	if !rs[4].Baseline.Stable {
		t.Fatalf("should be stable after 3 consistent: %+v", rs[4])
	}
	// stable_after=1 is stable immediately; zero is clamped.
	if !run(1, obs(80))[0].Baseline.Stable || !run(0, obs(80))[0].Baseline.Stable {
		t.Fatal("stable_after<=1")
	}
	// empty-data baseline is treated as no baseline
	r := Step(&store.Baseline{}, 1, "c", obs(80), LearnParams{StableAfter: 2}, t0)
	if r.Baseline.Consistent != 1 {
		t.Fatal(r)
	}
}

func TestStepDriftAndAdoption(t *testing.T) {
	rs := run(2, obs(80), obs(80), // stable
		obs(80, 22), // drift 1
		obs(80, 22), // adopted (2 consistent)
		obs(80, 22), // equal to new baseline
	)
	if !rs[1].Baseline.Stable {
		t.Fatal("not stable")
	}
	d := rs[2].Drift
	if len(d) != 1 || d[0].Field != "open_ports[]" || d[0].Change != "added" || d[0].Severity != model.SeverityHigh {
		t.Fatalf("drift: %+v", d)
	}
	if _, has := rs[2].Baseline.Data[pendingKey]; !has {
		t.Fatal("pending candidate must be recorded")
	}
	// the baseline is NOT yet changed
	if !reflect.DeepEqual(rs[2].Baseline.Data["open_ports"], []any{float64(80)}) {
		t.Fatalf("baseline adopted too early: %v", rs[2].Baseline.Data)
	}
	if !rs[3].Adopted || len(rs[3].Drift) != 0 {
		t.Fatalf("adoption: %+v", rs[3])
	}
	if !reflect.DeepEqual(rs[3].Baseline.Data["open_ports"], []any{float64(22), float64(80)}) {
		t.Fatalf("not adopted: %v", rs[3].Baseline.Data)
	}
	if _, has := rs[3].Baseline.Data[pendingKey]; has {
		t.Fatal("pending must clear on adoption")
	}
	if rs[4].Adopted || len(rs[4].Drift) != 0 || !rs[4].Baseline.Stable {
		t.Fatalf("%+v", rs[4])
	}
}

func TestStepDriftRevertAndFlapping(t *testing.T) {
	// Drift then revert: pending discarded, no adoption.
	rs := run(3, obs(80), obs(80), obs(80), obs(80, 8080), obs(80))
	if len(rs[3].Drift) != 1 || len(rs[4].Drift) != 0 {
		t.Fatalf("%+v %+v", rs[3], rs[4])
	}
	if _, has := rs[4].Baseline.Data[pendingKey]; has {
		t.Fatal("pending must clear when value reverts")
	}
	// Flapping between two different new values never adopts either.
	rs = run(3, obs(80), obs(80), obs(80), obs(80, 1), obs(80, 2), obs(80, 1), obs(80, 2))
	for i := 3; i < 7; i++ {
		if rs[i].Adopted || len(rs[i].Drift) == 0 {
			t.Fatalf("step %d: %+v", i, rs[i])
		}
	}
	// stable_after=1 still reports a change once before adopting.
	rs = run(1, obs(80), obs(80, 22), obs(80, 22))
	if len(rs[1].Drift) != 1 || rs[1].Adopted || !rs[2].Adopted {
		t.Fatalf("%+v %+v", rs[1], rs[2])
	}
}

func TestStepIgnoresVolatileKeys(t *testing.T) {
	a := map[string]any{"status": 200, "rtt_ms": 10, "observed_at": "a"}
	b := map[string]any{"status": 200, "rtt_ms": 55, "observed_at": "b"}
	rs := run(2, a, b, a)
	if !rs[1].Baseline.Stable || len(rs[2].Drift) != 0 {
		t.Fatalf("%+v", rs)
	}
	// per-check ignore list
	var prev *store.Baseline
	p := LearnParams{StableAfter: 1, Ignore: []string{"banner"}}
	r := Step(prev, 1, "c", map[string]any{"banner": "x", "v": 1}, p, t0)
	r2 := Step(&r.Baseline, 1, "c", map[string]any{"banner": "y", "v": 1}, p, t0)
	if len(r2.Drift) != 0 {
		t.Fatalf("%+v", r2)
	}
}

func TestDiffSeverityTable(t *testing.T) {
	tests := []struct {
		name     string
		old, cur map[string]any
		field    string
		change   string
		sev      model.Severity
	}{
		{"new web port", map[string]any{"open_ports": []any{80.0}}, map[string]any{"open_ports": []any{80.0, 8080.0}}, "open_ports[]", "added", model.SeverityMedium},
		{"new ssh port", map[string]any{"open_ports": []any{80.0}}, map[string]any{"open_ports": []any{80.0, 22.0}}, "open_ports[]", "added", model.SeverityHigh},
		{"new port object redis", map[string]any{"ports": []any{map[string]any{"port": 80.0}}}, map[string]any{"ports": []any{map[string]any{"port": 80.0}, map[string]any{"port": 6379.0}}}, "ports[]", "added", model.SeverityHigh},
		{"closed port", map[string]any{"open_ports": []any{80.0, 22.0}}, map[string]any{"open_ports": []any{80.0}}, "open_ports[]", "removed", model.SeverityInfo},
		{"port banner changed", map[string]any{"ports": []any{map[string]any{"port": 80.0, "svc": "a"}}}, map[string]any{"ports": []any{map[string]any{"port": 80.0, "svc": "b"}}}, "ports[]", "changed", model.SeverityLow},
		{"cert fingerprint", map[string]any{"cert_fingerprint": "aa"}, map[string]any{"cert_fingerprint": "bb"}, "cert_fingerprint", "changed", model.SeverityInfo},
		{"tech added", map[string]any{"tech": []any{"nginx"}}, map[string]any{"tech": []any{"nginx", "php"}}, "tech[]", "added", model.SeverityLow},
		{"header changed nested", map[string]any{"headers": map[string]any{"server": "a"}}, map[string]any{"headers": map[string]any{"server": "b"}}, "headers.server", "changed", model.SeverityLow},
		{"generic status", map[string]any{"status": 200.0}, map[string]any{"status": 500.0}, "status", "changed", model.SeverityInfo},
		{"field added", map[string]any{}, map[string]any{"headers": []any{"x"}}, "headers[]", "added", model.SeverityLow},
		{"scalar added", map[string]any{}, map[string]any{"title": "hi"}, "title", "added", model.SeverityInfo},
		{"field removed", map[string]any{"title": "hi"}, map[string]any{}, "title", "removed", model.SeverityInfo},
		{"list removed wholesale", map[string]any{"tech": []any{"a"}}, map[string]any{}, "tech[]", "removed", model.SeverityLow},
		{"type change", map[string]any{"x": []any{"a"}}, map[string]any{"x": "a"}, "x", "changed", model.SeverityInfo},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Diff(tc.old, tc.cur)
			if len(d) != 1 {
				t.Fatalf("want 1 drift got %+v", d)
			}
			if d[0].Field != tc.field || d[0].Change != tc.change || d[0].Severity != tc.sev {
				t.Fatalf("got %+v", d[0])
			}
		})
	}
	if d := Diff(map[string]any{"a": 1.0}, map[string]any{"a": 1.0}); len(d) != 0 {
		t.Fatal(d)
	}
}

func TestDriftFindings(t *testing.T) {
	d := Diff(map[string]any{"open_ports": []any{80.0}}, map[string]any{"open_ports": []any{80.0, 22.0}})
	fs := DriftFindings("net.ports", d)
	if len(fs) != 1 {
		t.Fatal(fs)
	}
	f := fs[0]
	if f.Check != "drift.net.ports" || f.Key != "open_ports[]=22" || f.Severity != model.SeverityHigh || f.Evidence["field"] != "open_ports[]" || f.Evidence["new"] != 22.0 {
		t.Fatalf("%+v", f)
	}
	// removed gets a distinct key from added of the same value.
	rm := DriftFindings("c", []Drift{{Field: "p[]", Change: "removed", Old: "x"}, {Field: "p[]", Change: "added", New: "x"}})
	if rm[0].Key == rm[1].Key {
		t.Fatal("keys must differ")
	}
	// very long values are hashed, stable and bounded.
	long := string(make([]byte, 500))
	k1 := DriftFindings("c", []Drift{{Field: "f", Change: "added", New: long}})[0].Key
	if len(k1) > 60 {
		t.Fatalf("key too long: %d", len(k1))
	}
	if short("abcdef", 3) != "abc..." || short("ab", 3) != "ab" {
		t.Fatal("short")
	}
	if DriftCheck("x") != "drift.x" {
		t.Fatal()
	}
}

func TestStepPendingTypes(t *testing.T) {
	// pending count may come back from JSON as float64 or from memory as int.
	base := map[string]any{"a": 1.0}
	for _, c := range []any{float64(1), 1, int64(1)} {
		prev := &store.Baseline{Data: map[string]any{"a": 1.0, pendingKey: map[string]any{"data": map[string]any{"a": 2.0}, "count": c}}, Stable: true, Consistent: 3}
		r := Step(prev, 1, "c", map[string]any{"a": 2}, LearnParams{StableAfter: 2}, t0)
		if !r.Adopted {
			t.Fatalf("count %T: %+v", c, r)
		}
		_ = base
	}
	// malformed pending is ignored
	prev := &store.Baseline{Data: map[string]any{"a": 1.0, pendingKey: "junk"}, Stable: true, Consistent: 3}
	r := Step(prev, 1, "c", map[string]any{"a": 1}, LearnParams{StableAfter: 2}, t0)
	if len(r.Drift) != 0 || r.Baseline.Consistent != 4 {
		t.Fatalf("%+v", r)
	}
}
