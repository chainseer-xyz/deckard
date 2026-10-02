package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// pendingKey is the reserved key inside Baseline.Data that carries the
// "candidate" value being learned while the baseline is stable:
//
//	{"_pending": {"data": <normalised observation>, "count": <consecutive runs>}}
//
// The store's Baseline row has no dedicated column for it. Checks that read
// Target.Baseline should ignore keys starting with "_".
const pendingKey = "_pending"

// DefaultIgnoreKeys are volatile observation keys never compared, at any
// depth: they change on every run and say nothing about the asset's state.
var DefaultIgnoreKeys = []string{
	"observed_at", "checked_at", "timestamp", "time", "date", "ts",
	"rtt", "rtt_ms", "latency", "latency_ms", "duration", "duration_ms", "elapsed", "elapsed_ms",
	// Countdowns and per-run timings change every run. not_before/not_after
	// are deliberately NOT here: a changed validity window is a real renewal.
	"days_remaining", "response_time", "response_time_ms",
}

// LearnParams tunes one baseline step.
type LearnParams struct {
	StableAfter int      // consecutive consistent runs before stable / adoption (>=1)
	Ignore      []string // extra volatile keys for this check (added to DefaultIgnoreKeys)
}

// Drift is one difference between a stable baseline and an observation.
type Drift struct {
	Field    string         // dotted path; set members use the "[]" suffix, e.g. "open_ports[]"
	Change   string         // added | removed | changed
	Old, New any            // Old is nil for added, New is nil for removed
	Severity model.Severity // by field class
}

// StepResult is the outcome of feeding one observation to a baseline.
type StepResult struct {
	Baseline store.Baseline
	Drift    []Drift
	Adopted  bool // a differing value was adopted as the new baseline this run
}

// Step is the baseline learning state machine (pure, no I/O).
//
//   - No baseline: the observation seeds a candidate (Consistent=1).
//   - Learning: an equal observation increments Consistent; a differing one
//     restarts the candidate. At Consistent >= StableAfter the baseline is
//     Stable. Nothing is reported while learning.
//   - Stable: an equal observation keeps it that way and discards any pending
//     candidate. A differing one yields Drift every run it persists, and the
//     baseline only adopts it after StableAfter consecutive runs of the SAME
//     new value (so it learns, but you are told in the meantime). The adoption
//     run itself reports no drift, which lets the drift finding resolve.
//
// Observations are compared in normalised form (see Normalize).
func Step(prev *store.Baseline, assetID int64, check string, obs map[string]any, p LearnParams, now time.Time) StepResult {
	if p.StableAfter < 1 {
		p.StableAfter = 1
	}
	ign := ignoreSet(p.Ignore)
	cur := Normalize(obs, ign)
	out := store.Baseline{AssetID: assetID, Check: check, UpdatedAt: now}

	if prev == nil || prev.Data == nil {
		out.Data, out.Consistent, out.Stable = cur, 1, p.StableAfter <= 1
		return StepResult{Baseline: out}
	}
	base, pend, pendN := splitPending(prev.Data, ign)

	if !prev.Stable {
		if reflect.DeepEqual(base, cur) {
			out.Data, out.Consistent = base, prev.Consistent+1
		} else {
			out.Data, out.Consistent = cur, 1
		}
		out.Stable = out.Consistent >= p.StableAfter
		return StepResult{Baseline: out}
	}

	out.Stable = true
	if reflect.DeepEqual(base, cur) {
		out.Data, out.Consistent = base, prev.Consistent+1
		return StepResult{Baseline: out}
	}

	drift := Diff(base, cur)
	n := 1
	if pend != nil && reflect.DeepEqual(pend, cur) {
		n = pendN + 1
	}
	// Adoption needs StableAfter consistent runs of the new value, and at
	// least two, so that even stable_after=1 reports a change once.
	if n >= max(p.StableAfter, 2) {
		out.Data, out.Consistent = cur, n
		return StepResult{Baseline: out, Drift: nil, Adopted: true}
	}
	out.Data = withPending(base, cur, n)
	out.Consistent = prev.Consistent
	return StepResult{Baseline: out, Drift: drift}
}

// splitPending separates the learned data from the reserved pending candidate.
func splitPending(data map[string]any, ign map[string]bool) (base, pend map[string]any, n int) {
	cp := make(map[string]any, len(data))
	for k, v := range data {
		if k == pendingKey {
			if m, ok := v.(map[string]any); ok {
				if d, ok := m["data"].(map[string]any); ok {
					pend = Normalize(d, ign)
				}
				switch c := m["count"].(type) {
				case float64:
					n = int(c)
				case int:
					n = c
				case int64:
					n = int(c)
				}
			}
			continue
		}
		cp[k] = v
	}
	return Normalize(cp, ign), pend, n
}

func withPending(base, cand map[string]any, n int) map[string]any {
	out := make(map[string]any, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out[pendingKey] = map[string]any{"data": cand, "count": float64(n)}
	return out
}

// Normalize returns a canonical copy of obs: JSON round-tripped (so int/float
// and typed slices compare equal), volatile keys dropped at every depth, and
// arrays sorted (arrays are treated as sets: order is not significant).
func Normalize(obs map[string]any, ignore map[string]bool) map[string]any {
	if obs == nil {
		return map[string]any{}
	}
	b, err := json.Marshal(obs)
	if err != nil {
		return map[string]any{}
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return map[string]any{}
	}
	return normMap(v, ignore)
}

func normMap(m map[string]any, ign map[string]bool) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if ign[strings.ToLower(k)] {
			continue
		}
		out[k] = normVal(v, ign)
	}
	return out
}

func normVal(v any, ign map[string]bool) any {
	switch t := v.(type) {
	case map[string]any:
		return normMap(t, ign)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = normVal(e, ign)
		}
		sort.SliceStable(out, func(i, j int) bool { return canon(out[i]) < canon(out[j]) })
		return out
	}
	return v
}

func ignoreSet(extra []string) map[string]bool {
	s := make(map[string]bool, len(DefaultIgnoreKeys)+len(extra))
	for _, k := range DefaultIgnoreKeys {
		s[k] = true
	}
	for _, k := range extra {
		s[strings.ToLower(k)] = true
	}
	return s
}

func canon(v any) string {
	b, _ := json.Marshal(v) // map keys are sorted by encoding/json
	return string(b)
}

// Diff computes field-level drift between two normalised datasets.
func Diff(old, cur map[string]any) []Drift {
	var out []Drift
	diffMap("", old, cur, &out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Field != out[j].Field {
			return out[i].Field < out[j].Field
		}
		return canon(firstNonNil(out[i].New, out[i].Old)) < canon(firstNonNil(out[j].New, out[j].Old))
	})
	return out
}

func firstNonNil(a, b any) any {
	if a != nil {
		return a
	}
	return b
}

func join(prefix, k string) string {
	if prefix == "" {
		return k
	}
	return prefix + "." + k
}

func diffMap(prefix string, old, cur map[string]any, out *[]Drift) {
	keys := map[string]bool{}
	for k := range old {
		keys[k] = true
	}
	for k := range cur {
		keys[k] = true
	}
	for k := range keys {
		path := join(prefix, k)
		ov, ook := old[k]
		cv, cok := cur[k]
		switch {
		case ook && !cok:
			emitRemoved(path, ov, out)
		case !ook && cok:
			emitAdded(path, cv, out)
		default:
			diffVal(path, ov, cv, out)
		}
	}
}

func emitAdded(path string, v any, out *[]Drift) {
	if arr, ok := v.([]any); ok {
		for _, e := range arr {
			*out = append(*out, mk(path+"[]", "added", nil, e))
		}
		return
	}
	*out = append(*out, mk(path, "added", nil, v))
}

func emitRemoved(path string, v any, out *[]Drift) {
	if arr, ok := v.([]any); ok {
		for _, e := range arr {
			*out = append(*out, mk(path+"[]", "removed", e, nil))
		}
		return
	}
	*out = append(*out, mk(path, "removed", v, nil))
}

func diffVal(path string, ov, cv any, out *[]Drift) {
	if reflect.DeepEqual(ov, cv) {
		return
	}
	switch o := ov.(type) {
	case map[string]any:
		if c, ok := cv.(map[string]any); ok {
			diffMap(path, o, c, out)
			return
		}
	case []any:
		if c, ok := cv.([]any); ok {
			diffSet(path+"[]", o, c, out)
			return
		}
	}
	*out = append(*out, mk(path, "changed", ov, cv))
}

// identity returns a stable identity for set members that are objects
// (e.g. {"port":443,...}), so a changed banner is "changed", not add+remove.
func identity(v any) (string, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return "", false
	}
	for _, k := range []string{"port", "name", "id", "key"} {
		if x, ok := m[k]; ok {
			return k + "=" + canon(x), true
		}
	}
	return "", false
}

func diffSet(path string, old, cur []any, out *[]Drift) {
	oldBy, curBy := map[string]any{}, map[string]any{}
	for _, e := range old {
		oldBy[setKey(e)] = e
	}
	for _, e := range cur {
		curBy[setKey(e)] = e
	}
	oldID, curID := map[string]any{}, map[string]any{}
	for _, e := range old {
		if id, ok := identity(e); ok {
			oldID[id] = e
		}
	}
	for _, e := range cur {
		if id, ok := identity(e); ok {
			curID[id] = e
		}
	}
	for _, e := range cur {
		if _, same := oldBy[setKey(e)]; same {
			continue
		}
		if id, ok := identity(e); ok {
			if o, had := oldID[id]; had {
				*out = append(*out, mk(path, "changed", o, e))
				continue
			}
		}
		*out = append(*out, mk(path, "added", nil, e))
	}
	for _, e := range old {
		if _, same := curBy[setKey(e)]; same {
			continue
		}
		if id, ok := identity(e); ok {
			if _, still := curID[id]; still {
				continue // reported as changed above
			}
		}
		*out = append(*out, mk(path, "removed", e, nil))
	}
}

func setKey(v any) string { return canon(v) }

func mk(field, change string, o, n any) Drift {
	d := Drift{Field: field, Change: change, Old: o, New: n}
	d.Severity = driftSeverity(d)
	return d
}

// highRiskPorts are remote-admin, database and orchestration ports whose
// sudden appearance is high severity; other new ports are medium.
var highRiskPorts = map[int]bool{
	21: true, 22: true, 23: true, 135: true, 139: true, 445: true, 1433: true, 1521: true, 2375: true, 2376: true,
	2379: true, 3306: true, 3389: true, 5432: true, 5900: true, 5984: true, 6379: true, 9200: true, 10250: true,
	11211: true, 27017: true,
}

func portOf(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case map[string]any:
		if p, ok := t["port"]; ok {
			return portOf(p)
		}
	}
	return 0, false
}

// driftSeverity classifies by field class: new open port medium/high by port
// class, certificate/fingerprint info, tech/headers low, anything else info.
func driftSeverity(d Drift) model.Severity {
	f := strings.ToLower(d.Field)
	switch {
	case strings.Contains(f, "port"):
		switch d.Change {
		case "added":
			if p, ok := portOf(d.New); ok && highRiskPorts[p] {
				return model.SeverityHigh
			}
			return model.SeverityMedium
		case "changed":
			return model.SeverityLow
		}
		return model.SeverityInfo
	case strings.Contains(f, "fingerprint"), strings.Contains(f, "cert"), strings.Contains(f, "serial"), strings.Contains(f, "issuer"):
		return model.SeverityInfo
	case strings.Contains(f, "tech"), strings.Contains(f, "header"), strings.Contains(f, "server"):
		return model.SeverityLow
	}
	return model.SeverityInfo
}

// DriftCheck is the finding check name for drift on a given check.
func DriftCheck(check string) string { return "drift." + check }

// DriftFindings turns drift into findings for check "drift.<check>". Set
// members ("field[]") key on field plus member value, so each distinct
// added/removed member is its own finding. Scalar fields key on the field name
// and change class only: the value goes in evidence, so a value that keeps
// changing never mints a new fingerprint per value (one finding, updated).
// Either way a finding resolves once the baseline adopts the change or it
// reverts.
func DriftFindings(check string, drift []Drift) []model.FindingInput {
	out := make([]model.FindingInput, 0, len(drift))
	for _, d := range drift {
		val := firstNonNil(d.New, d.Old)
		sign := ""
		if d.Change == "removed" {
			sign = "-"
		}
		key := keyFor(d.Field, sign+valStr(val))
		if !strings.HasSuffix(d.Field, "[]") {
			key = d.Field + "=" + d.Change
		}
		out = append(out, model.FindingInput{
			Check:    DriftCheck(check),
			Key:      key,
			Severity: d.Severity,
			Title:    fmt.Sprintf("%s drift: %s %s %s", check, d.Change, d.Field, short(valStr(val), 80)),
			Description: fmt.Sprintf("The %s observation for this asset differs from its learned baseline (%s %s). "+
				"If this is expected it will be adopted as the new baseline after it has been stable for several runs.", check, d.Change, d.Field),
			Evidence: map[string]any{"field": d.Field, "change": d.Change, "old": d.Old, "new": d.New},
			Tags:     []string{"drift"},
		})
	}
	return out
}

func valStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return canon(v)
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func keyFor(field, val string) string {
	k := field + "=" + val
	if len(k) > 200 {
		sum := sha256.Sum256([]byte(val))
		k = field + "=" + hex.EncodeToString(sum[:8])
	}
	return k
}
