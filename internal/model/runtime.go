package model

import "time"

// RuntimeEventTime reads the producer's event time, not its delivery time.
func RuntimeEventTime(evidence map[string]any) (time.Time, bool) {
	raw, ok := evidence["runtime_last_seen"].(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	return t, err == nil && !t.IsZero()
}

// RuntimeEventAdvances prevents replayed, delayed or timestamp-free delivery
// from replacing newer evidence or reopening an incident already handled.
func RuntimeEventAdvances(incoming, previous map[string]any) bool {
	old, known := RuntimeEventTime(previous)
	if !known {
		return true
	}
	next, valid := RuntimeEventTime(incoming)
	return valid && next.After(old)
}
