package bbot

import (
	"encoding/json"
	"math"
	"strconv"
	"time"
)

func provenance(e event) map[string]any {
	attrs := map[string]any{}
	for _, field := range []struct {
		key string
		raw json.RawMessage
	}{{"module", e.Module}, {"scan", e.Scan}, {"event_id", e.ID}, {"parent_uuid", e.Parent}} {
		var value string
		if json.Unmarshal(field.raw, &value) == nil && identifier(value) {
			attrs[field.key] = value
		}
	}
	if value := timestamp(e.Timestamp); value != nil {
		attrs["timestamp"] = value
	}
	return attrs
}

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') &&
			c != '-' && c != '_' && c != '.' && c != ':' {
			return false
		}
	}
	return true
}

func timestamp(raw json.RawMessage) any {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC().Format(time.RFC3339Nano)
		}
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return nil
	}
	f, err := strconv.ParseFloat(number.String(), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 253402300799 {
		return nil
	}
	return number
}
