// Package checkutil holds small helpers shared by the check packages: typed
// config access, DNS error classification, zone matching and an HTTP fetch
// helper that records the redirect chain.
package checkutil

import (
	"math"
	"strings"
)

// Merge returns base overlaid with over (over wins). Either may be nil.
func Merge(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		if n > math.MaxInt32 { // config values are small; refuse anything absurd
			return 0, false
		}
		return int(n), true
	case float64:
		return int(n), true
	case float32:
		return int(n), true
	}
	return 0, false
}

// Int reads an integer config value, returning def when absent or mistyped.
func Int(m map[string]any, key string, def int) int {
	if n, ok := toInt(m[key]); ok {
		return n
	}
	return def
}

// Bool reads a bool config value.
func Bool(m map[string]any, key string, def bool) bool {
	if b, ok := m[key].(bool); ok {
		return b
	}
	return def
}

// Str reads a string config value.
func Str(m map[string]any, key, def string) string {
	if s, ok := m[key].(string); ok && s != "" {
		return s
	}
	return def
}

// Strings reads a string-list config value.
func Strings(m map[string]any, key string, def []string) []string {
	switch v := m[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return def
}

// Ints reads an int-list config value.
func Ints(m map[string]any, key string, def []int) []int {
	switch v := m[key].(type) {
	case []int:
		return v
	case []any:
		out := make([]int, 0, len(v))
		for _, e := range v {
			if n, ok := toInt(e); ok {
				out = append(out, n)
			}
		}
		return out
	}
	return def
}

// Norm lowercases a DNS name and strips a trailing dot.
func Norm(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
