package netcheck

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// merge overlays over onto defaults without mutating either.
func merge(defaults, over map[string]any) map[string]any {
	out := make(map[string]any, len(defaults)+len(over))
	for k, v := range defaults {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func cfgInt(m map[string]any, key string, def int) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func cfgDuration(m map[string]any, key string, def time.Duration) time.Duration {
	switch v := m[key].(type) {
	case time.Duration:
		return v
	case string:
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	case int:
		return time.Duration(v) * time.Second
	case float64:
		return time.Duration(v * float64(time.Second))
	}
	return def
}

// cfgPorts reads a port list given as []int, []any, a single int or a
// comma/range string.
func cfgPorts(m map[string]any, key string) ([]int, error) {
	switch v := m[key].(type) {
	case nil:
		return nil, nil
	case string:
		return ParsePorts(v)
	case int:
		return []int{v}, nil
	case float64:
		return []int{int(v)}, nil
	case []int:
		return v, nil
	case []any:
		parts := make([]string, 0, len(v))
		for _, e := range v {
			parts = append(parts, fmt.Sprint(e))
		}
		return ParsePorts(strings.Join(parts, ","))
	case []string:
		return ParsePorts(strings.Join(v, ","))
	}
	return nil, fmt.Errorf("%s: unsupported type %T", key, m[key])
}
