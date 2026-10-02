package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CheckInterval reads the optional per-check cadence override
// (checks.<name>.interval). ok is false when the key is absent. The value may
// be a duration string ("30m") or a time.Duration and must be > 0.
func CheckInterval(opts map[string]any) (d time.Duration, ok bool, err error) {
	v, present := opts["interval"]
	if !present || v == nil {
		return 0, false, nil
	}
	switch t := v.(type) {
	case time.Duration:
		d = t
	case string:
		d, err = time.ParseDuration(strings.TrimSpace(t))
		if err != nil {
			return 0, false, fmt.Errorf("invalid duration %q", t)
		}
	default:
		return 0, false, fmt.Errorf("must be a duration string like \"30m\", got %T", v)
	}
	if d <= 0 {
		return 0, false, fmt.Errorf("must be > 0")
	}
	return d, true, nil
}

// CheckOnNewAsset reads checks.<name>.on_new_asset. ok is false when absent
// (the default, true, then applies). It can only narrow what the tier's
// on_inventory_change allows; it never widens it.
func CheckOnNewAsset(opts map[string]any) (v bool, ok bool, err error) {
	raw, present := opts["on_new_asset"]
	if !present || raw == nil {
		return false, false, nil
	}
	switch t := raw.(type) {
	case bool:
		return t, true, nil
	case string:
		b, perr := strconv.ParseBool(strings.TrimSpace(t))
		if perr != nil {
			return false, false, fmt.Errorf("must be a boolean, got %q", t)
		}
		return b, true, nil
	}
	return false, false, fmt.Errorf("must be a boolean, got %T", raw)
}
