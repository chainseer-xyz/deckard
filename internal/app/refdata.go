package app

import (
	"fmt"

	"github.com/chainseer-xyz/deckard/internal/refdata"
	"github.com/chainseer-xyz/deckard/internal/refdata/sets"
)

// buildRefdata installs the best offline reference data (the persisted last
// good copy, else the embedded one) and returns the manager that refreshes it.
// It returns nil when refresh is disabled: the embedded data stays in use and
// nothing touches the network (the air-gapped opt-out).
func (a *App) buildRefdata() (*refdata.Manager, error) {
	rc := a.cfg.Refdata
	if !rc.Enabled {
		return nil, nil
	}
	m, err := sets.Build(sets.Config{
		Dir:       rc.Dir,
		Timeout:   rc.Timeout,
		Takeover:  rc.Datasets.TakeoverFingerprints,
		Shared:    rc.Datasets.SharedRanges,
		Guard:     a.guard,
		UserAgent: "deckard/" + a.opts.Version + " (defensive attack-surface monitor; refreshes public reference data)",
		Log:       a.log,
		Rec:       a.metrics,
	})
	if err != nil {
		return nil, fmt.Errorf("refdata: %w", err)
	}
	if err := m.Init(); err != nil {
		return nil, fmt.Errorf("refdata: %w", err)
	}
	return m, nil
}

// DisableRefdataUpdate stops network refreshes for this process (the
// `deckard scan --no-update` flag). Persisted or embedded data stays live.
func (a *App) DisableRefdataUpdate() { a.eng.SetRefresher(nil) }
