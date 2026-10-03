package app

import (
	"github.com/chainseer-xyz/deckard/internal/intel"
)

// buildIntel creates the restricted third-party metadata client checks reach
// through Target.Intel. With intel.enabled: false (air-gapped) the client is
// still built but answers every request with intel.ErrDisabled, so consumers
// record a "skipped" observation instead of failing.
func (a *App) buildIntel() (*intel.Client, error) {
	ic := a.cfg.Intel
	if !ic.Enabled {
		a.log.Info("intel disabled: no RDAP or other third-party metadata lookups; checks that need them are skipped")
	}
	return intel.New(intel.Options{
		Disabled: !ic.Enabled,
		Version:  a.opts.Version,
		Contact:  ic.UserAgentContact,
		Services: ic.ServiceOptions(),
		Logger:   a.log,
		Recorder: a.metrics,
	})
}
