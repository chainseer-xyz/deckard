package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/chainseer-xyz/deckard/internal/engine"
	"github.com/chainseer-xyz/deckard/internal/finding"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/vulnintel"
)

// buildVulnintel creates the exploit-intelligence service (CISA KEV + FIRST
// EPSS) and returns the processor and engine options that use it. With
// vulnintel.enabled: false (air-gapped) it returns nothing: no feed is ever
// contacted and findings are not enriched.
func (a *App) buildVulnintel() ([]finding.Option, []engine.Option, error) {
	v := a.cfg.Vulnintel
	if !v.Enabled {
		a.log.Info("vulnintel disabled: no CISA KEV / FIRST EPSS enrichment")
		return nil, nil, nil
	}
	vo := vulnintel.Options{
		Dir:        v.Dir,
		HTTPClient: &http.Client{Timeout: v.Timeout},
		UserAgent:  "deckard/" + a.opts.Version + " (defensive attack-surface monitor; +https://github.com/chainseer-xyz/deckard)",
		Logger:     a.log,
	}
	if a.opts.VulnintelOptions != nil {
		a.opts.VulnintelOptions(&vo)
	}
	svc, err := vulnintel.NewService(vo)
	if err != nil {
		return nil, nil, err
	}
	a.vuln = svc
	a.metrics.RegisterVulnintel(svc)
	pol := finding.IntelPolicy{KEVFloor: model.Severity(v.KEVFloor), EPSSHigh: v.EPSSHigh, EPSSMedium: v.EPSSMedium}
	return []finding.Option{finding.WithIntel(svc), finding.WithIntelPolicy(pol)},
		[]engine.Option{engine.WithVulnIntel(svc), engine.WithCVEScanTrigger(cveTrigger{a: a})}, nil
}

// cveTrigger connects the exploit-intel feed to the targeted template scan: a
// CVE newly added to CISA KEV starts an immediate nuclei run of the matching
// templates against every owned web asset, instead of waiting for the next
// scheduled scan. The engine does not exist yet when the engine options are
// built, so it is resolved lazily.
type cveTrigger struct{ a *App }

// EnqueueCVEScan implements engine.CVEScanTrigger.
func (t cveTrigger) EnqueueCVEScan(ctx context.Context, cves []string) (int, error) {
	if t.a.eng == nil {
		return 0, errors.New("engine not ready")
	}
	n, err := t.a.eng.EnqueueCVEScan(ctx, cves)
	if errors.Is(err, engine.ErrNoTemplateScanning) {
		// nuclei is disabled or unavailable: there is nothing to run, and
		// retrying would never succeed. Findings are still enriched.
		t.a.log.Info("new CISA KEV CVEs but template scanning is disabled: no targeted scan", "cves", len(cves))
		return 0, nil
	}
	return n, err
}
