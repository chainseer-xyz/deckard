package engine

import (
	"context"
	"log/slog"
	"slices"
)

type collectedCVEScans struct {
	batches [][]string
	enabled bool
	log     *slog.Logger
}

func (c *collectedCVEScans) EnqueueCVEScan(_ context.Context, cves []string) (int, error) {
	if !c.enabled {
		if c.log != nil {
			c.log.Info("new CISA KEV CVEs but template scanning is disabled: no targeted scan", "cves", len(cves))
		}
		return 0, nil // Deliberately dropped, not retried, when scanning is off.
	}
	c.batches = append(c.batches, slices.Clone(cves))
	return 0, nil
}

// refreshVulnintelOnce refreshes intelligence before regular scans while
// retaining targeted work until the pass has discovered its current assets.
// Nothing is submitted to the engine's River queue or acknowledged here.
func (e *Engine) refreshVulnintelOnce(ctx context.Context) (batches [][]string, keys []string) {
	if e.o.vi.feed == nil || !e.d.Config.Vulnintel.Enabled {
		return nil, nil
	}
	base := e.vulnJob()
	collected := &collectedCVEScans{enabled: e.r.Delta != nil, log: base.log}
	j := &vulnintelJob{
		feed: base.feed, findings: base.findings, rec: base.rec, log: base.log,
		triggers: base.triggers, deferAck: true, trigger: collected,
	}
	// Intelligence remains best-effort. Durable triggers remain pending when
	// refresh or dispatch fails, and accepted batches still run in this pass.
	_ = j.run(ctx)
	return collected.batches, j.deferredKeys
}
