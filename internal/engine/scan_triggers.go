package engine

import (
	"context"
	"fmt"

	"github.com/chainseer-xyz/deckard/internal/nuclei/updater"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// enqueueTemplateTriggers replays durable deltas even when the updater reports
// an unchanged release. Publication callbacks write the outbox first; Put here
// also supports TemplateManager implementations without that callback.
func (r *runner) enqueueTemplateTriggers(ctx context.Context, up updater.Update, changed bool) ([]string, error) {
	triggers, ok := r.Store.(store.ScanTriggerStore)
	if !ok {
		if changed {
			_, err := r.enqueueNewTemplateScans(ctx, up)
			return nil, err
		}
		return nil, nil
	}
	if !r.Config.Nuclei.Update.RunNewTemplates || r.Delta == nil {
		return nil, nil
	}
	if changed && len(up.NewTemplates) > 0 {
		trigger := store.NewScanTrigger(store.ScanTriggerTemplates, up.Version, up.NewTemplates, nil)
		if err := triggers.PutScanTrigger(ctx, trigger); err != nil {
			return nil, fmt.Errorf("persist template scans: %w", err)
		}
	}
	pending, err := triggers.ListPendingScanTriggers(ctx, store.ScanTriggerTemplates)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, trigger := range pending {
		if _, err := r.enqueueNewTemplateScans(ctx, updater.Update{Version: trigger.Release, NewTemplates: trigger.Templates}); err != nil {
			return nil, err
		}
		keys = append(keys, trigger.Key)
	}
	return keys, nil
}

func (r *runner) acknowledgeScanTriggers(ctx context.Context, keys []string) error {
	triggers, ok := r.Store.(store.ScanTriggerStore)
	if !ok {
		return nil
	}
	for _, key := range keys {
		if err := triggers.AckScanTrigger(ctx, key); err != nil {
			return fmt.Errorf("acknowledge queued scan trigger: %w", err)
		}
	}
	return nil
}
