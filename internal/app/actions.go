package app

import (
	"context"
	"errors"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/engine"
)

// engineActions adapts the engine to api.Actions. The engine reports its own
// typed errors; handing it to the API directly meant none of them matched the
// API's error mapping, so an unknown source (or an asset with nothing to scan)
// came back as a 500 instead of a 404 or 409.
type engineActions struct{ e *engine.Engine }

func (a engineActions) RescanAsset(ctx context.Context, assetID int64) error {
	return translateActionErr(a.e.RescanAsset(ctx, assetID))
}

func (a engineActions) TriggerSync(ctx context.Context, source string) error {
	return translateActionErr(a.e.TriggerSync(ctx, source))
}

// translateActionErr maps engine errors onto the sentinels the API turns into
// statuses, keeping the original error in the chain for logs.
func translateActionErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, engine.ErrUnknownSource):
		return errors.Join(api.ErrUnknownSource, err)
	case errors.Is(err, engine.ErrNotScannable):
		return errors.Join(api.ErrNotScannable, err)
	case errors.Is(err, engine.ErrNoQueue):
		return errors.Join(api.ErrNotSupported, err)
	}
	return err
}
