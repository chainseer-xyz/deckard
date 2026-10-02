// Package notify defines how findings leave deckard.
package notify

import (
	"context"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// Notifier delivers the current set of open findings and the findings that
// just resolved. Implementations must be idempotent: Notify is called
// repeatedly with the same open set.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, open []model.Finding, resolved []model.Finding) error
}
