package postgres_test

import (
	"testing"

	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/storetest"
)

func TestRuntimeContract(t *testing.T) {
	storetest.RunRuntime(t, func(t *testing.T) store.Store { return newMigratedStore(t) })
}
