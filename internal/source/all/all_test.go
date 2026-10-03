package all

import (
	"slices"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/source/registry"
)

func TestAllSourceTypesRegistered(t *testing.T) {
	got := registry.Types()
	for _, want := range []string{"aws", "cloudflare", "gcpdns", "kubernetes", "route53", "static"} {
		if !slices.Contains(got, want) {
			t.Errorf("type %q not registered; have %v", want, got)
		}
	}
}
