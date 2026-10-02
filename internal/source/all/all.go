// Package all registers every built-in source type with the registry.
// Import it for side effects from the binary: _ "github.com/chainseer-xyz/deckard/internal/source/all".
package all

import (
	"github.com/chainseer-xyz/deckard/internal/source/aws"
	"github.com/chainseer-xyz/deckard/internal/source/kubernetes"
	"github.com/chainseer-xyz/deckard/internal/source/registry"
	"github.com/chainseer-xyz/deckard/internal/source/route53"
)

func init() {
	registry.Register("route53", route53.Constructor)
	registry.Register("aws", aws.Constructor)
	registry.Register("kubernetes", kubernetes.Constructor)
}
