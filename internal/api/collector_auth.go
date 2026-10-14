package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/api/auth"
	"github.com/chainseer-xyz/deckard/internal/config"
)

type collectorContextKey struct{}
type collectorCredential struct {
	name   string
	digest [32]byte
	grant  config.CollectorCredentialConfig
}

func (s *Server) initCollectors() {
	getenv := s.d.AuthOptions.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	seen := map[[32]byte]bool{}
	if s.d.Auth.Mode == "token" {
		seen[sha256.Sum256([]byte(strings.TrimSpace(getenv(s.d.Auth.TokenEnv))))] = true
	}
	for name, grant := range s.d.Ingest.Credentials {
		token := strings.TrimSpace(getenv(grant.TokenEnv))
		digest := sha256.Sum256([]byte(token))
		if len(token) < auth.MinTokenBytes || seen[digest] {
			s.authErr = errors.New("collector credentials require distinct tokens of at least 32 bytes")
			return
		}
		seen[digest] = true
		s.collectors = append(s.collectors, collectorCredential{name: name, digest: digest, grant: grant})
	}
}

func (s *Server) authenticateCollector(r *http.Request) (*collectorCredential, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, false
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(token)))
	var found *collectorCredential
	for i := range s.collectors {
		if subtle.ConstantTimeCompare(digest[:], s.collectors[i].digest[:]) == 1 {
			found = &s.collectors[i]
		}
	}
	return found, found != nil
}

func (c *collectorCredential) permitsRoute(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if r.URL.Path == "/api/v1/ingest" {
		return len(c.grant.Tools) > 0
	}
	for _, name := range c.grant.DiscoverySources {
		if r.URL.Path == "/api/v1/discovery/"+name {
			return true
		}
	}
	return false
}

func collectorFrom(ctx context.Context) *collectorCredential {
	c, _ := ctx.Value(collectorContextKey{}).(*collectorCredential)
	return c
}

func permitsIngest(ctx context.Context, tool, scope string) bool {
	c := collectorFrom(ctx)
	return c == nil || slices.Contains(c.grant.Tools, tool) && slices.Contains(c.grant.Scopes, scope)
}
