package scope

import (
	"context"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// verifyTTL is how long a VerifyOwnedTarget verdict is cached.
const verifyTTL = 30 * time.Second

type verifyEntry struct {
	ok      bool
	expires time.Time
}

// verifyCache is a small TTL cache; the zero value is ready to use.
type verifyCache struct {
	mu  sync.Mutex
	m   map[string]verifyEntry
	now func() time.Time // test hook; nil => time.Now
}

func (c *verifyCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *verifyCache) get(k string) (ok, hit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found := c.m[k]
	if !found || !c.clock().Before(e.expires) {
		return false, false
	}
	return e.ok, true
}

func (c *verifyCache) put(k string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	if c.m == nil {
		c.m = map[string]verifyEntry{}
	}
	if len(c.m) > 4096 { // bound memory: drop expired, then everything
		for key, e := range c.m {
			if !now.Before(e.expires) {
				delete(c.m, key)
			}
		}
		if len(c.m) > 4096 {
			c.m = map[string]verifyEntry{}
		}
	}
	c.m[k] = verifyEntry{ok: ok, expires: now.Add(verifyTTL)}
}

// VerifyOwnedTarget reports whether host is safe to hand to a component that
// runs its OWN network stack (nuclei, exec plugins) and therefore bypasses the
// guarded dialer. It fails closed: the name must classify as owned AND, when it
// is a name, it is resolved through the guard's resolver and EVERY answer must
// classify as owned. An IP-literal host is classified directly. A resolution
// error, an empty answer, an unparseable answer, or any answer that is
// excluded, shared, external or special-range makes the result false. Verdicts
// (including refusals) are cached for 30 seconds. Safe for concurrent use.
func (g *Guard) VerifyOwnedTarget(ctx context.Context, host string) bool {
	if ip, ok := parseIP(host); ok {
		return g.classifyIP(ip) == model.ScopeOwned
	}
	name, ok := normHost(host)
	if !ok || g.classifyName(name) != model.ScopeOwned {
		return false
	}
	if v, hit := g.verified.get(name); hit {
		return v
	}
	v := g.resolvesOnlyToOwned(ctx, name)
	if ctx.Err() == nil { // a cancelled lookup says nothing about the name
		g.verified.put(name, v)
	}
	return v
}

func (g *Guard) resolvesOnlyToOwned(ctx context.Context, name string) bool {
	addrs, err := g.resolver.LookupHost(ctx, name)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		ip, ok := parseIP(a)
		if !ok || g.classifyIP(ip) != model.ScopeOwned {
			return false
		}
	}
	return true
}
