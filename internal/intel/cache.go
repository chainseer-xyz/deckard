package intel

import (
	"sync"
	"time"
)

// defaultCacheEntries bounds the response cache. RDAP answers are a few KiB;
// the bound keeps a misbehaving consumer from growing memory without limit.
const defaultCacheEntries = 4096

type cacheEntry struct {
	resp     Response
	notFound bool
	expires  time.Time
}

// ttlCache is a small in-memory cache with per-entry expiry. When full it
// drops expired entries first, then the entry closest to expiry.
type ttlCache struct {
	mu  sync.Mutex
	m   map[string]cacheEntry
	max int
	now func() time.Time
}

func newTTLCache(limit int, now func() time.Time) *ttlCache {
	return &ttlCache{m: map[string]cacheEntry{}, max: limit, now: now}
}

func (c *ttlCache) get(key string) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return cacheEntry{}, false
	}
	if !c.now().Before(e.expires) {
		delete(c.m, key)
		return cacheEntry{}, false
	}
	return e, true
}

func (c *ttlCache) put(key string, e cacheEntry, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	e.expires = now.Add(ttl)
	if _, ok := c.m[key]; !ok && len(c.m) >= c.max {
		c.evict(now)
	}
	c.m[key] = e
}

// evict makes room for one entry. Callers hold mu.
func (c *ttlCache) evict(now time.Time) {
	for k, e := range c.m {
		if !now.Before(e.expires) {
			delete(c.m, k)
		}
	}
	if len(c.m) < c.max {
		return
	}
	var victim string
	var soonest time.Time
	for k, e := range c.m {
		if victim == "" || e.expires.Before(soonest) {
			victim, soonest = k, e.expires
		}
	}
	delete(c.m, victim)
}

func (c *ttlCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
