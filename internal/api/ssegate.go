package api

import "sync"

// sseGate bounds concurrent SSE streams globally (a semaphore) and per
// identity, so one client cannot exhaust file descriptors or store capacity.
type sseGate struct {
	global chan struct{}
	perID  int

	mu    sync.Mutex
	count map[string]int
}

func newSSEGate(global, perID int) *sseGate {
	return &sseGate{global: make(chan struct{}, global), perID: perID, count: map[string]int{}}
}

// acquire reserves a slot for key. The returned release func is idempotent;
// ok is false when either limit is reached.
func (g *sseGate) acquire(key string) (release func(), ok bool) {
	g.mu.Lock()
	if g.count[key] >= g.perID {
		g.mu.Unlock()
		return nil, false
	}
	select {
	case g.global <- struct{}{}:
	default:
		g.mu.Unlock()
		return nil, false
	}
	g.count[key]++
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			if g.count[key]--; g.count[key] <= 0 {
				delete(g.count, key)
			}
			g.mu.Unlock()
			<-g.global
		})
	}, true
}
