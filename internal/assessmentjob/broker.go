package assessmentjob

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// ServeBroker dispatches opaque tokens before entering a session policy. An
// unknown token cannot cancel any valid assessment. The serving HTTP server
// must impose <=16KiB headers, 5s header timeout and bounded read/write times.
func (m *Manager) ServeBroker(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/report" && !r.URL.IsAbs() {
		m.upload(w, r)
		return
	}
	if r.URL.Path == "/v1/report" && r.URL.Hostname() == m.settings.BrokerIP.String() {
		http.Error(w, "assessment broker cannot be a target", http.StatusForbidden)
		return
	}
	scheme, encoded, ok := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") || len(encoded) > 512 {
		proxyChallenge(w)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		proxyChallenge(w)
		return
	}
	user, token, ok := strings.Cut(string(decoded), ":")
	if !ok || user != "deckard" {
		proxyChallenge(w)
		return
	}
	m.mu.RLock()
	id := m.proxyTokens[token]
	state := m.sessions[id]
	m.mu.RUnlock()
	if state == nil {
		proxyChallenge(w)
		return
	}
	state.proxy.ServeHTTP(w, r)
}

// Native HTTP clients may first CONNECT without credentials and negotiate
// Basic authentication from this challenge. Unknown identities never enter a
// session policy: ordinary negotiation cannot poison a valid assessment.
func proxyChallenge(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="Deckard assessment"`)
	http.Error(w, "unknown assessment proxy identity", http.StatusProxyAuthRequired)
}

func (m *Manager) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "report requires POST", http.StatusMethodNotAllowed)
		return
	}
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || scheme != "Bearer" || len(token) > 256 {
		http.Error(w, "unknown assessment report identity", http.StatusUnauthorized)
		return
	}
	m.mu.Lock()
	id := m.uploadTokens[token]
	state := m.sessions[id]
	if state == nil || id != r.Header.Get("X-Deckard-Session") || string(state.session.Tool) != r.Header.Get("X-Deckard-Tool") {
		m.mu.Unlock()
		http.Error(w, "unknown assessment report identity", http.StatusUnauthorized)
		return
	}
	if state.finalizing || state.uploading || state.report != nil || state.ctx.Err() != nil {
		m.mu.Unlock()
		http.Error(w, "assessment report already submitted or session ended", http.StatusConflict)
		return
	}
	select {
	case m.uploadSlots <- struct{}{}:
		state.uploading = true
	default:
		m.mu.Unlock()
		http.Error(w, "assessment report capacity exhausted", http.StatusTooManyRequests)
		return
	}
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		state.uploading = false
		m.mu.Unlock()
		<-m.uploadSlots
	}()
	stop := context.AfterFunc(state.ctx, func() { _ = r.Body.Close() })
	defer stop()
	limit := int64(32 << 20)
	if state.session.Tool == ToolStrix {
		limit = 4 << 20
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil || len(body) == 0 {
		state.policy.Close()
		http.Error(w, "assessment report unavailable or oversized", http.StatusRequestEntityTooLarge)
		return
	}
	m.mu.Lock()
	if state.finalizing || state.report != nil || state.ctx.Err() != nil {
		m.mu.Unlock()
		http.Error(w, "assessment report already submitted or session ended", http.StatusConflict)
		return
	}
	state.report = body
	m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"session_id": id, "status": "report_received"})
}
