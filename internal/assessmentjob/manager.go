package assessmentjob

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/idna"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8s "k8s.io/client-go/kubernetes"

	"github.com/chainseer-xyz/deckard/internal/assessment"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

type resourceRef struct {
	kind, name string
	uid        types.UID
}
type sessionState struct {
	session    Session
	input      PlanInput
	proxy      *assessment.Proxy
	policy     *assessment.Policy
	resources  []resourceRef
	report     []byte
	jobUID     string
	runtimeUID string
	finalizing bool
	uploading  bool
	finished   bool
	lifecycle  chan struct{}
	doneOnce   sync.Once
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
}

// Manager owns only explicit assessment Jobs and their scoped resources. Its
// sessions are intentionally not recovered as clean after a controller restart.
type Manager struct {
	settings     Settings
	assets       AssetStore
	guard        *scope.Guard
	kube         k8s.Interface
	complete     CompletionFunc
	ctx          context.Context
	cancel       context.CancelFunc
	startMu      sync.Mutex
	mu           sync.RWMutex
	sessions     map[string]*sessionState
	proxyTokens  map[string]string
	uploadTokens map[string]string
	uploadSlots  chan struct{}
	wg           sync.WaitGroup
	closed       bool
	closeOnce    sync.Once
}

func NewManager(settings Settings, assets AssetStore, guard *scope.Guard, kube k8s.Interface, complete CompletionFunc) (*Manager, error) {
	var err error
	settings, err = normalizeSettings(settings)
	if err != nil {
		return nil, err
	}
	if assets == nil || guard == nil || kube == nil || complete == nil {
		return nil, fmt.Errorf("%w: missing manager dependency", ErrRefused)
	}
	images := make(map[Tool]string, len(settings.Images))
	for tool, image := range settings.Images {
		images[tool] = image
	}
	settings.Images = images
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{settings: settings, assets: assets, guard: guard, kube: kube, complete: complete, ctx: ctx, cancel: cancel, sessions: make(map[string]*sessionState), proxyTokens: make(map[string]string), uploadTokens: make(map[string]string), uploadSlots: make(chan struct{}, settings.MaxRunning)}, nil
}

func (m *Manager) Start(ctx context.Context, request Request) (Session, error) {
	// Register the synchronous start before Close can begin waiting. Starts
	// already admitted also observe manager cancellation during Kubernetes I/O.
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return Session{}, fmt.Errorf("%w: manager stopped", ErrRefused)
	}
	m.wg.Add(1)
	m.mu.Unlock()
	defer m.wg.Done()
	ctx, cancelStart := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, cancelStart)
	defer func() { stop(); cancelStart() }()
	m.startMu.Lock()
	defer m.startMu.Unlock()
	if m.ctx.Err() != nil {
		return Session{}, fmt.Errorf("%w: manager stopped", ErrRefused)
	}
	if len(request.AssetIDs) == 0 || len(request.AssetIDs) > 16 {
		return Session{}, fmt.Errorf("%w: invalid asset count", ErrRefused)
	}
	targets, err := m.targets(ctx, request.AssetIDs)
	if err != nil {
		return Session{}, err
	}
	if err := m.verifyNamespace(ctx); err != nil {
		return Session{}, err
	}
	if err := m.cleanupOrphans(ctx); err != nil {
		return Session{}, err
	}
	m.mu.Lock()
	now := time.Now().UTC()
	for id, state := range m.sessions {
		if now.After(state.session.ExpiresAt) && (state.session.Status == "complete" || state.session.Status == "partial" || state.session.Status == "failed") {
			delete(m.sessions, id)
		}
	}
	running := 0
	for _, state := range m.sessions {
		if state.session.Status == "starting" || state.session.Status == "running" || state.finalizing {
			running++
		}
	}
	full := len(m.sessions) >= m.settings.MaxSessions || running >= m.settings.MaxRunning
	m.mu.Unlock()
	if full {
		return Session{}, fmt.Errorf("%w: assessment capacity exhausted", ErrRefused)
	}
	jobs, err := m.kube.BatchV1().Jobs(m.settings.Namespace).List(ctx, metav1.ListOptions{LabelSelector: ManagedLabel + "=" + ManagedValue})
	if err != nil {
		return Session{}, fmt.Errorf("%w: cannot verify existing job capacity", ErrRefused)
	}
	active := 0
	for _, job := range jobs.Items {
		if !terminalJob(&job) {
			active++
		}
	}
	if active >= m.settings.MaxRunning {
		return Session{}, fmt.Errorf("%w: existing jobs exhaust capacity", ErrRefused)
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return Session{}, fmt.Errorf("generate assessment identity: %w", err)
	}
	input := PlanInput{ID: id.String(), Tool: request.Tool, Targets: targets}
	input.ProxyToken, err = randomToken()
	if err != nil {
		return Session{}, err
	}
	input.UploadToken, err = randomToken()
	if err != nil {
		return Session{}, err
	}
	input.RuntimeToken, err = randomToken()
	if err != nil {
		return Session{}, err
	}
	origins := make([]string, 0, len(targets))
	for _, target := range targets {
		origins = append(origins, target.Origin)
	}
	sessionCtx, cancel := context.WithTimeout(m.ctx, m.settings.SessionDuration)
	policy, err := assessment.NewPolicy(sessionCtx, m.guard, origins, m.settings.Limits, assessment.WithOwnershipRefresh(m.settings.RefreshOwnership))
	if err != nil {
		cancel()
		return Session{}, fmt.Errorf("%w: target policy refused", ErrRefused)
	}
	proxy, err := assessment.NewProxy(policy, input.ProxyToken)
	if err != nil {
		policy.Close()
		cancel()
		return Session{}, err
	}
	input.CAPEM = proxy.CAPEM()
	plan, err := BuildPlan(ctx, m.settings, input)
	if err != nil {
		policy.Close()
		cancel()
		return Session{}, err
	}
	state := &sessionState{session: Session{ID: input.ID, Tool: request.Tool, AssetIDs: append([]int64(nil), request.AssetIDs...), Status: "starting", CreatedAt: now, ExpiresAt: now.Add(m.settings.SessionDuration), JobName: plan.Job.Name}, input: input, policy: policy, proxy: proxy, ctx: sessionCtx, cancel: cancel, done: make(chan struct{}), lifecycle: make(chan struct{}, 1)}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		policy.Close()
		cancel()
		return Session{}, fmt.Errorf("%w: manager stopped", ErrRefused)
	}
	m.sessions[input.ID] = state
	m.proxyTokens[input.ProxyToken] = input.ID
	m.uploadTokens[input.UploadToken] = input.ID
	m.mu.Unlock()
	if err := m.install(ctx, state, plan); err != nil {
		m.mu.Lock()
		delete(m.proxyTokens, input.ProxyToken)
		delete(m.uploadTokens, input.UploadToken)
		m.mu.Unlock()
		policy.Close()
		cancel()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		cleanupErr := m.cleanup(cleanupCtx, state)
		cleanupCancel()
		m.mu.Lock()
		state.session.Status = "failed"
		state.session.Reason = "installation_failed"
		if cleanupErr == nil {
			delete(m.sessions, input.ID)
		} else {
			state.session.Reason = "cleanup_pending"
		}
		m.mu.Unlock()
		state.doneOnce.Do(func() { close(state.done) })
		return Session{}, err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		policy.Close()
		cancel()
		return Session{}, fmt.Errorf("%w: manager stopped", ErrRefused)
	}
	if plan.RuntimePod == nil {
		state.session.Status = "running"
	}
	result := cloneSession(state.session)
	m.mu.Unlock()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if plan.RuntimePod != nil {
			m.startStrix(state, plan)
		} else {
			m.watchJob(state)
		}
	}()
	return result, nil
}

func (m *Manager) Get(ctx context.Context, id string) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	state := m.sessions[id]
	if state == nil {
		return Session{}, fmt.Errorf("%w: unknown session", ErrRefused)
	}
	return cloneSession(state.session), nil
}

// Wait waits for this controller's native Job observation and report handling.
// It never assumes an unobserved or previous-controller Job completed cleanly.
func (m *Manager) Wait(ctx context.Context, id string) (Session, error) {
	m.mu.RLock()
	state := m.sessions[id]
	m.mu.RUnlock()
	if state == nil {
		return Session{}, fmt.Errorf("%w: unknown session", ErrRefused)
	}
	select {
	case <-state.done:
		return m.Get(ctx, id)
	case <-ctx.Done():
		return Session{}, ctx.Err()
	}
}

// Close fails closed and cleans only resources created by this manager. A new
// process never adopts an old Job's report as a complete observation.
func (m *Manager) Close() {
	m.closeOnce.Do(func() {
		// One shared budget bounds shutdown even when every session needs API
		// cleanup. Cancellation precedes lifecycle locks and report callbacks.
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
		defer cancel()
		m.mu.Lock()
		m.closed = true
		m.cancel()
		states := make([]*sessionState, 0, len(m.sessions))
		for _, state := range m.sessions {
			states = append(states, state)
			delete(m.proxyTokens, state.input.ProxyToken)
			delete(m.uploadTokens, state.input.UploadToken)
		}
		m.mu.Unlock()
		var cleanup sync.WaitGroup
		for _, state := range states {
			state.cancel()
			state.policy.Close()
			cleanup.Add(1)
			go func() {
				defer cleanup.Done()
				_ = m.cleanup(ctx, state)
				m.mu.Lock()
				if !state.finished {
					state.session.Status = "failed"
					if !state.session.CleanupPending {
						state.session.Reason = "manager_stopped"
					}
					state.finished = true
				}
				state.doneOnce.Do(func() { close(state.done) })
				m.mu.Unlock()
			}()
		}
		done := make(chan struct{})
		go func() { cleanup.Wait(); m.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-ctx.Done():
			for _, state := range states {
				m.markCleanupPending(state)
			}
		}
	})
}

func cloneSession(session Session) Session {
	session.AssetIDs = append([]int64(nil), session.AssetIDs...)
	return session
}

func cloneTargets(targets []Target) []Target {
	out := append([]Target(nil), targets...)
	for index := range out {
		out[index].Addresses = append([]netip.Addr(nil), out[index].Addresses...)
	}
	return out
}
func randomToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate assessment token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:]), nil
}

func (m *Manager) targets(ctx context.Context, ids []int64) ([]Target, error) {
	if m.settings.RefreshOwnership != nil && m.settings.RefreshOwnership(ctx) != nil {
		return nil, fmt.Errorf("%w: ownership refresh unavailable", ErrRefused)
	}
	seen := make(map[int64]bool)
	targets := make([]Target, 0, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return nil, fmt.Errorf("%w: invalid or repeated asset ID", ErrRefused)
		}
		seen[id] = true
		asset, err := m.assets.GetAsset(ctx, id)
		if err != nil || asset == nil || asset.RemovedAt != nil || asset.Scope != model.ScopeOwned {
			return nil, fmt.Errorf("%w: asset is not currently live and owned", ErrRefused)
		}
		origin, err := assetOrigin(*asset)
		if err != nil {
			return nil, err
		}
		parsed, err := url.Parse(origin)
		if err != nil || !m.guard.VerifyOwnedTarget(ctx, parsed.Hostname()) {
			return nil, fmt.Errorf("%w: destination is not fully owned", ErrRefused)
		}
		answers, err := m.guard.Resolver(model.TierActive, model.ScopeOwned, nil).LookupHost(ctx, parsed.Hostname())
		if err != nil || len(answers) == 0 || len(answers) > 16 {
			return nil, fmt.Errorf("%w: destination addresses unavailable or excessive", ErrRefused)
		}
		port, _ := strconv.ParseUint(parsed.Port(), 10, 16)
		target := Target{AssetID: id, Origin: origin, Port: uint16(port)}
		unique := make(map[netip.Addr]bool)
		for _, raw := range answers {
			address, err := netip.ParseAddr(raw)
			if err != nil || m.guard.Classify(model.KindIP, address.String()) != model.ScopeOwned || address.Unmap() == m.settings.BrokerIP.Unmap() {
				return nil, fmt.Errorf("%w: destination address not owned or broker address", ErrRefused)
			}
			address = address.Unmap()
			if !unique[address] {
				target.Addresses = append(target.Addresses, address)
				unique[address] = true
			}
		}
		if m.guard.Classify(model.KindHostname, parsed.Hostname()) != model.ScopeOwned {
			return nil, fmt.Errorf("%w: hostname ownership revoked", ErrRefused)
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func assetOrigin(asset model.Asset) (string, error) {
	var raw string
	switch asset.Kind {
	case model.KindURL:
		raw = asset.Key
	case model.KindHostname, model.KindIP:
		raw = "https://" + net.JoinHostPort(asset.Key, "443")
	case model.KindService:
		host, port, err := net.SplitHostPort(strings.TrimSuffix(asset.Key, "/tcp"))
		if err != nil {
			return "", fmt.Errorf("%w: invalid service", ErrRefused)
		}
		scheme := "http"
		if port == "443" {
			scheme = "https"
		}
		raw = scheme + "://" + net.JoinHostPort(host, port)
	default:
		return "", fmt.Errorf("%w: metadata assets are not assessment targets", ErrRefused)
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("%w: invalid network target", ErrRefused)
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return "", fmt.Errorf("%w: invalid target port", ErrRefused)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return "", fmt.Errorf("%w: invalid target address", ErrRefused)
		}
		host = address.Unmap().String()
	} else {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil {
			return "", fmt.Errorf("%w: invalid target hostname", ErrRefused)
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(host, strconv.FormatUint(number, 10)), nil
}
