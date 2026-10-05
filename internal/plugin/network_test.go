package plugin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	scopeguard "github.com/chainseer-xyz/deckard/internal/scope"
)

type brokerResolver struct {
	mu      sync.Mutex
	answers [][]string
	calls   int
}

func (r *brokerResolver) LookupHost(context.Context, string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	answer := r.answers[min(r.calls, len(r.answers)-1)]
	r.calls++
	return answer, nil
}
func (*brokerResolver) LookupCNAME(context.Context, string) (string, error) { return "", nil }
func (*brokerResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (*brokerResolver) LookupNS(context.Context, string) ([]string, error)  { return nil, nil }

type brokerDialer struct {
	address string
	calls   atomic.Int32
}

func (d *brokerDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls.Add(1)
	if host, _, _ := net.SplitHostPort(address); host != "198.51.100.7" {
		return nil, fmt.Errorf("unvetted address: %s", address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func TestPluginSandboxBlocksDirectSockets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("sandboxed plugin reached the socket")
	}))
	defer server.Close()
	c := New(cfgFor("direct-network", map[string]any{"address": server.Listener.Addr().String()}), scope("app.example.com"))
	result, err := c.Run(context.Background(), urlTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) != 1 || result.Observations[0].Data["blocked"] != true {
		t.Fatalf("direct socket was not blocked: %+v", result)
	}
}

func brokerTarget(t *testing.T, answers [][]string, handler http.Handler) (check.Target, *scopeguard.Guard, *brokerDialer) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	dialer := &brokerDialer{address: server.Listener.Addr().String()}
	guard, err := scopeguard.NewGuard(config.ScopeConfig{Include: []string{"198.51.100.7"}},
		scopeguard.WithResolver(&brokerResolver{answers: answers}), scopeguard.WithDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	guard.SetZones([]string{"example.com"})
	target := urlTarget()
	target.HTTP = guard.HTTPClient(model.TierActive, model.ScopeOwned, nil)
	target.Dialer = guard.Dialer(model.TierActive, model.ScopeOwned, nil)
	return target, guard, dialer
}

func TestPluginBrokerUsesGuardedHTTP(t *testing.T) {
	var requests atomic.Int32
	target, guard, dialer := brokerTarget(t, [][]string{{"198.51.100.7"}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != "app.example.com" {
			t.Errorf("lost HTTP host: %q", r.Host)
		}
		_, _ = w.Write([]byte("guarded-response"))
	}))
	c := New(cfgFor("broker-network", map[string]any{"request": networkRequest{Operation: "http", URL: "http://app.example.com/"}}), guard.VerifyOwnedTarget)
	result, err := c.Run(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || dialer.calls.Load() != 1 || result.Observations[0].Data["body"] != "guarded-response" {
		t.Fatalf("broker did not use guarded HTTP: %+v", result)
	}
}

func TestPluginBrokerRefusalCannotBecomeCleanObservation(t *testing.T) {
	for _, test := range []struct {
		name    string
		answers [][]string
		request networkRequest
	}{
		{"rebound-at-dial", [][]string{{"198.51.100.7"}, {"198.51.100.7"}, {"93.184.216.34"}}, networkRequest{Operation: "http", URL: "http://app.example.com/"}},
		{"foreign-target", [][]string{{"198.51.100.7"}}, networkRequest{Operation: "http", URL: "http://outside.example.net/"}},
		{"invalid-operation", [][]string{{"198.51.100.7"}}, networkRequest{Operation: "raw-socket"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, guard, dialer := brokerTarget(t, test.answers, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("refused destination received traffic")
			}))
			// No in-scope neighbour lookup consumes the staged DNS answers.
			target.Neighbours = nil
			c := New(cfgFor("broker-network", map[string]any{"request": test.request}), guard.VerifyOwnedTarget)
			result, err := c.Run(context.Background(), target)
			if err == nil || result != nil || dialer.calls.Load() != 0 {
				t.Fatalf("refusal became a clean result: result=%+v err=%v dials=%d", result, err, dialer.calls.Load())
			}
		})
	}
}

func TestPluginBrokerRechecksOwnership(t *testing.T) {
	target, guard, dialer := brokerTarget(t, [][]string{{"198.51.100.7"}}, http.NotFoundHandler())
	guard.SetOwnedPrefixes([]netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")})
	// Static scope.include still owns the address, but dropping the zone must
	// revoke the hostname immediately regardless of earlier preflight calls.
	if !guard.VerifyOwnedTarget(context.Background(), "app.example.com") {
		t.Fatal("fixture was not owned")
	}
	guard.SetZones(nil)
	b := &broker{plugin: &pluginCheck{verify: guard.VerifyOwnedTarget}, target: target}
	response := b.exchange(context.Background(), networkRequest{Operation: "http", URL: "http://app.example.com/"})
	if response.Error == "" || dialer.calls.Load() != 0 {
		t.Fatalf("ownership revocation ignored: %+v", response)
	}
}
