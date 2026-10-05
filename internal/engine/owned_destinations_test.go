package engine

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/scope"
)

type ownedDestinationCheck struct {
	*fakeCheck
	required bool
}

func (c ownedDestinationCheck) RequiresOwnedDestinations() bool { return c.required }

type ownedDestinationGuard struct{ *fakeGuard }

func (g ownedDestinationGuard) DNS(tier model.Tier, class model.ScopeClass, _ scope.RateLimiter) check.DNSQuerier {
	g.note(tier, class)
	return nil
}

func TestOwnedDestinationClientsPreserveSchedulingTier(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tier    model.Tier
		require bool
		want    model.Tier
	}{
		{"passive_plugin", model.TierPassive, true, model.TierActive},
		{"ordinary_passive", model.TierPassive, false, model.TierPassive},
		{"active_plugin", model.TierActive, true, model.TierActive},
		{"intrusive_plugin", model.TierIntrusive, true, model.TierIntrusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := hostAsset(1, "app.example.com")
			c := ownedDestinationCheck{fakeCheck: &fakeCheck{name: "plugin.test", tier: tc.tier}, required: tc.require}
			h := newHarness(nil, []model.Asset{a}, c)
			h.r.Guard = ownedDestinationGuard{h.g}
			if err := h.r.runCheck(context.Background(), c, a, nil, model.ScopeOwned, nil); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(h.g.tiers, []model.Tier{tc.want, tc.want, tc.want, tc.want}) {
				t.Fatalf("network client tiers = %v, want all %s", h.g.tiers, tc.want)
			}
			if runs := h.st.runs(); len(runs) != 1 || runs[0].Tier != string(tc.tier) {
				t.Fatalf("recorded tier changed: %+v", runs)
			}
			if len(h.rec.scans) != 1 || h.rec.scans[0].tier != string(tc.tier) {
				t.Fatalf("metric tier changed: %+v", h.rec.scans)
			}
		})
	}
}

type ownedDestinationResolver struct {
	mapResolver
	mu      sync.Mutex
	answers [][]string
	calls   int
}

func (r *ownedDestinationResolver) LookupHost(context.Context, string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	answer := r.answers[min(r.calls, len(r.answers)-1)]
	r.calls++
	return answer, nil
}

func TestPassiveOwnedDestinationCheckRejectsRebindingAtDial(t *testing.T) {
	for _, operation := range []string{"http", "tcp"} {
		for _, destination := range []string{"93.184.216.34", "104.16.0.1"} {
			t.Run(operation+"_"+destination, func(t *testing.T) {
				resolver := &ownedDestinationResolver{answers: [][]string{{"198.51.100.7"}, {"198.51.100.7"}, {destination}}}
				dialer := &countingDialer{}
				guard, err := scope.NewGuard(config.ScopeConfig{Include: []string{"198.51.100.7"}},
					scope.WithResolver(resolver), scope.WithDialer(dialer))
				if err != nil {
					t.Fatal(err)
				}
				guard.SetZones([]string{"example.com"})
				a := hostAsset(1, "app.example.com")
				c := ownedDestinationCheck{fakeCheck: passiveCheck("plugin.test"), required: true}
				c.run = func(ctx context.Context, target check.Target) (*check.Result, error) {
					// Match the plugin's Run preflight and broker request preflight.
					for range 2 {
						if !guard.VerifyOwnedTarget(ctx, a.Key) {
							t.Fatal("owned preflight unexpectedly refused")
						}
					}
					var err error
					if operation == "http" {
						request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+a.Key+"/", nil)
						if requestErr != nil {
							return nil, requestErr
						}
						response, requestErr := target.HTTP.Do(request)
						err = requestErr
						if response != nil {
							_ = response.Body.Close()
						}
					} else {
						conn, dialErr := target.Dialer.DialContext(ctx, "tcp", a.Key+":8080")
						err = dialErr
						if conn != nil {
							_ = conn.Close()
						}
					}
					if !errors.Is(err, scope.ErrOutOfScope) {
						t.Errorf("rebound destination was not refused by scope: %v", err)
					}
					return nil, err
				}
				h := newHarness(func(cfg *testCfg) { cfg.Profiles.Active.Enabled = false }, []model.Asset{a}, c)
				h.r.Guard = guard
				if err := h.r.runScan(context.Background(), scanJob{AssetID: a.ID, Tier: model.TierPassive}); err != nil {
					t.Fatal(err)
				}
				if len(dialer.calls) != 0 || len(h.proc.calls) != 0 {
					t.Fatalf("rebound scan reached a destination or processed findings: dials = %v, processes = %d", dialer.calls, len(h.proc.calls))
				}
				if c.calls.Load() != 1 {
					t.Fatal("disabling the active profile changed passive plugin scheduling")
				}
				if runs := h.st.runs(); len(runs) != 1 || runs[0].Tier != "passive" || runs[0].Error == "" {
					t.Fatalf("refused passive plugin scan = %+v", runs)
				}
			})
		}
	}
}
