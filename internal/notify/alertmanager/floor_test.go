package alertmanager

import (
	"context"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func sev(id int64, s model.Severity) model.Finding {
	return finding(func(f *model.Finding) {
		f.ID = id
		f.Severity = s
		f.Fingerprint = "fp-" + string(s)
	})
}

func sentFingerprints(m *mock) map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for _, r := range m.reqs {
		for _, a := range r.alerts {
			out[a.Labels["fingerprint"]] = true
		}
	}
	return out
}

func TestMinSeverityDropsOpenAndResolvedBelowTheFloor(t *testing.T) {
	m := newMock(t, nil)
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}, MinSeverity: "medium"}, nil)
	open := []model.Finding{sev(1, model.SeverityInfo), sev(2, model.SeverityLow), sev(3, model.SeverityMedium), sev(4, model.SeverityCritical)}
	if err := n.Notify(context.Background(), open, nil); err != nil {
		t.Fatal(err)
	}
	got := sentFingerprints(m)
	if len(got) != 2 || !got["fp-medium"] || !got["fp-critical"] {
		t.Fatalf("open alerts sent = %v, want only medium and critical", got)
	}

	// Resolutions follow the same rule: the low one was never sent, so its
	// notice must not be either; the high one was, so its notice must be.
	m2 := newMock(t, nil)
	n2, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m2.URL}, MinSeverity: "medium"}, nil)
	res := []model.Finding{sev(5, model.SeverityLow), sev(6, model.SeverityHigh)}
	if err := n2.Notify(context.Background(), nil, res); err != nil {
		t.Fatal(err)
	}
	got = sentFingerprints(m2)
	if len(got) != 1 || !got["fp-high"] {
		t.Fatalf("resolved notices sent = %v, want only high", got)
	}
}

func TestMinSeverityEverythingBelowSendsNothing(t *testing.T) {
	m := newMock(t, nil)
	n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}, MinSeverity: "high"}, nil)
	err := n.Notify(context.Background(),
		[]model.Finding{sev(1, model.SeverityInfo), sev(2, model.SeverityMedium)},
		[]model.Finding{sev(3, model.SeverityLow)})
	if err != nil {
		t.Fatal(err)
	}
	if m.hits.Load() != 0 {
		t.Fatalf("hits = %d, want no request at all", m.hits.Load())
	}
}

func TestMinSeverityDefaultSendsEverything(t *testing.T) {
	for _, floor := range []string{"", "info"} {
		m := newMock(t, nil)
		n, _ := newNotifier(t, config.AlertmanagerConfig{URLs: []string{m.URL}, MinSeverity: floor}, nil)
		odd := sev(9, "bogus") // unknown severities rank below info and must still go out by default
		if err := n.Notify(context.Background(), []model.Finding{sev(1, model.SeverityInfo), odd}, []model.Finding{sev(2, model.SeverityLow)}); err != nil {
			t.Fatal(err)
		}
		if got := sentFingerprints(m); len(got) != 3 {
			t.Fatalf("floor %q: sent %v, want all three", floor, got)
		}
	}
}

func TestMinSeverityInvalidIsRejected(t *testing.T) {
	_, err := New(config.AlertmanagerConfig{URLs: []string{"http://am:9093"}, MinSeverity: "urgent"}, nil, nil)
	if err == nil {
		t.Fatal("an unknown min_severity must be rejected")
	}
}
