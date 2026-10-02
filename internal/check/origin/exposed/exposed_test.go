package exposed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestSimilar(t *testing.T) {
	p := func(s int, title, body string) Page { return Summarise(s, []byte("<title>"+title+"</title>"+body)) }
	cases := []struct {
		name string
		a, b Page
		want bool
	}{
		{"same", p(200, "Acme Home", ""), p(200, "Acme Home", "x"), true},
		{"near title", p(200, "Acme Home Page", ""), p(200, "acme home page", ""), true},
		{"different title", p(200, "Acme Home", ""), p(200, "Welcome to nginx!", ""), false},
		{"different status", p(200, "Acme", ""), p(301, "Acme", ""), false},
		{"expected is error page", p(403, "Blocked", ""), p(403, "Blocked", ""), false},
		{"no titles same body", Summarise(200, []byte("{\"ok\":1}")), Summarise(200, []byte("{\"ok\":1}")), true},
		{"no titles diff body", Summarise(200, []byte("a")), Summarise(200, []byte("b")), false},
	}
	for _, c := range cases {
		if got := Similar(c.a, c.b); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestApplies(t *testing.T) {
	c := New(nil)
	yes := model.Asset{Kind: model.KindIP, Scope: model.ScopeOwned, Attrs: map[string]any{"origin": true}}
	if !c.Applies(yes) {
		t.Error("origin ip")
	}
	no := []model.Asset{
		{Kind: model.KindIP, Scope: model.ScopeOwned},
		{Kind: model.KindIP, Scope: model.ScopeShared, Attrs: map[string]any{"origin": true}},
		{Kind: model.KindHostname, Scope: model.ScopeOwned, Attrs: map[string]any{"origin": true}},
	}
	for i, a := range no {
		if c.Applies(a) {
			t.Errorf("case %d should not apply", i)
		}
	}
}

func site(title string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "app.example.com" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte("<html><title>" + title + "</title></html>"))
	}
}

func setup(t *testing.T, originTitle string, originUp bool) (check.Target, *checktest.Dialer) {
	t.Helper()
	cdn := httptest.NewTLSServer(site("Acme Home"))
	t.Cleanup(cdn.Close)
	routes := map[string]string{}
	if originUp {
		o443 := httptest.NewTLSServer(site(originTitle))
		o80 := httptest.NewServer(site(originTitle))
		t.Cleanup(func() { o443.Close(); o80.Close() })
		routes["192.0.2.10:443"] = o443.Listener.Addr().String()
		routes["192.0.2.10:80"] = o80.Listener.Addr().String()
	}
	d := &checktest.Dialer{Routes: routes}
	ip := model.Asset{Kind: model.KindIP, Key: "192.0.2.10", Scope: model.ScopeOwned, Attrs: map[string]any{"origin": true}}
	tg := checktest.NewTarget(ip,
		checktest.WithDialer(d),
		checktest.WithHTTP(checktest.HostClient(map[string]*httptest.Server{"app.example.com:443": cdn})),
		checktest.WithNeighbours(check.Neighbour{
			Asset:    checktest.Hostname("app.example.com", "example.com"),
			Relation: model.RelOriginOf,
		}))
	return tg, d
}

func TestRunOriginExposed(t *testing.T) {
	tg, d := setup(t, "Acme Home", true)
	res, err := New(nil).Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("want findings on 443 and 80, got %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != model.SeverityHigh || f.Key != "direct:app.example.com:443" || f.Remediation == "" {
		t.Errorf("finding: %+v", f)
	}
	if len(d.Dialed) != 2 {
		t.Errorf("lean probing: want exactly 2 direct dials (one per port), got %v", d.Dialed)
	}
}

func TestRunOriginRespondsDifferently(t *testing.T) {
	tg, _ := setup(t, "Welcome to nginx!", true)
	res, _ := New(nil).Run(context.Background(), tg)
	if len(res.Findings) != 0 {
		t.Errorf("a default page is not the site: %+v", res.Findings)
	}
}

func TestRunOriginFirewalled(t *testing.T) {
	tg, _ := setup(t, "", false)
	res, _ := New(nil).Run(context.Background(), tg)
	if len(res.Findings) != 0 {
		t.Errorf("unreachable origin is the good case: %+v", res.Findings)
	}
}

func TestRunNoHostnamesNoConnections(t *testing.T) {
	tg, d := setup(t, "Acme Home", true)
	tg.Neighbours = nil
	res, _ := New(nil).Run(context.Background(), tg)
	if len(res.Findings) != 0 || len(d.Dialed) != 0 {
		t.Errorf("no hostnames -> no probing: %v %v", res.Findings, d.Dialed)
	}
}

func TestEvidenceReferencesPublishingHostnames(t *testing.T) {
	tg, _ := setup(t, "Acme Home", true)
	tg.Neighbours = append(tg.Neighbours,
		check.Neighbour{Asset: model.Asset{Kind: model.KindHostname, Key: "dev.example.com", Attrs: map[string]any{"proxied": false}}, Relation: model.RelResolvesTo},
		check.Neighbour{Asset: model.Asset{Kind: model.KindHostname, Key: "app.example.com", Attrs: map[string]any{"proxied": true}}, Relation: model.RelResolvesTo})
	res, _ := New(nil).Run(context.Background(), tg)
	if len(res.Findings) == 0 {
		t.Fatal("no findings")
	}
	ev := res.Findings[0].Evidence
	if u, _ := ev["unproxied_hostnames"].([]string); len(u) != 1 || u[0] != "dev.example.com" {
		t.Errorf("evidence: %v", ev)
	}
	if p, _ := ev["proxied_hostnames"].([]string); len(p) != 1 || p[0] != "app.example.com" {
		t.Errorf("evidence: %v", ev)
	}
}
