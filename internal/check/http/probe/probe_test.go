package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/model"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExtractTitle(t *testing.T) {
	if got := ExtractTitle(fixture(t, "wordpress.html")); got != "Acme & Sons Blog" {
		t.Errorf("title = %q", got)
	}
	if got := ExtractTitle([]byte("<p>none</p>")); got != "" {
		t.Errorf("title = %q", got)
	}
	long := "<title>" + strings.Repeat("a", 500) + "</title>"
	if got := ExtractTitle([]byte(long)); len(got) != 200 {
		t.Errorf("len = %d", len(got))
	}
}

func TestDetectTech(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		body []byte
		want []string
	}{
		{"nginx+php", http.Header{"Server": {"nginx/1.25.3"}, "X-Powered-By": {"PHP/8.2"}}, nil, []string{"nginx", "php"}},
		{"wordpress body", http.Header{"Server": {"Apache/2.4.58"}}, fixture(t, "wordpress.html"), []string{"apache", "wordpress"}},
		{"grafana", http.Header{}, fixture(t, "grafana.html"), []string{"grafana"}},
		{"iis+asp", http.Header{"Server": {"Microsoft-IIS/10.0"}, "X-Powered-By": {"ASP.NET"}}, nil, []string{"asp.net", "iis"}},
		{"express cookie", http.Header{"X-Powered-By": {"Express"}, "Set-Cookie": {"connect.sid=abc; Path=/"}}, nil, []string{"express"}},
		{"jenkins header", http.Header{"X-Jenkins": {"2.440"}}, nil, []string{"jenkins"}},
		{"nothing", http.Header{}, []byte("hi"), []string{}},
	}
	for _, c := range cases {
		if got := DetectTech(c.h, c.body); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v want %v", c.name, got, c.want)
		}
	}
}

func servers(t *testing.T) (client *http.Client) {
	t.Helper()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		_, _ = w.Write(fixture(t, "wordpress.html"))
	}))
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.example.com/", http.StatusMovedPermanently)
	}))
	t.Cleanup(func() { tlsSrv.Close(); plain.Close() })
	return checktest.HostClient(map[string]*httptest.Server{
		"app.example.com:443": tlsSrv, "www.example.com:443": tlsSrv, "app.example.com:80": plain,
	})
}

func TestRunHostname(t *testing.T) {
	tg := checktest.NewTarget(checktest.Hostname("app.example.com", "example.com"), checktest.WithHTTP(servers(t)))
	res, err := New(nil).Run(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	obs := res.Observations[0].Data
	if obs["status"] != 200 || obs["title"] != "Acme & Sons Blog" || obs["server"] != "nginx/1.25.3" {
		t.Errorf("obs: %+v", obs)
	}
	if tech := obs["tech"].([]string); !reflect.DeepEqual(tech, []string{"nginx", "wordpress"}) {
		t.Errorf("tech: %v", tech)
	}
	results := obs["results"].([]map[string]any)
	if len(results) != 2 || results[1]["status"] != 200 {
		t.Fatalf("results: %+v", results)
	}
	// http redirects (301) to https://www.example.com/ and ends 200.
	if hops := results[1]["redirects"]; hops == nil {
		t.Error("redirect chain missing")
	}

	var urls, hosts []string
	for _, a := range res.Discovered {
		switch a.Kind {
		case model.KindURL:
			urls = append(urls, a.Key)
			if tags, _ := a.Attrs["tech"].([]string); len(tags) != 2 {
				t.Errorf("url attrs tech: %+v", a.Attrs)
			}
		case model.KindHostname:
			hosts = append(hosts, a.Key)
		}
	}
	if !reflect.DeepEqual(urls, []string{"https://app.example.com/", "http://app.example.com/"}) {
		t.Errorf("urls: %v", urls)
	}
	if !reflect.DeepEqual(hosts, []string{"www.example.com"}) {
		t.Errorf("hosts: %v", hosts)
	}
}

func TestRunExternalRedirectNotDiscovered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://login.example.net/", http.StatusFound)
	}))
	ext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	defer ext.Close()
	c := checktest.HostClient(map[string]*httptest.Server{"app.example.com:80": srv, "login.example.net:443": ext})
	tg := checktest.NewTarget(checktest.Hostname("app.example.com", "example.com"), checktest.WithHTTP(c),
		checktest.WithConfig(map[string]any{"schemes": []any{"http"}}))
	res, _ := New(nil).Run(context.Background(), tg)
	for _, a := range res.Discovered {
		if a.Kind == model.KindHostname {
			t.Errorf("out-of-zone redirect target must not be discovered: %+v", a)
		}
	}
}

func TestRunNothingListening(t *testing.T) {
	tg := checktest.NewTarget(checktest.Hostname("app.example.com", "example.com"), checktest.WithHTTP(checktest.HostClient(nil)))
	res, err := New(nil).Run(context.Background(), tg)
	if err != nil || len(res.Discovered) != 0 || len(res.Findings) != 0 {
		t.Errorf("%+v %v", res, err)
	}
	if res.Observations[0].Data["results"].([]map[string]any)[0]["error"] == nil {
		t.Error("error should be recorded")
	}
}

func TestBodyCap(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 3<<20)))
	}))
	defer big.Close()
	c := checktest.HostClient(map[string]*httptest.Server{"app.example.com:80": big})
	tg := checktest.NewTarget(checktest.Hostname("app.example.com", "example.com"), checktest.WithHTTP(c),
		checktest.WithConfig(map[string]any{"schemes": []string{"http"}}))
	res, _ := New(nil).Run(context.Background(), tg)
	if res.Observations[0].Data["results"].([]map[string]any)[0]["truncated"] != true {
		t.Error("body should be flagged truncated at 1 MiB")
	}
}

func TestURLAsset(t *testing.T) {
	c := servers(t)
	a := model.Asset{Kind: model.KindURL, Key: "https://app.example.com/", Zone: "example.com", Scope: model.ScopeOwned}
	res, _ := New(nil).Run(context.Background(), checktest.NewTarget(a, checktest.WithHTTP(c)))
	if len(res.Observations[0].Data["results"].([]map[string]any)) != 1 {
		t.Error("url asset probes only itself")
	}
}

func TestApplies(t *testing.T) {
	c := New(nil)
	if !c.Applies(model.Asset{Kind: model.KindURL, Scope: model.ScopeOwned}) || c.Applies(model.Asset{Kind: model.KindIP, Scope: model.ScopeOwned}) ||
		c.Applies(model.Asset{Kind: model.KindHostname, Scope: model.ScopeShared}) {
		t.Error("Applies")
	}
}
