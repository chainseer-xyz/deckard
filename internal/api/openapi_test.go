package api_test

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.yaml.in/yaml/v3"

	"github.com/chainseer-xyz/deckard/docs"
)

func registeredRoutes(t *testing.T, h http.Handler) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := chi.Walk(h.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOpenAPIDocumentsEveryRouteAndViceVersa(t *testing.T) {
	// Token mode has the API routes; OIDC mode additionally mounts /auth/*.
	routes := registeredRoutes(t, newEnv(t).h)
	for k := range registeredRoutes(t, newEnv(t, oidcDeps).h) {
		routes[k] = true
	}

	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(docs.OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for path, ops := range doc.Paths {
		for method := range ops {
			switch m := strings.ToUpper(method); m {
			case "GET", "POST", "PUT", "PATCH", "DELETE":
				documented[m+" "+path] = true
			}
		}
	}

	var missing, stale []string
	for r := range routes {
		if !documented[r] {
			missing = append(missing, r)
		}
	}
	for d := range documented {
		if !routes[d] {
			stale = append(stale, d)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("routes missing from docs/openapi.yaml: %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("documented but not registered: %v", stale)
	}
	if len(routes) < 20 {
		t.Errorf("suspiciously few routes walked: %d", len(routes))
	}
}

func TestOpenAPIRefsResolve(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(docs.OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["openapi"] == nil {
		t.Fatal("not an OpenAPI document")
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if ref, ok := x["$ref"].(string); ok {
				cur := any(doc)
				for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
					m, ok := cur.(map[string]any)
					if !ok || m[part] == nil {
						t.Errorf("unresolved $ref %s", ref)
						return
					}
					cur = m[part]
				}
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(doc)
}
