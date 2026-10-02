package checkutil_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/check/checktest"
	"github.com/chainseer-xyz/deckard/internal/check/checkutil"
)

func TestZoneOf(t *testing.T) {
	zones := []string{"example.com", "dev.example.com"}
	cases := map[string]string{
		"a.example.com":     "example.com",
		"x.dev.example.com": "dev.example.com",
		"example.com":       "example.com",
		"notexample.com":    "",
		"foo.example.org":   "",
	}
	for name, want := range cases {
		if got := checkutil.ZoneOf(name, zones); got != want {
			t.Errorf("ZoneOf(%q)=%q want %q", name, got, want)
		}
	}
}

func TestConfigHelpers(t *testing.T) {
	m := map[string]any{"n": 3.0, "s": []any{"a", "b"}, "b": true, "i": []any{1, 2.0}}
	if checkutil.Int(m, "n", 0) != 3 || checkutil.Int(m, "x", 7) != 7 {
		t.Error("Int")
	}
	if got := checkutil.Strings(m, "s", nil); len(got) != 2 {
		t.Error("Strings")
	}
	if got := checkutil.Ints(m, "i", nil); len(got) != 2 || got[1] != 2 {
		t.Error("Ints")
	}
	if !checkutil.Bool(m, "b", false) {
		t.Error("Bool")
	}
	if got := checkutil.Merge(map[string]any{"a": 1, "b": 1}, map[string]any{"b": 2}); got["b"] != 2 || got["a"] != 1 {
		t.Error("Merge")
	}
}

func TestFetchRecordsHopsAndCapsBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := checktest.HostClient(map[string]*httptest.Server{"app.example.com:80": srv})

	r, err := checkutil.Fetch(context.Background(), c, "http://app.example.com/", checkutil.FetchOpts{MaxBody: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Hops) != 2 || r.Hops[0].Status != 302 || r.Hops[0].Location != "/final" {
		t.Errorf("hops: %+v", r.Hops)
	}
	if r.FinalURL != "http://app.example.com/final" || len(r.Body) != 10 || !r.Truncated {
		t.Errorf("resp: %+v", r)
	}
	if _, err := checkutil.Fetch(context.Background(), c, "http://other.example.com/", checkutil.FetchOpts{}); err == nil {
		t.Error("unrouted host should fail")
	}
}
