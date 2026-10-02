package metrics_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/metrics"
)

func TestServeListenerBearerToken(t *testing.T) {
	m := metrics.New("dev", "none")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- metrics.ServeListener(ctx, ln, m.Registry(), metrics.WithToken("s3cret-scrape-token")) }()

	get := func(authz string) int {
		req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/metrics", nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 401 && resp.Header.Get("WWW-Authenticate") == "" {
			t.Error("401 without WWW-Authenticate")
		}
		return resp.StatusCode
	}
	for authz, want := range map[string]int{
		"":                               401,
		"Bearer wrong":                   401,
		"Bearer s3cret-scrape-token ":    200, // trailing space tolerated
		"Basic czNjcmV0":                 401,
		"Bearer":                         401,
		"bearer s3cret-scrape-token":     200,
		"Bearer s3cret-scrape-tokenX":    401,
		"Bearer s3cret-scrape-toke":      401,
		"Bearer s3cret-scrape-token\t ?": 401,
	} {
		if got := get(authz); got != want {
			t.Errorf("Authorization %q = %d, want %d", authz, got, want)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("did not shut down")
	}
}

func TestServeListenerEmptyTokenIsOpen(t *testing.T) {
	m := metrics.New("dev", "none")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = metrics.ServeListener(ctx, ln, m.Registry(), metrics.WithToken("")) }()
	resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("open metrics = %d", resp.StatusCode)
	}
}
