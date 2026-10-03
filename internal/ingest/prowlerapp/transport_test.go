package prowlerapp

import (
	"context"
	"net/http"
	"testing"
)

func TestTransportUsesNoProxyUnlessAsked(t *testing.T) {
	if newTransport(false).Proxy != nil {
		t.Fatal("the environment's proxy must not apply by default")
	}
	if newTransport(true).Proxy == nil {
		t.Fatal("proxy support was requested")
	}
	tr := newTransport(false)
	if tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Fatal("TLS must verify and be at least 1.2")
	}
}

func TestCheckRedirect(t *testing.T) {
	c, err := NewClient(Config{BaseURL: "https://prowler.example.com", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(u string) *http.Request {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
		return r
	}
	for u, ok := range map[string]bool{
		"https://prowler.example.com/api/v1/x": true,
		"http://prowler.example.com/api/v1/x":  false,
		"https://other.example.com/api/v1/x":   false,
		"https://prowler.example.com:8443/x":   false,
	} {
		if err := c.checkRedirect(mk(u), []*http.Request{mk("https://prowler.example.com/")}); (err == nil) != ok {
			t.Errorf("%s: %v", u, err)
		}
	}
	if c.checkRedirect(mk("https://prowler.example.com/x"), make([]*http.Request, 4)) == nil {
		t.Error("redirect chain not bounded")
	}
}
