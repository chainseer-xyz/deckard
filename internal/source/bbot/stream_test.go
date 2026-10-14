package bbot

import (
	"context"
	"strings"
	"testing"
)

func TestParseStreamUsesConfiguredSourceWithoutAuthority(t *testing.T) {
	d, err := Parse(context.Background(), strings.NewReader(`{"type":"DNS_NAME","data":"web.example.com","source":"cloudflare","zone":"example.com","attrs":{"owned":true}}`), "remote-recon")
	if err != nil || d == nil || len(d.Assets) != 1 {
		t.Fatalf("stream import failed: %+v %v", d, err)
	}
	if !d.Partial || len(d.Zones) != 0 || d.Assets[0].Source != "remote-recon" || d.Assets[0].Zone != "" || d.Assets[0].Attrs["owned"] != nil {
		t.Fatalf("caller granted authority: %+v", d)
	}
}
