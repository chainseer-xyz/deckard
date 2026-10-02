package checktest

import (
	"net"
	"testing"
)

// ServePlain starts a plaintext TCP listener that replies with banner and
// closes. Returns its address; closed on test cleanup.
func ServePlain(t testing.TB, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte(banner))
			}(c)
		}
	}()
	return ln.Addr().String()
}
