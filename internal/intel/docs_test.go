package intel

import (
	"os"
	"strings"
	"testing"
)

// TestEgressDocumented keeps the operations guide's egress table in step with
// the allow-list: operators copy it into their firewalls.
func TestEgressDocumented(t *testing.T) {
	b, err := os.ReadFile("../../docs/operations.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for svc, hosts := range StaticHosts() {
		for _, h := range hosts {
			if !strings.Contains(doc, "`"+h+"`") {
				t.Errorf("docs/operations.md does not list %s (service %s)", h, svc)
			}
		}
	}
	cfg, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, svc := range ServiceNames() {
		if !strings.Contains(string(cfg), "`"+svc+"`") {
			t.Errorf("docs/configuration.md does not mention service %s", svc)
		}
	}
}
