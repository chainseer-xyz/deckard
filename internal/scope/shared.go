package scope

import (
	_ "embed"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

//go:embed shared_cidrs.txt
var embeddedShared string

// parseCIDRList parses "CIDR [label]" lines; '#' starts a comment. Bare IPs
// become host prefixes. Any malformed line fails the whole parse so a bad
// refresh file never silently shrinks the shared list.
func parseCIDRList(src string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i, line := range strings.Split(src, "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		p, err := parsePrefixOrAddr(f[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return normPrefix(p), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR or IP %q", s)
	}
	a = normAddr(a)
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ReloadShared replaces the file-provided shared ranges with those in path.
// The embedded list is always kept. On error the previous list stays active.
func (g *Guard) ReloadShared(path string) error {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured shared-ranges file
	if err != nil {
		return fmt.Errorf("scope: read shared list: %w", err)
	}
	ps, err := parseCIDRList(string(b))
	if err != nil {
		return fmt.Errorf("scope: shared list %s: %w", path, err)
	}
	g.mu.Lock()
	g.sharedFile = ps
	g.mu.Unlock()
	return nil
}

// SharedPrefixes returns a copy of all known shared-infrastructure ranges.
func (g *Guard) SharedPrefixes() []netip.Prefix {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]netip.Prefix, 0, len(g.sharedEmbedded)+len(g.sharedFile)+len(g.sharedLive))
	out = append(out, g.sharedEmbedded...)
	out = append(out, g.sharedFile...)
	return append(out, g.sharedLive...)
}
