package intel

import (
	"net/netip"
)

// blockedPrefix is a range the client never dials, with the reason logged
// when a metadata host resolves into it.
type blockedPrefix struct {
	p      netip.Prefix
	reason string
}

// blockedPrefixes covers everything that is not ordinary public unicast:
// loopback, private, link-local, CGNAT, multicast, unspecified, reserved,
// documentation and benchmarking ranges, and the IPv6 transition ranges that
// can tunnel to any of them. Cloud metadata endpoints are listed first so the
// log names them.
var blockedPrefixes = func() []blockedPrefix {
	raw := []struct{ cidr, reason string }{
		{"169.254.169.254/32", "cloud-metadata"},
		{"169.254.170.2/32", "cloud-metadata"},
		{"100.100.100.200/32", "cloud-metadata"},
		{"168.63.129.16/32", "cloud-metadata"},
		{"fd00:ec2::254/128", "cloud-metadata"},
		{"0.0.0.0/8", "unspecified"},
		{"10.0.0.0/8", "private"},
		{"100.64.0.0/10", "cgnat"},
		{"127.0.0.0/8", "loopback"},
		{"169.254.0.0/16", "link-local"},
		{"172.16.0.0/12", "private"},
		{"192.0.0.0/24", "reserved"},
		{"192.0.2.0/24", "documentation"},
		{"192.88.99.0/24", "reserved"},
		{"192.168.0.0/16", "private"},
		{"198.18.0.0/15", "benchmarking"},
		{"198.51.100.0/24", "documentation"},
		{"203.0.113.0/24", "documentation"},
		{"224.0.0.0/4", "multicast"},
		{"240.0.0.0/4", "reserved"},
		{"::/128", "unspecified"},
		{"::1/128", "loopback"},
		{"64:ff9b:1::/48", "nat64-local"},
		{"100::/64", "discard"},
		{"2001::/32", "teredo"},
		{"2001:db8::/32", "documentation"},
		{"2002::/16", "6to4"},
		{"fc00::/7", "private"},
		{"fe80::/10", "link-local"},
		{"fec0::/10", "site-local"},
		{"ff00::/8", "multicast"},
	}
	out := make([]blockedPrefix, 0, len(raw))
	for _, r := range raw {
		out = append(out, blockedPrefix{netip.MustParsePrefix(r.cidr), r.reason})
	}
	return out
}()

// nat64 is the well-known NAT64 prefix: the IPv4 address it embeds is checked
// instead, so IPv6-only networks with DNS64 keep working without opening a
// path to private IPv4 space.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// blockedReason returns why a may not be dialled, or "" when it is ordinary
// public unicast.
func blockedReason(a netip.Addr) string {
	if !a.IsValid() {
		return "invalid"
	}
	a = a.Unmap().WithZone("") // a zone would make every prefix test miss
	if a.Is6() && nat64.Contains(a) {
		b := a.As16()
		return blockedReason(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	for _, b := range blockedPrefixes {
		if b.p.Contains(a) {
			return b.reason
		}
	}
	if !a.IsGlobalUnicast() {
		return "not-global-unicast"
	}
	return ""
}

// IsPublicAddr reports whether a is ordinary public unicast: none of the
// ranges the client refuses to dial (private, loopback, link-local, CGNAT,
// documentation, reserved, cloud metadata, ...). Checks use it to skip the
// addresses a third-party service cannot know anything about.
func IsPublicAddr(a netip.Addr) bool { return blockedReason(a) == "" }
