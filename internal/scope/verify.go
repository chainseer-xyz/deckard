package scope

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// VerifyOwnedTarget performs a fresh lookup. A preflight verdict is not a
// network boundary: callers must also use a guarded dialer or DestinationDenylist.
func (g *Guard) VerifyOwnedTarget(ctx context.Context, host string) bool {
	_, err := g.ownedAddresses(ctx, host)
	return err == nil
}

func (g *Guard) ownedAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ip, ok := parseIP(host); ok {
		if g.classifyIP(ip) == model.ScopeOwned {
			return []netip.Addr{ip.Unmap()}, nil
		}
		return nil, fmt.Errorf("scope: address %s is not owned", host)
	}
	name, ok := normHost(host)
	if !ok || g.classifyName(name) != model.ScopeOwned {
		return nil, fmt.Errorf("scope: host %s is not owned", host)
	}
	answers, err := g.resolver.LookupHost(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("scope: resolving %s: %w", name, err)
	}
	if len(answers) == 0 {
		return nil, fmt.Errorf("scope: host %s has no addresses", name)
	}
	var addresses []netip.Addr
	for _, answer := range answers {
		ip, ok := parseIP(answer)
		if !ok || g.classifyIP(ip) != model.ScopeOwned {
			return nil, fmt.Errorf("scope: host %s has an unowned address", name)
		}
		addresses = append(addresses, ip.Unmap())
	}
	return addresses, ctx.Err()
}

// DestinationDenylist returns the CIDR complement of the freshly verified
// addresses. Nuclei enforces this list inside its dialer, including after a DNS
// change. Hostnames and TLS SNI remain unchanged; unrelated addresses are denied.
func (g *Guard) DestinationDenylist(ctx context.Context, hosts []string) ([]string, error) {
	var approved []netip.Addr
	for _, host := range hosts {
		addresses, err := g.ownedAddresses(ctx, host)
		if err != nil {
			return nil, err
		}
		approved = append(approved, addresses...)
		if len(approved) > 1024 {
			return nil, fmt.Errorf("scope: too many scanner destination addresses")
		}
	}
	if len(approved) == 0 {
		return nil, fmt.Errorf("scope: scanner has no approved destinations")
	}
	slices.SortFunc(approved, netip.Addr.Compare)
	approved = slices.Compact(approved)
	var denied []string
	complement(netip.MustParsePrefix("0.0.0.0/0"), approved, &denied)
	complement(netip.MustParsePrefix("::/0"), approved, &denied)
	return denied, nil
}

func complement(prefix netip.Prefix, approved []netip.Addr, denied *[]string) {
	var inside []netip.Addr
	for _, address := range approved {
		if prefix.Contains(address) {
			inside = append(inside, address)
		}
	}
	if len(inside) == 0 {
		*denied = append(*denied, prefix.String())
		return
	}
	if prefix.Bits() == prefix.Addr().BitLen() {
		return
	}
	bits := prefix.Bits()
	bytes := prefix.Addr().As16()
	offset := 0
	if prefix.Addr().Is4() {
		offset = 96
	}
	bytes[(offset+bits)/8] |= 1 << (7 - (offset+bits)%8)
	right := netip.AddrFrom16(bytes)
	if prefix.Addr().Is4() {
		right = right.Unmap()
	}
	complement(netip.PrefixFrom(prefix.Addr(), bits+1), inside, denied)
	complement(netip.PrefixFrom(right, bits+1), inside, denied)
}
