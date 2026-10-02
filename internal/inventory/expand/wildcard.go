package expand

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/check"
)

// WildcardInfo describes whether a zone answers for names that do not exist.
type WildcardInfo struct {
	Zone       string
	IsWildcard bool
	// Answers is the union of addresses returned for the random probe labels.
	Answers []string
}

const wildcardProbes = 3

// RandomLabel returns a 16-hex-char label that cannot plausibly exist.
func RandomLabel() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "deckard-" + hex.EncodeToString(b[:])
}

// DetectWildcard resolves three random labels under zone. If any resolves the
// zone has wildcard DNS; the answers seen are recorded so candidates that only
// exist because of the wildcard can be dropped. A zone where every probe fails
// with something other than NXDOMAIN (e.g. the guard refused it, resolver
// down) is an error, never "no wildcard".
func DetectWildcard(ctx context.Context, r check.Resolver, zone string) (WildcardInfo, error) {
	return DetectWildcardWith(ctx, r, zone, RandomLabel)
}

// DetectWildcardWith is DetectWildcard with an injectable label generator.
func DetectWildcardWith(ctx context.Context, r check.Resolver, zone string, label func() string) (WildcardInfo, error) {
	zone = normName(zone)
	info := WildcardInfo{Zone: zone}
	if zone == "" {
		return info, errors.New("wildcard: empty zone")
	}
	answers := map[string]bool{}
	var firstErr error
	failures, answered := 0, false
	for i := 0; i < wildcardProbes; i++ {
		if err := ctx.Err(); err != nil {
			return info, err
		}
		addrs, err := r.LookupHost(ctx, label()+"."+zone)
		switch {
		case err == nil:
			for _, a := range addrs {
				answers[normAddr(a)] = true
			}
			answered = true
		case isNotFound(err):
		default:
			failures++
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if failures == wildcardProbes {
		return info, fmt.Errorf("wildcard: all probes for %s failed: %w", zone, firstErr)
	}
	info.IsWildcard = answered
	for a := range answers {
		info.Answers = append(info.Answers, a)
	}
	sort.Strings(info.Answers)
	return info, nil
}

func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

func normAddr(a string) string {
	if ip := net.ParseIP(strings.TrimSpace(a)); ip != nil {
		return ip.String()
	}
	return strings.ToLower(strings.TrimSpace(a))
}

// Matches reports whether a candidate's addresses are explained entirely by
// the wildcard: every address is one a random label also got. A candidate with
// no addresses at all never matches (nothing to compare).
func (w WildcardInfo) Matches(addrs []string) bool {
	if !w.IsWildcard || len(addrs) == 0 {
		return false
	}
	known := make(map[string]bool, len(w.Answers))
	for _, a := range w.Answers {
		known[a] = true
	}
	for _, a := range addrs {
		if !known[normAddr(a)] {
			return false
		}
	}
	return true
}

// Candidate is a discovered hostname, optionally with its resolved addresses.
type Candidate struct {
	Name   string
	Zone   string
	Origin string // "ct" | "dns_bruteforce"
	Addrs  []string
}

// Filter drops candidates that only exist because of the zone's wildcard: names
// that resolve to exactly the addresses random labels resolved to. If the zone
// has no wildcard, no DNS is performed and every name passes. A real host that
// happens to share the wildcard's address cannot be told apart and is dropped;
// give it its own address or add it via a source.
func Filter(ctx context.Context, r check.Resolver, names []string, info WildcardInfo, origin string) ([]Candidate, error) {
	out := make([]Candidate, 0, len(names))
	for _, n := range names {
		n = normName(n)
		if !info.IsWildcard {
			out = append(out, Candidate{Name: n, Zone: info.Zone, Origin: origin})
			continue
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		addrs, err := r.LookupHost(ctx, n)
		if err != nil && !isNotFound(err) {
			continue // cannot tell; do not add on a failed lookup in a wildcard zone
		}
		if info.Matches(addrs) {
			continue
		}
		out = append(out, Candidate{Name: n, Zone: info.Zone, Origin: origin, Addrs: addrs})
	}
	return out, nil
}
