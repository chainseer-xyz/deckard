package expand

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/time/rate"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

//go:embed wordlist.txt
var defaultWordlist string

// DefaultWordlist returns the embedded list of common labels.
func DefaultWordlist() []string {
	w, _ := parseWordlist(strings.NewReader(defaultWordlist))
	return w
}

// LoadWordlist reads one label per line ('#' comments and blanks ignored,
// lower-cased, invalid labels skipped, duplicates removed). An empty path
// returns the embedded default.
func LoadWordlist(path string) ([]string, error) {
	if path == "" {
		return DefaultWordlist(), nil
	}
	f, err := os.Open(path) // #nosec G304 -- operator-configured wordlist path
	if err != nil {
		return nil, fmt.Errorf("wordlist: %w", err)
	}
	defer f.Close()
	w, err := parseWordlist(f)
	if err != nil {
		return nil, fmt.Errorf("wordlist %s: %w", path, err)
	}
	return w, nil
}

func parseWordlist(r interface{ Read([]byte) (int, error) }) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		l := strings.ToLower(strings.TrimSpace(sc.Text()))
		if l == "" || strings.HasPrefix(l, "#") || !validLabel(l) || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out, sc.Err()
}

// Bruteforce resolves each word as a label under zone using r (which MUST be
// the scope-guarded resolver: it refuses names outside owned zones) and
// returns the ones that exist. It is opt-in (expansion.dns_bruteforce).
//
//   - Wildcard DNS is detected first; names that only exist because of the
//     wildcard are dropped.
//   - ratePerSec bounds queries per second (<=0 means 10/s).
//   - It honours ctx between and during queries, returning what was found so
//     far plus ctx.Err().
//   - If every lookup fails with something other than NXDOMAIN (resolver down,
//     zone refused by the guard) it returns an error instead of "found nothing".
func Bruteforce(ctx context.Context, r check.Resolver, zone string, words []string, ratePerSec float64) ([]Candidate, error) {
	zone = normName(zone)
	if zone == "" {
		return nil, errors.New("bruteforce: empty zone")
	}
	if ratePerSec <= 0 {
		ratePerSec = 10
	}
	info, err := DetectWildcard(ctx, r, zone)
	if err != nil {
		return nil, fmt.Errorf("bruteforce %s: %w", zone, err)
	}
	lim := rate.NewLimiter(rate.Limit(ratePerSec), 1)
	var out []Candidate
	attempts, failures := 0, 0
	var firstErr error
	for _, w := range words {
		w = strings.ToLower(strings.TrimSpace(w))
		if !validLabel(w) {
			continue
		}
		if err := lim.Wait(ctx); err != nil {
			// Wait also fails early when the next slot is past the deadline.
			if cerr := ctx.Err(); cerr != nil {
				err = cerr
			} else {
				err = context.DeadlineExceeded
			}
			return sorted(out), err
		}
		name := w + "." + zone
		addrs, err := r.LookupHost(ctx, name)
		attempts++
		if err != nil {
			if ctx.Err() != nil {
				return sorted(out), ctx.Err()
			}
			if !isNotFound(err) {
				failures++
				if firstErr == nil {
					firstErr = err
				}
			}
			continue
		}
		if info.Matches(addrs) || (info.IsWildcard && len(addrs) == 0) {
			continue
		}
		out = append(out, Candidate{Name: name, Zone: zone, Origin: "dns_bruteforce", Addrs: addrs})
	}
	if attempts > 0 && failures == attempts {
		return nil, fmt.Errorf("bruteforce %s: all %d lookups failed: %w", zone, attempts, firstErr)
	}
	return sorted(out), nil
}

func sorted(c []Candidate) []Candidate {
	sort.Slice(c, func(i, j int) bool { return c[i].Name < c[j].Name })
	return c
}

// AssetInput converts a candidate into an inventory asset. source names the
// provenance (e.g. "expansion:ct"); the inventory service still classifies it
// and keeps it only if it falls under an owned zone.
func (c Candidate) AssetInput(source string) model.AssetInput {
	attrs := map[string]any{"discovered_by": c.Origin}
	if len(c.Addrs) > 0 {
		addrs := append([]string(nil), c.Addrs...)
		sort.Strings(addrs)
		attrs["resolved"] = addrs
	}
	return model.AssetInput{Kind: model.KindHostname, Key: c.Name, Source: source, Zone: c.Zone, Attrs: attrs}
}

// AssetInputs converts candidates, skipping duplicate names.
func AssetInputs(cands []Candidate, source string) []model.AssetInput {
	seen := map[string]bool{}
	out := make([]model.AssetInput, 0, len(cands))
	for _, c := range cands {
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		out = append(out, c.AssetInput(source))
	}
	return out
}
