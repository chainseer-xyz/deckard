package intel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// BootstrapURL is IANA's RDAP bootstrap registry for domain names (RFC 9224).
const BootstrapURL = "https://data.iana.org/rdap/dns.json"

// Bootstrap maps DNS suffixes to RDAP base URLs. Only entries that passed
// validation are kept; its hosts are the only dynamic part of the rdap
// service's allow-list.
type Bootstrap struct {
	bases map[string]string // suffix (lowercase, no dots at the ends) -> https base URL ending in "/"
	hosts map[string]bool
}

type bootstrapFile struct {
	Version  string            `json:"version"`
	Services []json.RawMessage `json:"services"`
}

// ParseBootstrap parses and validates an RDAP bootstrap file. Entries whose
// URLs are not plain https URLs on a hostname (no IP literal, no userinfo, no
// port other than 443, no query or fragment) are dropped; a file with no
// usable entry is rejected.
func ParseBootstrap(body []byte) (*Bootstrap, error) {
	var f bootstrapFile
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("rdap bootstrap: invalid json: %w", err)
	}
	b := &Bootstrap{bases: map[string]string{}, hosts: map[string]bool{}}
	for _, raw := range f.Services {
		var entry [][]string
		if err := json.Unmarshal(raw, &entry); err != nil || len(entry) != 2 {
			continue
		}
		base, host := "", ""
		for _, u := range entry[1] {
			if bu, h, err := validBaseURL(u); err == nil {
				base, host = bu, h
				break
			}
		}
		if base == "" {
			continue
		}
		added := false
		for _, s := range entry[0] {
			s = strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".")
			if !validDNSName(s) {
				continue
			}
			if _, dup := b.bases[s]; dup {
				continue // first entry wins, as RFC 9224 leaves duplicates undefined
			}
			b.bases[s] = base
			added = true
		}
		if added {
			b.hosts[host] = true
		}
	}
	if len(b.bases) == 0 {
		return nil, errors.New("rdap bootstrap: no usable services")
	}
	return b, nil
}

// validBaseURL accepts only https://<hostname>[:443]/<path>, returning the
// canonical base (path ending in "/") and the lowercase host.
func validBaseURL(raw string) (string, string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", err
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case u.Scheme != "https":
		return "", "", errors.New("not https")
	case u.User != nil:
		return "", "", errors.New("userinfo")
	case u.Port() != "" && u.Port() != "443":
		return "", "", errors.New("non-default port")
	case u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return "", "", errors.New("query or fragment")
	case !validDNSName(host) || !strings.Contains(host, "."):
		return "", "", errors.New("not a hostname")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", "", errors.New("ip literal")
	}
	p := u.EscapedPath()
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return "https://" + host + p, host, nil
}

// validDNSName reports whether s is a lowercase LDH name (labels of 1-63
// letters, digits and inner hyphens; punycode labels qualify).
func validDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	// A purely numeric last label would make the name an IP lookalike.
	last := s[strings.LastIndexByte(s, '.')+1:]
	return strings.Trim(last, "0123456789") != ""
}

// Base returns the RDAP base URL for domain: the entry for its longest
// matching suffix.
func (b *Bootstrap) Base(domain string) (string, bool) {
	if b == nil {
		return "", false
	}
	d := strings.Trim(strings.ToLower(domain), ".")
	for d != "" {
		if base, ok := b.bases[d]; ok {
			return base, true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return "", false
}

// Hosts lists the RDAP hosts the bootstrap allows, sorted.
func (b *Bootstrap) Hosts() []string {
	if b == nil {
		return nil
	}
	out := make([]string, 0, len(b.hosts))
	for h := range b.hosts {
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}

func (b *Bootstrap) allows(host string) bool { return b != nil && b.hosts[host] }
