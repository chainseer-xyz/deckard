package netcheck

import (
	_ "embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// top1000.txt is a curated approximation of a "top 1000" TCP list: all
// well-known ports (1-1024) plus commonly exposed service ports. It is not
// nmap's frequency-ordered list.
//
//go:embed top1000.txt
var top1000Spec string

const top100Spec = "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157"

// ParsePorts expands a port spec: "top-100", "top-1000", numbers and ranges
// ("22,80,443,8000-8100"), freely combined. The result is sorted and unique.
func ParsePorts(spec string) ([]int, error) {
	set := map[int]struct{}{}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		switch strings.ToLower(tok) {
		case "top-100":
			if err := addSpec(set, top100Spec); err != nil {
				return nil, err
			}
			continue
		case "top-1000":
			if err := addSpec(set, top1000Spec); err != nil {
				return nil, err
			}
			continue
		}
		if err := addToken(set, tok); err != nil {
			return nil, err
		}
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("port spec %q selects no ports", spec)
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

func addSpec(set map[int]struct{}, spec string) error {
	for _, tok := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		if err := addToken(set, tok); err != nil {
			return err
		}
	}
	return nil
}

func addToken(set map[int]struct{}, tok string) error {
	lo, hi, isRange := strings.Cut(tok, "-")
	a, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return fmt.Errorf("invalid port %q", tok)
	}
	b := a
	if isRange {
		if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
			return fmt.Errorf("invalid port range %q", tok)
		}
	}
	if a < 1 || b > 65535 || a > b {
		return fmt.Errorf("port out of range %q", tok)
	}
	for p := a; p <= b; p++ {
		set[p] = struct{}{}
	}
	return nil
}
