package fakestore

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func findingGroupKey(f model.Finding, by string) string {
	switch by {
	case "asset":
		return f.AssetKey
	case "check":
		return f.Check
	default:
		return f.Zone
	}
}

func findingKEV(f model.Finding) bool {
	for _, tag := range f.Tags {
		if strings.EqualFold(tag, "kev") {
			return true
		}
	}
	return f.Evidence["kev"] == true
}

var expiryTitle = regexp.MustCompile(`(?i)\b(expired|expires|expiring|expiry)\b`)

func attentionRank(f model.Finding) int {
	if strings.Contains(strings.ToLower(f.Check), "takeover") {
		return 0
	}
	for _, tag := range f.Tags {
		if tag == "takeover" {
			return 0
		}
	}
	_, expires := f.Evidence["not_after"]
	_, remaining := f.Evidence["days_remaining"]
	if strings.Contains(strings.ToLower(f.Check), "cert") && (expires || remaining) || expiryTitle.MatchString(f.Title) {
		return 1
	}
	return 2
}

func findingLess(a, b model.Finding, f store.FindingFilter) bool {
	if f.Sort == "" {
		return a.ID < b.ID
	}
	if f.Sort == "attention" {
		if attentionRank(a) != attentionRank(b) {
			return attentionRank(a) < attentionRank(b)
		}
		if a.Severity != b.Severity {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if findingKEV(a) != findingKEV(b) {
			return findingKEV(a)
		}
		if !a.FirstSeen.Equal(b.FirstSeen) {
			return a.FirstSeen.Before(b.FirstSeen)
		}
		return a.ID < b.ID
	}
	if f.Sort == "severity" {
		if a.Severity != b.Severity {
			if f.Direction == "asc" {
				return a.Severity.Rank() < b.Severity.Rank()
			}
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
	} else {
		at, bt := a.LastSeen, b.LastSeen
		if f.Sort == "first_seen" {
			at, bt = a.FirstSeen, b.FirstSeen
		}
		if !at.Equal(bt) {
			if f.Direction == "asc" {
				return at.Before(bt)
			}
			return at.After(bt)
		}
		if a.Severity != b.Severity {
			return a.Severity.Rank() > b.Severity.Rank()
		}
	}
	return a.ID < b.ID
}

func (s *Store) ListFindingGroups(ctx context.Context, f store.FindingFilter) ([]store.FindingGroup, int, error) {
	limit, offset := f.Limit, f.Offset
	f.Limit, f.Offset = 0, 0
	items, _, err := s.ListFindings(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	groups := map[string]*store.FindingGroup{}
	for _, item := range items {
		key := findingGroupKey(item, f.GroupBy)
		g := groups[key]
		if g == nil {
			g = &store.FindingGroup{Key: key, Label: key, Counts: map[string]int{}, Top: model.SeverityInfo}
			if key == "" {
				g.Label = "(no zone)"
			}
			groups[key] = g
		}
		g.Total++
		g.Counts[string(item.Severity)]++
		if item.Severity.Rank() > g.Top.Rank() {
			g.Top = item.Severity
		}
	}
	var out []store.FindingGroup
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if f.Sort != "count" && out[i].Top != out[j].Top {
			return out[i].Top.Rank() > out[j].Top.Rank()
		}
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].Key < out[j].Key
	})
	lo, hi := page(len(out), limit, offset)
	return out[lo:hi], len(out), nil
}

func (s *Store) AssetSummaries(_ context.Context, ids []int64) ([]store.AssetSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.AssetSummary
	for _, id := range ids {
		v := store.AssetSummary{AssetID: id, TopSeverity: model.SeverityInfo}
		for _, f := range s.Findings {
			if f.AssetID == id && f.Status == model.StatusOpen {
				v.OpenFindings++
				if f.Severity.Rank() > v.TopSeverity.Rank() {
					v.TopSeverity = f.Severity
				}
			}
		}
		for _, scan := range s.Scans {
			if scan.AssetID == id && (v.LastScan == nil || scan.StartedAt.After(*v.LastScan)) {
				t := scan.StartedAt
				v.LastScan = &t
			}
		}
		out = append(out, v)
	}
	return out, nil
}
