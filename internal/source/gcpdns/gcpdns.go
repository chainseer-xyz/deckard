// Package gcpdns discovers Cloud DNS managed zones and their record sets from
// Google Cloud, producing the same asset and relation shapes as the route53
// source so every check works on it unchanged.
package gcpdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/source"
)

// Source implements source.Source for Google Cloud DNS.
type Source struct {
	name           string
	projects       []string
	includePrivate bool
	allow          map[string]bool
	api            API
	log            *slog.Logger
}

// NewWithAPI builds a Source around an explicit API (used by tests).
func NewWithAPI(cfg config.SourceConfig, api API, log *slog.Logger) (*Source, error) {
	if len(cfg.Projects) == 0 {
		return nil, fmt.Errorf("gcpdns %q: projects is required", cfg.Name)
	}
	if log == nil {
		log = slog.Default()
	}
	projects := append([]string(nil), cfg.Projects...)
	sort.Strings(projects)
	allow := map[string]bool{}
	for _, z := range cfg.Zones {
		if z = normalizeName(z); z != "" {
			allow[z] = true
		}
	}
	return &Source{
		name: cfg.Name, projects: dedup(projects), includePrivate: cfg.IncludePrivate,
		allow: allow, api: api, log: log.With("source", cfg.Name, "type", "gcpdns"),
	}, nil
}

// New builds a Source that authenticates with Application Default Credentials.
func New(cfg config.SourceConfig, log *slog.Logger) (*Source, error) {
	return NewWithAPI(cfg, NewClient(ADCTokenSource()), log)
}

// Constructor matches the registry constructor signature.
func Constructor(cfg config.SourceConfig, _ config.ScopeConfig, _ func(string) string, log *slog.Logger) (source.Source, error) {
	return New(cfg, log)
}

// Name returns the configured instance name.
func (s *Source) Name() string { return s.name }

// Type returns "gcpdns".
func (s *Source) Type() string { return "gcpdns" }

func dedup(sorted []string) []string {
	out := sorted[:0]
	for i, v := range sorted {
		if i == 0 || v != sorted[i-1] {
			out = append(out, v)
		}
	}
	return out
}

type projectZone struct {
	project string
	zone    ManagedZone
}

// Discover lists the public managed zones (and private ones when configured)
// of every project and their record sets.
//
// A project the identity cannot list, or a zone whose record sets cannot be
// read, makes the result partial: the rest is still returned and the inventory
// skips removals. Credentials that do not work, an unexpected failure to list
// zones, or no project being readable at all is an error and no result.
func (s *Source) Discover(ctx context.Context) (*source.Discovery, error) {
	b := newBuilder(s.name, s.log)

	var zones []projectZone
	var failed []string
	for _, project := range s.projects {
		zs, err := s.api.ListManagedZones(ctx, project)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var ae *APIError
			if errors.As(err, &ae) && ae.Denied() {
				reason := fmt.Sprintf("gcpdns project %s: managed zones not listed (HTTP %d%s; needs dns.managedZones.list, grant roles/dns.reader)",
					project, ae.Status, upstream(ae))
				failed = append(failed, reason)
				b.skip(reason)
				s.log.Warn("gcpdns: project skipped", "project", project, "status", ae.Status)
				continue
			}
			return nil, fmt.Errorf("gcpdns %q: project %s: %w", s.name, project, err)
		}
		for _, z := range zs {
			zones = append(zones, projectZone{project, z})
		}
	}
	if len(failed) == len(s.projects) {
		return nil, fmt.Errorf("gcpdns %q: no project could be listed: %s", s.name, strings.Join(failed, "; "))
	}

	// Public zones first, then by name and project: output never depends on API
	// order, and a private zone can never shadow a public zone of the same name.
	sort.Slice(zones, func(i, j int) bool {
		a, c := zones[i], zones[j]
		if ap, cp := isPrivate(a.zone), isPrivate(c.zone); ap != cp {
			return !ap
		}
		if an, cn := normalizeName(a.zone.DNSName), normalizeName(c.zone.DNSName); an != cn {
			return an < cn
		}
		if a.project != c.project {
			return a.project < c.project
		}
		return a.zone.Name < c.zone.Name
	})

	matched := map[string]bool{}
	publicNames := map[string]bool{}
	for _, pz := range zones {
		z := pz.zone
		dnsName := normalizeName(z.DNSName)
		if dnsName == "" {
			continue
		}
		private := isPrivate(z)
		if private && !s.includePrivate {
			s.log.Info("gcpdns: skipping private managed zone", "project", pz.project, "zone", z.Name)
			continue
		}
		if len(s.allow) > 0 {
			byName, byDNS := s.allow[strings.ToLower(z.Name)], s.allow[dnsName]
			if !byName && !byDNS {
				continue
			}
			matched[strings.ToLower(z.Name)], matched[dnsName] = true, true
		}
		if len(z.PeeringConfig) > 0 && string(z.PeeringConfig) != "null" {
			s.log.Info("gcpdns: skipping peering zone (serves no records of its own)", "project", pz.project, "zone", z.Name)
			continue
		}
		if private && publicNames[dnsName] {
			s.log.Warn("gcpdns: skipping private zone shadowing a public zone of the same name", "project", pz.project, "zone", z.Name, "dns_name", dnsName)
			continue
		}
		if !private {
			publicNames[dnsName] = true
		}

		attrs := map[string]any{
			"project": pz.project, "managed_zone": z.Name, "zone_id": z.ID.String(),
			"visibility": visibility(z),
		}
		if z.DNSSECConfig != nil && z.DNSSECConfig.State != "" {
			attrs["dnssec"] = strings.ToLower(z.DNSSECConfig.State)
		}
		b.addZone(dnsName, attrs)

		rrsets, err := s.api.ListRRSets(ctx, pz.project, z.Name)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if isAuthFailure(err) {
				return nil, fmt.Errorf("gcpdns %q: zone %s in project %s: %w", s.name, z.Name, pz.project, err)
			}
			reason := fmt.Sprintf("gcpdns zone %s in project %s: record sets not listed (%s; needs dns.resourceRecordSets.list, grant roles/dns.reader)",
				z.Name, pz.project, errSummary(err))
			b.skip(reason)
			s.log.Warn("gcpdns: zone record sets skipped", "project", pz.project, "zone", z.Name, "error", err)
			continue
		}
		sort.SliceStable(rrsets, func(i, j int) bool {
			ni, nj := normalizeName(rrsets[i].Name), normalizeName(rrsets[j].Name)
			if ni != nj {
				return ni < nj
			}
			return strings.ToUpper(rrsets[i].Type) < strings.ToUpper(rrsets[j].Type)
		})
		for _, rs := range rrsets {
			b.addRRSet(dnsName, z.Name, pz.project, rs)
		}
	}

	if len(failed) == 0 {
		for z := range s.allow {
			if !matched[z] {
				s.log.Warn("gcpdns: zones allow-list entry matched no managed zone", "entry", z)
			}
		}
	}
	return b.result(), nil
}

func isPrivate(z ManagedZone) bool { return strings.EqualFold(z.Visibility, "private") }

func visibility(z ManagedZone) string {
	if isPrivate(z) {
		return "private"
	}
	return "public"
}

// isAuthFailure reports credentials that do not work. Nothing trustworthy can
// come from such a run, so it is an error rather than a partial result.
func isAuthFailure(err error) bool {
	var ce *CredentialsError
	if errors.As(err, &ce) {
		return true
	}
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusUnauthorized
}

// upstream renders Google's own message for a denied call, e.g. "Cloud DNS API
// has not been used in project X", which is what tells an operator what to fix.
func upstream(ae *APIError) string {
	if ae.Message == "" {
		return ""
	}
	return ": " + ae.Message
}

func errSummary(err error) string {
	var ae *APIError
	if errors.As(err, &ae) {
		return fmt.Sprintf("HTTP %d%s", ae.Status, upstream(ae))
	}
	return err.Error()
}

var _ source.Source = (*Source)(nil)

// Compile-time check that the real client satisfies API.
var _ API = (*Client)(nil)
