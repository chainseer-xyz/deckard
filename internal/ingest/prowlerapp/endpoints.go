package prowlerapp

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Providers lists every provider Prowler knows. Providers that cannot be
// decoded are counted, not guessed at.
func (c *Client) Providers(ctx context.Context) (providers []Provider, undecodable int, err error) {
	q := url.Values{"page[size]": {strconv.Itoa(DefaultPageSize)}}
	err = c.pages(ctx, c.apiURL("/providers", q), func(d *Document) (bool, error) {
		for _, r := range d.Data {
			p, perr := AsProvider(r)
			if perr != nil {
				undecodable++
				continue
			}
			providers = append(providers, p)
		}
		return false, nil
	})
	return providers, undecodable, err
}

// RecentScans returns the newest scans of a provider (one page, newest first
// as the server sorts them). Callers must not rely on the order alone: see
// Scan.Sort.
func (c *Client) RecentScans(ctx context.Context, providerID string) ([]Scan, error) {
	q := url.Values{
		"filter[provider]": {providerID},
		"sort":             {"-attempted_at"},
		"page[size]":       {"20"},
	}
	doc, err := c.get(ctx, c.apiURL("/scans", q))
	if err != nil {
		return nil, err
	}
	scans := make([]Scan, 0, len(doc.Data))
	for _, r := range doc.Data {
		s, err := AsScan(r)
		if err != nil {
			return nil, fmt.Errorf("prowler api: %w", err)
		}
		scans = append(scans, s)
	}
	return scans, nil
}

// FindingsQuery selects the findings of one provider's latest scan.
type FindingsQuery struct {
	ProviderID string
	// Severities are Prowler's severity words (critical, high, medium, low,
	// informational) to ask for; empty asks for all.
	Severities   []string
	IncludeMuted bool
	// Sparse asks the server for only the fields the mapper uses, which keeps
	// raw results and resource details off the wire altogether.
	Sparse bool
}

const (
	sparseFindings  = "uid,delta,status,status_extended,severity,check_id,check_metadata,first_seen_at,muted,scan,resources"
	sparseResources = "uid,name,region,service,type"
)

func (q FindingsQuery) values() url.Values {
	v := url.Values{
		"filter[provider]": {q.ProviderID},
		"filter[status]":   {"FAIL"},
		"include":          {"resources"},
		"sort":             {"check_id"},
		"page[size]":       {strconv.Itoa(DefaultPageSize)},
	}
	if !q.IncludeMuted {
		v.Set("filter[muted]", "false")
	}
	if len(q.Severities) > 0 {
		v.Set("filter[severity__in]", strings.Join(q.Severities, ","))
	}
	if q.Sparse {
		v.Set("fields[findings]", sparseFindings)
		v.Set("fields[resources]", sparseResources)
	}
	return v
}

// LatestFindings pages through /findings/latest for q, calling fn with every
// page (primary findings plus the included resources). fn returns stop to end
// the iteration early.
func (c *Client) LatestFindings(ctx context.Context, q FindingsQuery, fn func(*Document) (stop bool, err error)) error {
	return c.pages(ctx, c.apiURL("/findings/latest", q.values()), fn)
}
