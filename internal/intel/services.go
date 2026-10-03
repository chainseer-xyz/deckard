package intel

import (
	"slices"
	"time"
)

// Service names. A consumer passes one of these to Client.Get.
const (
	ServiceRDAP       = "rdap"
	ServiceInternetDB = "internetdb"
	ServiceWayback    = "wayback"
)

// spec is one metadata service the client may reach.
type spec struct {
	name string
	// hosts is the fixed allow-list (exact hostnames, port 443 only).
	hosts []string
	// bootstrap also allows the RDAP registry hosts published in IANA's
	// bootstrap file (fetched from data.iana.org, which must be in hosts).
	bootstrap bool
	// rate is the default token-bucket rate in requests per second.
	rate float64
}

// registry is every service the client can reach. Adding a service is one line
// here. Hosts cannot be added from configuration: there is deliberately no
// escape hatch that turns this client into a general outbound path.
var registry = []spec{
	{name: ServiceRDAP, hosts: []string{"data.iana.org"}, bootstrap: true, rate: 2},
	{name: ServiceInternetDB, hosts: []string{"internetdb.shodan.io"}, rate: 1},
	{name: ServiceWayback, hosts: []string{"web.archive.org"}, rate: 1},
}

// Defaults applied to every service unless overridden in ServiceConfig.
const (
	DefaultTimeout          = 20 * time.Second
	DefaultMaxBytes         = 2 << 20
	DefaultCacheTTL         = 6 * time.Hour
	DefaultNegativeCacheTTL = 15 * time.Minute
)

// ServiceNames lists the registered services, sorted.
func ServiceNames() []string {
	out := make([]string, 0, len(registry))
	for _, s := range registry {
		out = append(out, s.name)
	}
	slices.Sort(out)
	return out
}

// StaticHosts returns each service's fixed allow-list (RDAP registry hosts
// learned from the bootstrap file come on top of the rdap entry).
func StaticHosts() map[string][]string {
	out := make(map[string][]string, len(registry))
	for _, s := range registry {
		out[s.name] = slices.Clone(s.hosts)
	}
	return out
}

// DefaultRate returns the default requests per second of service (0 when the
// service is unknown).
func DefaultRate(service string) float64 {
	for _, s := range registry {
		if s.name == service {
			return s.rate
		}
	}
	return 0
}
