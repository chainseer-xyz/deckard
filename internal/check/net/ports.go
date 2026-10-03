// Package netcheck holds the active network checks: net.ports (TCP connect
// scan) and net.services (read-only banner/handshake fingerprinting). Both
// use only the scope-guarded Target.Dialer.
package netcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/chainseer-xyz/deckard/internal/check"
	"github.com/chainseer-xyz/deckard/internal/model"
)

// Checks returns the net checks. defaults is the global per-check config map
// (config `checks:`); Target.Config overlays it at run time.
func Checks(defaults map[string]map[string]any) []check.Check {
	return []check.Check{
		&portsCheck{defaults: defaults["net.ports"]},
		&servicesCheck{defaults: defaults["net.services"]},
	}
}

type portClass struct {
	name     string
	class    string
	severity model.Severity
}

// portTable classifies ports whose exposure to the internet is notable.
var portTable = map[int]portClass{
	21:    {"FTP", "legacy-transfer", model.SeverityMedium},
	22:    {"SSH", "remote-admin", model.SeverityLow},
	23:    {"Telnet", "remote-admin", model.SeverityHigh},
	25:    {"SMTP", "mail", model.SeverityLow},
	445:   {"SMB", "file-sharing", model.SeverityHigh},
	1433:  {"MSSQL", "database", model.SeverityHigh},
	2375:  {"Docker API", "remote-admin", model.SeverityCritical},
	2379:  {"etcd", "database", model.SeverityHigh},
	3306:  {"MySQL", "database", model.SeverityHigh},
	3389:  {"RDP", "remote-admin", model.SeverityHigh},
	5432:  {"PostgreSQL", "database", model.SeverityHigh},
	5900:  {"VNC", "remote-admin", model.SeverityHigh},
	6379:  {"Redis", "cache", model.SeverityHigh},
	9200:  {"Elasticsearch", "database", model.SeverityHigh},
	11211: {"Memcached", "cache", model.SeverityHigh},
	27017: {"MongoDB", "database", model.SeverityHigh},
	80:    {"HTTP", "web", model.SeverityInfo},
	443:   {"HTTPS", "web", model.SeverityInfo},
	8080:  {"HTTP alt", "web", model.SeverityInfo},
	8443:  {"HTTPS alt", "web", model.SeverityInfo},
}

type portsCheck struct{ defaults map[string]any }

func (*portsCheck) Name() string     { return "net.ports" }
func (*portsCheck) Tier() model.Tier { return model.TierActive }
func (*portsCheck) Applies(a model.Asset) bool {
	return a.Kind == model.KindIP && a.Scope == model.ScopeOwned
}

func (c *portsCheck) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	cfg := merge(c.defaults, t.Config)
	ports, err := cfgPorts(cfg, "ports")
	if err != nil {
		return nil, fmt.Errorf("net.ports: %w", err)
	}
	if ports == nil {
		if ports, err = ParsePorts("top-1000"); err != nil {
			return nil, err
		}
	}
	excl, err := cfgPorts(cfg, "exclude_ports")
	if err != nil {
		return nil, fmt.Errorf("net.ports exclude_ports: %w", err)
	}
	allowed, err := cfgPorts(cfg, "allowed_ports")
	if err != nil {
		return nil, fmt.Errorf("net.ports allowed_ports: %w", err)
	}
	ports = without(ports, excl)

	ip := t.Asset.Key
	open, err := scan(ctx, t.Dialer, ip, ports, cfgInt(cfg, "concurrency", 100), cfgDuration(cfg, "timeout", 2*time.Second))
	if err != nil {
		return nil, err // never report a partial scan: it would resolve findings wrongly
	}
	return buildPortsResult(ip, open, allowed, baselinePorts(t.Baseline), cfg, ports), nil
}

func without(ports, excl []int) []int {
	if len(excl) == 0 {
		return ports
	}
	skip := map[int]bool{}
	for _, p := range excl {
		skip[p] = true
	}
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if !skip[p] {
			out = append(out, p)
		}
	}
	return out
}

// scan connect-scans ports with bounded concurrency and returns sorted open ports.
func scan(ctx context.Context, d check.Dialer, host string, ports []int, conc int, timeout time.Duration) ([]int, error) {
	if d == nil {
		return nil, fmt.Errorf("net.ports: no dialer in target")
	}
	if conc < 1 {
		conc = 1
	}
	var (
		mu      sync.Mutex
		open    []int
		limited error
		wg      sync.WaitGroup
		sem     = make(chan struct{}, conc)
	)
	td, _ := d.(check.TimeoutDialer)
loop:
	for _, p := range ports {
		select {
		case <-ctx.Done():
			break loop
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			addr := net.JoinHostPort(host, strconv.Itoa(p))
			var (
				conn net.Conn
				err  error
			)
			if td != nil {
				conn, err = td.DialTimeout(ctx, "tcp", addr, timeout)
			} else {
				cctx, cancel := context.WithTimeout(ctx, timeout)
				conn, err = d.DialContext(cctx, "tcp", addr)
				cancel()
			}
			if err != nil {
				// A dial the rate limiter never let through says nothing
				// about the port; reporting it closed would resolve findings.
				if errors.Is(err, check.ErrRateLimited) {
					mu.Lock()
					limited = err
					mu.Unlock()
				}
				return
			}
			_ = conn.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limited != nil {
		return nil, fmt.Errorf("net.ports: %w", limited)
	}
	sort.Ints(open)
	return open, nil
}

func baselinePorts(b map[string]map[string]any) map[int]bool {
	out := map[int]bool{}
	raw, ok := b["net.ports"]["ports"]
	if !ok {
		return out
	}
	list, _ := cfgPorts(map[string]any{"p": raw}, "p")
	for _, p := range list {
		out[p] = true
	}
	return out
}

func buildPortsResult(ip string, open, allowed []int, baseline map[int]bool, cfg map[string]any, scanned ...[]int) *check.Result {
	res := &check.Result{}
	if open == nil {
		open = []int{}
	}
	coverage := []int{}
	if len(scanned) > 0 {
		coverage = append(coverage, scanned[0]...)
	}
	res.Observations = []model.ObservationInput{{Check: "net.ports", Data: map[string]any{
		"ports":            open,
		"scanned_ports":    coverage,
		"address_families": []string{"ipv4", "ipv6"},
	}}}
	allow := map[int]bool{}
	for _, p := range allowed {
		allow[p] = true
	}
	overrides, _ := cfg["port_severity"].(map[string]any)
	for _, p := range open {
		key := net.JoinHostPort(ip, strconv.Itoa(p)) + "/tcp"
		res.Discovered = append(res.Discovered, model.AssetInput{
			Kind: model.KindService, Key: key, Source: "net.ports",
			Attrs: map[string]any{"ip": ip, "port": p, "proto": "tcp"},
		})
		res.Relations = append(res.Relations, model.RelationInput{
			FromKind: model.KindIP, FromKey: ip, ToKind: model.KindService, ToKey: key, Type: model.RelExposes,
		})
		if allow[p] {
			continue
		}
		pc, known := portTable[p]
		if !known {
			pc = portClass{name: "unknown", class: "other", severity: model.SeverityLow}
		}
		if s, ok := overrides[strconv.Itoa(p)].(string); ok && model.Severity(s).Valid() {
			pc.severity = model.Severity(s)
		}
		inBaseline := baseline[p]
		if inBaseline && !pc.severity.AtLeast(model.SeverityHigh) {
			continue // learned and low-risk: accepted. High-risk ports are always reported.
		}
		res.Findings = append(res.Findings, portFinding(ip, p, pc))
		if len(baseline) > 0 && !inBaseline {
			res.Findings = append(res.Findings, model.FindingInput{
				Check: "net.ports", Key: fmt.Sprintf("drift/%d", p), Severity: model.SeverityLow,
				Title:       fmt.Sprintf("New open port %d/tcp since baseline", p),
				Description: fmt.Sprintf("Port %d/tcp on %s was not open when the baseline was learned.", p, ip),
				Evidence:    map[string]any{"port": p},
				Remediation: "Confirm the new listener is intended; if so add it to allowed_ports, otherwise close it.",
				Tags:        []string{"net", "drift"},
			})
		}
	}
	return res
}

func portFinding(ip string, p int, pc portClass) model.FindingInput {
	return model.FindingInput{
		Check:    "net.ports",
		Key:      fmt.Sprintf("%d/tcp", p),
		Severity: pc.severity,
		Title:    fmt.Sprintf("Open port %d/tcp (%s) reachable on %s", p, pc.name, ip),
		Description: fmt.Sprintf("TCP port %d (%s, class %s) accepted a connection and is not in the allowed_ports list.",
			p, pc.name, pc.class),
		Evidence:    map[string]any{"port": p, "service_guess": pc.name, "class": pc.class},
		Remediation: "Restrict the port with a firewall or security group to the networks that need it, or add it to allowed_ports if the exposure is intended.",
		Tags:        []string{"net", "exposure", pc.class},
	}
}
