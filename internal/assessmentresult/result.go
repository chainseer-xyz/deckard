// Package assessmentresult admits only reports bound to a manager's explicit
// session grant. It never retains raw HTTP, credentials or model traces.
package assessmentresult

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"golang.org/x/net/idna"
)

var ErrInvalid = errors.New("assessment report is invalid or outside its session grant")

type Finding struct {
	AssetID int64
	Data    ingest.Finding
}
type Result struct {
	Findings     []Finding
	Observations map[int64][]model.ObservationInput
	Complete     bool
}

func Parse(c assessmentjob.Completion) (Result, error) {
	if len(c.Data) == 0 || len(c.Data) > 32<<20 || len(c.Targets) == 0 || len(c.Targets) > 16 {
		return Result{}, ErrInvalid
	}
	switch c.Session.Tool {
	case assessmentjob.ToolZGrab2:
		return parseZGrab(c)
	case assessmentjob.ToolZAP:
		return parseZAP(c)
	case assessmentjob.ToolStrix:
		return parseStrix(c)
	default:
		return Result{}, ErrInvalid
	}
}

func origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", ErrInvalid
	}
	host, err := canonicalHost(u.Hostname())
	if err != nil {
		return "", err
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(host, port), nil
}

func canonicalHost(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String(), nil
	}
	host, err := idna.Lookup.ToASCII(host)
	if err != nil || host == "" {
		return "", ErrInvalid
	}
	return host, nil
}

func targetOrigins(targets []assessmentjob.Target) (map[string]int64, error) {
	allowed := map[string]int64{}
	for _, target := range targets {
		key, err := origin(target.Origin)
		if err != nil || target.AssetID <= 0 {
			return nil, ErrInvalid
		}
		if id, seen := allowed[key]; seen && id != target.AssetID {
			return nil, ErrInvalid
		}
		allowed[key] = target.AssetID
	}
	return allowed, nil
}

func stableKey(parts ...string) string {
	data, _ := json.Marshal(parts)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type zapReport struct {
	Site []zapSite `json:"site"`
}
type zapSite struct {
	Name   string     `json:"@name"`
	Alerts []zapAlert `json:"alerts"`
}
type zapAlert struct {
	PluginID  string `json:"pluginid"`
	Alert     string `json:"alert"`
	Risk      string `json:"riskcode"`
	Solution  string `json:"solution"`
	CWE       string `json:"cweid"`
	Instances []struct {
		URI    string `json:"uri"`
		Method string `json:"method"`
	} `json:"instances"`
}

func parseZAP(c assessmentjob.Completion) (Result, error) {
	var report zapReport
	if err := json.Unmarshal(c.Data, &report); err != nil || report.Site == nil || len(report.Site) > 128 {
		return Result{}, ErrInvalid
	}
	allowed, err := targetOrigins(c.Targets)
	if err != nil {
		return Result{}, err
	}
	seen, keys := map[string]bool{}, map[string]bool{}
	// ZAP 2.17's passiveScan-wait exits without warning when its time budget
	// expires. Successful Job/site coverage cannot certify a drained queue or
	// an untruncated active scan. Findings remain additive until native proof
	// of both completion conditions is available.
	out := Result{Complete: false}
	severities := map[string]model.Severity{"0": model.SeverityInfo, "1": model.SeverityLow, "2": model.SeverityMedium, "3": model.SeverityHigh}
	for _, site := range report.Site {
		base, err := origin(site.Name)
		if err != nil || allowed[base] == 0 {
			return Result{}, ErrInvalid
		}
		seen[base] = true
		if len(site.Alerts) > 5000 {
			return Result{}, ErrInvalid
		}
		for _, alert := range site.Alerts {
			severity, ok := severities[alert.Risk]
			plugin, err := strconv.ParseUint(alert.PluginID, 10, 32)
			if !ok || err != nil || plugin == 0 || alert.Alert == "" || len(alert.Instances) > 5000 {
				return Result{}, ErrInvalid
			}
			if len(alert.Instances) == 0 {
				out.Complete = false
				continue
			}
			for _, instance := range alert.Instances {
				base, err := origin(instance.URI)
				if err != nil || allowed[base] == 0 {
					return Result{}, ErrInvalid
				}
				safe := ingest.SafeURL(instance.URI)
				method := strings.ToUpper(instance.Method)
				if method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" && method != "HEAD" && method != "OPTIONS" {
					return Result{}, ErrInvalid
				}
				key := stableKey(alert.PluginID, safe, method)
				if keys[key] {
					continue
				}
				keys[key] = true
				// Native descriptions and evidence may contain reflected response
				// bodies or credentials. Keep only rule identity and safe location.
				f := ingest.Finding{Key: key, Title: ingest.Line(alert.Alert, 240), Severity: severity,
					Description: "ZAP reported this rule on the assessment target. Review the rule and reproduce it before remediation.",
					Evidence:    map[string]any{"plugin_id": alert.PluginID, "endpoint": safe, "method": method}, Tags: []string{"zap", "dast"}}
				if cwe, err := strconv.ParseUint(alert.CWE, 10, 32); err == nil && cwe > 0 {
					f.Evidence["cwe"] = "CWE-" + alert.CWE
				}
				out.Findings = append(out.Findings, Finding{AssetID: allowed[base], Data: f})
				if len(out.Findings) > ingest.MaxFindings {
					return Result{}, ErrInvalid
				}
			}
		}
	}
	if len(seen) != len(allowed) {
		out.Complete = false
	}
	return out, nil
}

type zgrabRow struct {
	IP     string `json:"ip"`
	Domain string `json:"domain"`
	Port   uint16 `json:"port"`
	Data   map[string]struct {
		Status string `json:"status"`
		Result struct {
			Response *struct {
				StatusCode int `json:"status_code"`
			} `json:"response"`
		} `json:"result"`
	} `json:"data"`
}

func parseZGrab(c assessmentjob.Completion) (Result, error) {
	allowed := map[string]int64{}
	for _, target := range c.Targets {
		u, err := url.Parse(target.Origin)
		if err != nil {
			return Result{}, ErrInvalid
		}
		host, err := canonicalHost(u.Hostname())
		if err != nil {
			return Result{}, ErrInvalid
		}
		for _, address := range target.Addresses {
			key := address.Unmap().String() + "|" + host + "|" + strconv.Itoa(int(target.Port))
			if id, exists := allowed[key]; exists && id != target.AssetID {
				return Result{}, ErrInvalid
			}
			allowed[key] = target.AssetID
		}
	}
	seen := map[string]bool{}
	endpoints := map[int64][]map[string]any{}
	out := Result{Complete: c.Complete, Observations: map[int64][]model.ObservationInput{}}
	scanner := bufio.NewScanner(bytes.NewReader(c.Data))
	scanner.Buffer(make([]byte, 64<<10), 32<<20)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var row zgrabRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil || len(row.Data) != 1 {
			return Result{}, ErrInvalid
		}
		address, err := netip.ParseAddr(row.IP)
		if err != nil {
			return Result{}, ErrInvalid
		}
		key := address.Unmap().String() + "|" + strings.ToLower(row.Domain) + "|" + strconv.Itoa(int(row.Port))
		id := allowed[key]
		if id == 0 || seen[key] {
			return Result{}, ErrInvalid
		}
		seen[key] = true
		httpResult, ok := row.Data["http"]
		if !ok {
			return Result{}, ErrInvalid
		}
		data := map[string]any{"address": address.String(), "port": row.Port, "observed": false}
		if httpResult.Status == "success" && httpResult.Result.Response != nil && httpResult.Result.Response.StatusCode >= 100 && httpResult.Result.Response.StatusCode <= 599 {
			data["observed"], data["http_status"] = true, httpResult.Result.Response.StatusCode
		} else {
			out.Complete = false
		}
		endpoints[id] = append(endpoints[id], data)
		if len(seen) > 256 {
			return Result{}, ErrInvalid
		}
	}
	if scanner.Err() != nil {
		return Result{}, ErrInvalid
	}
	if len(seen) != len(allowed) {
		out.Complete = false
	}
	for id, values := range endpoints {
		sort.Slice(values, func(i, j int) bool {
			return values[i]["address"].(string) < values[j]["address"].(string)
		})
		out.Observations[id] = []model.ObservationInput{{Check: "ext.zgrab2", Data: map[string]any{"endpoints": values}}}
	}
	return out, nil
}

func parseStrix(c assessmentjob.Completion) (Result, error) {
	var report struct {
		Version   int              `json:"schema_version"`
		SessionID string           `json:"session_id"`
		Tool      string           `json:"tool"`
		Source    string           `json:"upstream_source_sha"`
		Completed bool             `json:"completed"`
		Complete  bool             `json:"complete"`
		Findings  []ingest.Finding `json:"findings"`
		Error     string           `json:"error,omitempty"`
	}
	if len(c.Data) > 4<<20 || json.Unmarshal(c.Data, &report) != nil || report.Version != 1 || report.SessionID != c.Session.ID || report.Tool != "strix" || report.Source != "55bc07991aacb1c26a81b43e7ca53148730d2019" || report.Complete || report.Findings == nil || len(report.Findings) > 1000 {
		return Result{}, ErrInvalid
	}
	allowed, err := targetOrigins(c.Targets)
	if err != nil {
		return Result{}, err
	}
	out := Result{Complete: false}
	for _, f := range report.Findings {
		key, err := origin(f.Asset.Key)
		if err != nil || allowed[key] == 0 || f.Asset.Ref != nil || f.Asset.Kind != model.KindURL {
			return Result{}, ErrInvalid
		}
		for field, value := range f.Evidence {
			switch field {
			case "endpoint", "producer", "confidence", "confidence_rationale", "cwe", "method":
				text, ok := value.(string)
				if !ok || len(text) > 1024 {
					return Result{}, ErrInvalid
				}
			default:
				return Result{}, ErrInvalid
			}
		}
		f.Tags = []string{"strix", "constrained-http", "requires-review"}
		out.Findings = append(out.Findings, Finding{AssetID: allowed[key], Data: f})
	}
	return out, nil
}

func (r Result) String() string {
	return fmt.Sprintf("%d findings; complete=%t", len(r.Findings), r.Complete)
}
