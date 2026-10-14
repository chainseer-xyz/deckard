package assessmentexec

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

func loadRequest(o ExecuteOptions) (assessmentjob.ExecutionRequest, error) {
	var r assessmentjob.ExecutionRequest
	raw, err := readRegular(o.RequestFile, 64<<10, true)
	if err != nil || decodeStrict(raw, &r) != nil || duplicateJSONKeys(raw) || !validTool(o.Tool) || r.Tool != o.Tool || r.SchemaVersion != 1 || !sessionID.MatchString(r.SessionID) || o.ReportFile == o.DoneFile || o.ReportFile == o.RequestFile || o.DoneFile == o.RequestFile {
		return r, ErrInvalid
	}
	if r.TimeoutSeconds < 1 || r.TimeoutSeconds > 900 || r.MaxRequests < 1 || r.MaxRequests > 10000 || r.MaxOutputBytes < 1 || r.MaxOutputBytes > outputLimit(r.Tool) || r.MaxTurns < 1 || r.MaxTurns > 100 || len(r.Targets) < 1 || len(r.Targets) > 16 {
		return r, ErrInvalid
	}
	seen := map[string]bool{}
	for i, target := range r.Targets {
		canonical, _, err := targetOrigin(target)
		if err != nil || seen[canonical] {
			return r, ErrInvalid
		}
		seen[canonical] = true
		r.Targets[i] = canonical
	}
	if r.Tool != assessmentjob.ToolZGrab2 {
		if len(r.FixedTargets) != 0 {
			return r, ErrInvalid
		}
		return r, nil
	}
	if err := validateFixed(&r, seen); err != nil {
		return r, err
	}
	return r, nil
}

func validateFixed(r *assessmentjob.ExecutionRequest, origins map[string]bool) error {
	if len(r.FixedTargets) != len(r.Targets) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	count := 0
	for i, target := range r.FixedTargets {
		canonical, port, err := targetOrigin(target.Origin)
		if err != nil || !origins[canonical] || seen[canonical] || port != target.Port || target.AssetID <= 0 || len(target.Addresses) < 1 || len(target.Addresses) > 16 {
			return ErrInvalid
		}
		seen[canonical] = true
		r.FixedTargets[i].Origin = canonical
		addresses := map[netip.Addr]bool{}
		for _, ip := range target.Addresses {
			ip = ip.Unmap()
			if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" || addresses[ip] {
				return ErrInvalid
			}
			addresses[ip] = true
			count++
		}
	}
	if count > r.MaxRequests {
		return ErrInvalid
	}
	return nil
}

func targetOrigin(raw string) (string, uint16, error) {
	if len(raw) > 4096 || strings.ContainsAny(raw, "\\\r\n\t#") {
		return "", 0, ErrInvalid
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https") {
		return "", 0, ErrInvalid
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return "", 0, ErrInvalid
		}
		host = ip.Unmap().String()
	} else {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || len(host) > 253 {
			return "", 0, ErrInvalid
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) < 1 || len(label) > 63 || !hostnameLabel(label) {
				return "", 0, ErrInvalid
			}
		}
	}
	defaultPort := uint64(80)
	if u.Scheme == "https" {
		defaultPort = 443
	}
	port := defaultPort
	if u.Port() != "" {
		port, err = strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || port == 0 {
			return "", 0, ErrInvalid
		}
	}
	if port != defaultPort {
		host = net.JoinHostPort(host, strconv.FormatUint(port, 10))
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host, uint16(port), nil
}

func hostnameLabel(label string) bool {
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
