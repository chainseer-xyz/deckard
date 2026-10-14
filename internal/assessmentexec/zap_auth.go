package assessmentexec

import (
	"net/url"
	"regexp"
	"strings"
)

func loadZAPAuth(path string, targets []string) ([]zapAuthOrigin, error) {
	raw, err := readRegular(path, 16<<10, true)
	var config zapAuthFile
	if err != nil || decodeStrict(raw, &config) != nil || duplicateJSONKeys(raw) || config.SchemaVersion != 1 || len(config.Origins) < 1 || len(config.Origins) > 16 {
		return nil, ErrInvalid
	}
	allowed := map[string]bool{}
	for _, target := range targets {
		allowed[target] = true
	}
	seen := map[string]bool{}
	for i, grant := range config.Origins {
		canonical, _, err := targetOrigin(grant.Origin)
		if err != nil || !allowed[canonical] || seen[canonical] || !verificationPath(grant.VerificationPath) || grant.ExpectedStatus != 200 {
			return nil, ErrInvalid
		}
		if grant.Header != "Authorization" && grant.Header != "X-Api-Key" {
			return nil, ErrInvalid
		}
		if grant.Value == "" || len(grant.Value) > 4096 || strings.Contains(grant.Value, "${") {
			return nil, ErrInvalid
		}
		for _, c := range grant.Value {
			if c < 32 || c > 126 {
				return nil, ErrInvalid
			}
		}
		config.Origins[i].Origin = canonical
		seen[canonical] = true
	}
	return config.Origins, nil
}

func verificationPath(path string) bool {
	if path == "" || len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n\t?#") {
		return false
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || u.IsAbs() || u.Host != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return false
	}
	decoded, err := url.PathUnescape(path)
	if err != nil || strings.ContainsAny(decoded, "\\\r\n\t\x00") {
		return false
	}
	return true
}

// ZAP Replacer matches the entire request URL using Java-compatible regex.
// Default-port spellings are equivalent; every other origin remains excluded.
func originPattern(origin string) string {
	u, _ := url.Parse(origin)
	base := regexp.QuoteMeta(origin)
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		base += "(?::" + port + ")?"
	}
	return "^" + base + "(?:[/?].*)?$"
}
