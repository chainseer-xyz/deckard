package exposed

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// probe is one well-known path with a strict validator. validate must return
// ok only when the body is unmistakably the real resource, and any evidence
// it returns must never contain secret values.
type probe struct {
	path     string
	severity model.Severity
	title    string
	desc     string
	fix      string
	tags     []string
	validate func(r *response) (map[string]any, bool)
}

var (
	envLineRe      = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$`)
	sensitiveKeyRe = regexp.MustCompile(`(?i)(secret|passw|token|api_?key|private|credential|auth)`)
	htmlRe         = regexp.MustCompile(`(?i)<\s*(!doctype|html|head|body|script)\b`)
	phpDefineRe    = regexp.MustCompile(`define\(\s*['"]([A-Z_]+)['"]`)
	headRefRe      = regexp.MustCompile(`^ref: (refs/[A-Za-z0-9._/\-]+)\s*$`)
	svnEntriesRe   = regexp.MustCompile(`\A\d+\n`)
	titleRe        = regexp.MustCompile(`(?is)<title>(.*?)</title>`)
)

const (
	fixFiles = "Remove the file from the web root and deny the path at the web server; rotate any credential it may have contained."
	fixDebug = "Disable the endpoint in production or restrict it to an internal network or authenticated operators."
)

var probes = []probe{
	{"/.git/HEAD", model.SeverityHigh, "Exposed .git repository (/.git/HEAD)",
		"The .git directory is served over HTTP, allowing the source history to be reconstructed.",
		"Deny access to dot-directories at the web server and deploy build artefacts only, not the working tree.",
		[]string{"git", "source-disclosure"}, validateGitHead},
	{"/.git/config", model.SeverityHigh, "Exposed .git config (/.git/config)",
		"The git configuration file is served over HTTP and may reveal remote URLs and credentials.",
		"Deny access to dot-directories at the web server.", []string{"git", "source-disclosure"}, validateGitConfig},
	{"/.env", model.SeverityCritical, "Exposed environment file (/.env)",
		"A dotenv file with KEY=VALUE entries is served over HTTP and commonly contains credentials.",
		fixFiles, []string{"secrets"}, validateEnv},
	{"/.DS_Store", model.SeverityLow, "Exposed macOS .DS_Store (/.DS_Store)",
		"A Finder metadata file is served and leaks directory and file names.", fixFiles, nil, validateDSStore},
	{"/.svn/entries", model.SeverityMedium, "Exposed Subversion metadata (/.svn/entries)",
		"Subversion working-copy metadata is served over HTTP and leaks file names and possibly source.",
		"Deny access to .svn directories at the web server.", []string{"svn", "source-disclosure"}, validateSVN},
	{"/server-status", model.SeverityMedium, "Apache server-status exposed (/server-status)",
		"mod_status output is reachable and reveals client addresses, request URLs and server internals.",
		"Restrict /server-status to localhost or an admin network.", nil, validateContains("Apache Server Status")},
	{"/actuator/health", model.SeverityInfo, "Spring Boot actuator health exposed (/actuator/health)",
		"The actuator health endpoint is reachable without authentication.",
		"Expose only the minimal health endpoint and hide component details.", []string{"actuator"}, validateActuatorHealth},
	{"/actuator/env", model.SeverityHigh, "Spring Boot actuator env exposed (/actuator/env)",
		"The actuator env endpoint is reachable and lists configuration properties, which can leak secrets or aid exploitation.",
		"Disable the env endpoint or protect actuator endpoints with authentication.", []string{"actuator"}, validateActuatorEnv},
	{"/phpinfo.php", model.SeverityMedium, "phpinfo() page exposed (/phpinfo.php)",
		"A phpinfo page is reachable and discloses PHP configuration, paths and environment details.",
		"Delete the phpinfo file.", []string{"php"}, validateAll("PHP Version", "phpinfo()")},
	{"/wp-config.php.bak", model.SeverityCritical, "WordPress config backup exposed (/wp-config.php.bak)",
		"A backup of wp-config.php is served as readable text and contains database credentials and salts.",
		fixFiles, []string{"wordpress", "secrets"}, validateWPConfig},
	{"/backup.zip", model.SeverityHigh, "Backup archive exposed (/backup.zip)",
		"A ZIP archive named backup.zip is downloadable from the web root.", fixFiles, []string{"backup"}, validateZip},
	{"/debug/pprof/", model.SeverityHigh, "Go pprof debug endpoint exposed (/debug/pprof/)",
		"The Go profiling index is reachable; profiles and command lines can disclose internals and enable denial of service.",
		fixDebug, []string{"debug"}, validateContains("Types of profiles available")},
	{"/metrics", model.SeverityLow, "Prometheus metrics exposed (/metrics)",
		"A metrics endpoint is reachable without authentication and discloses internal topology and workload details.",
		fixDebug, []string{"metrics"}, validateMetrics},
	{"/swagger.json", model.SeverityInfo, "API specification exposed (/swagger.json)",
		"An OpenAPI/Swagger document is publicly readable and documents the API surface.",
		"Confirm the API description is intended to be public; otherwise restrict it.", []string{"api"}, validateSwagger},
	{"/admin", model.SeverityInfo, "Admin interface reachable (/admin)",
		"An administrative interface responds on /admin from the internet.",
		"Restrict administrative interfaces to a VPN or allow-listed networks and require strong authentication.",
		[]string{"admin"}, validateAdmin},
	{"/", model.SeverityMedium, "Directory listing enabled (/)", dirDesc,
		dirFix, []string{"directory-listing"}, validateDirListing},
	{"/backup/", model.SeverityMedium, "Directory listing enabled (/backup/)", dirDesc,
		dirFix, []string{"directory-listing"}, validateDirListing},
	{"/uploads/", model.SeverityMedium, "Directory listing enabled (/uploads/)", dirDesc,
		dirFix, []string{"directory-listing"}, validateDirListing},
	{"/files/", model.SeverityMedium, "Directory listing enabled (/files/)", dirDesc,
		dirFix, []string{"directory-listing"}, validateDirListing},
	{"/logs/", model.SeverityMedium, "Directory listing enabled (/logs/)", dirDesc,
		dirFix, []string{"directory-listing"}, validateDirListing},
}

const (
	dirDesc = "The web server returns an automatic index of the directory, exposing file names."
	dirFix  = "Disable directory indexing (autoindex off / Options -Indexes) and move sensitive files out of the web root."
)

func looksHTML(b []byte) bool {
	if len(b) > 1024 {
		b = b[:1024]
	}
	return htmlRe.Match(b)
}

func validateGitHead(r *response) (map[string]any, bool) {
	if looksHTML(r.body) {
		return nil, false
	}
	m := headRefRe.FindSubmatch(bytes.TrimSpace(r.body))
	if m == nil {
		return nil, false
	}
	return map[string]any{"ref": string(m[1])}, true
}

func validateGitConfig(r *response) (map[string]any, bool) {
	if looksHTML(r.body) || !bytes.Contains(r.body, []byte("[core]")) || !bytes.Contains(r.body, []byte("repositoryformatversion")) {
		return nil, false
	}
	return nil, true
}

// validateEnv requires the body to be (almost) entirely KEY=VALUE lines.
// Only key names are returned; values are never copied.
func validateEnv(r *response) (map[string]any, bool) {
	if looksHTML(r.body) {
		return nil, false
	}
	var keys []string
	other := 0
	for _, line := range strings.Split(string(r.body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := envLineRe.FindStringSubmatch(line); m != nil {
			keys = append(keys, m[1])
		} else {
			other++
		}
	}
	if len(keys) == 0 || other > len(keys)/4 {
		return nil, false
	}
	sens := 0
	for _, k := range keys {
		if sensitiveKeyRe.MatchString(k) {
			sens++
		}
	}
	return map[string]any{"key_count": len(keys), "sensitive_key_count": sens, "key_names": capList(keys, 20)}, true
}

func capList(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func validateDSStore(r *response) (map[string]any, bool) {
	return nil, bytes.HasPrefix(r.body, []byte("\x00\x00\x00\x01Bud1"))
}

func validateSVN(r *response) (map[string]any, bool) {
	return nil, !looksHTML(r.body) && svnEntriesRe.Match(r.body) && bytes.Contains(r.body, []byte("\ndir\n"))
}

func validateContains(s string) func(*response) (map[string]any, bool) {
	return func(r *response) (map[string]any, bool) { return nil, bytes.Contains(r.body, []byte(s)) }
}

func validateAll(parts ...string) func(*response) (map[string]any, bool) {
	return func(r *response) (map[string]any, bool) {
		for _, p := range parts {
			if !bytes.Contains(r.body, []byte(p)) {
				return nil, false
			}
		}
		return nil, true
	}
}

func jsonObject(b []byte) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(bytes.TrimSpace(b), &m) != nil {
		return nil
	}
	return m
}

func validateActuatorHealth(r *response) (map[string]any, bool) {
	m := jsonObject(r.body)
	var status string
	if m == nil || json.Unmarshal(m["status"], &status) != nil {
		return nil, false
	}
	switch status {
	case "UP", "DOWN", "OUT_OF_SERVICE", "UNKNOWN":
		return map[string]any{"status": status, "detailed": m["components"] != nil || m["details"] != nil}, true
	}
	return nil, false
}

func validateActuatorEnv(r *response) (map[string]any, bool) {
	m := jsonObject(r.body)
	if m == nil || (m["propertySources"] == nil && m["activeProfiles"] == nil) {
		return nil, false
	}
	var srcs []struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(m["propertySources"], &srcs)
	names := make([]string, 0, len(srcs))
	for _, s := range srcs {
		names = append(names, s.Name)
	}
	return map[string]any{"property_sources": capList(names, 20)}, true
}

func validateWPConfig(r *response) (map[string]any, bool) {
	if looksHTML(r.body) {
		return nil, false
	}
	var names []string
	for _, m := range phpDefineRe.FindAllSubmatch(r.body, -1) {
		names = append(names, string(m[1]))
	}
	has := func(n string) bool {
		for _, x := range names {
			if x == n {
				return true
			}
		}
		return false
	}
	if !has("DB_NAME") && !has("DB_PASSWORD") {
		return nil, false
	}
	sort.Strings(names)
	return map[string]any{"defined_constants": capList(names, 20)}, true
}

func validateZip(r *response) (map[string]any, bool) {
	return nil, bytes.HasPrefix(r.body, []byte("PK\x03\x04"))
}

func validateMetrics(r *response) (map[string]any, bool) {
	if looksHTML(r.body) {
		return nil, false
	}
	return nil, bytes.HasPrefix(r.body, []byte("# HELP ")) || bytes.HasPrefix(r.body, []byte("# TYPE ")) ||
		bytes.Contains(r.body, []byte("\n# HELP ")) || bytes.Contains(r.body, []byte("\n# TYPE "))
}

func validateSwagger(r *response) (map[string]any, bool) {
	m := jsonObject(r.body)
	if m == nil || (m["swagger"] == nil && m["openapi"] == nil) || m["paths"] == nil {
		return nil, false
	}
	return nil, true
}

func validateAdmin(r *response) (map[string]any, bool) {
	if !looksHTML(r.body) {
		return nil, false
	}
	low := strings.ToLower(string(r.body))
	title := ""
	if m := titleRe.FindStringSubmatch(string(r.body)); m != nil {
		title = strings.TrimSpace(m[1])
	}
	if strings.Contains(strings.ToLower(title), "admin") || strings.Contains(low, `type="password"`) && strings.Contains(low, "admin") {
		return map[string]any{"title": capString(title, 80)}, true
	}
	return nil, false
}

func capString(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func validateDirListing(r *response) (map[string]any, bool) {
	s := string(r.body)
	ok := strings.Contains(s, "<title>Index of /") || strings.Contains(s, "<h1>Index of /") ||
		strings.Contains(s, "<title>Directory listing for /") || strings.Contains(s, "<h1>Directory listing for /")
	return nil, ok
}
