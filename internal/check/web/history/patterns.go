package history

import (
	"regexp"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// Classes of archived path. A path belongs to the first rule (in table order,
// which is severity order) that matches it.
const (
	ClassSecrets = "secrets" // credentials, keys, VCS metadata
	ClassDump    = "dump"    // database and archive dumps, backup copies
	ClassAdmin   = "admin"   // admin and debug surfaces
	ClassMisc    = "misc"    // low-signal leftovers
)

// rule is one curated pattern. Patterns match the lower-cased, cleaned URL
// path (no query string), so write them in lower case.
type rule struct {
	class string
	sev   model.Severity
	// label names what matched, for the finding title.
	label string
	re    *regexp.Regexp
	// root is true for subtree rules: capture group 1 is the directory that is
	// reported (and keyed) instead of every file below it, so one exposed
	// repository is one finding, not one per archived object.
	root bool
	// file is true when the path should be a non-HTML file. A capture served as
	// text/html there is most likely a soft 404 or an application shell that
	// answers 200 for everything, so its severity drops one level.
	file bool
}

func r(class string, sev model.Severity, label, pattern string, root, file bool) rule {
	return rule{class: class, sev: sev, label: label, re: regexp.MustCompile(pattern), root: root, file: file}
}

// rules is the pattern table. It is documented in docs/configuration.md; keep
// the two in step.
//
//	secrets  high    /.env*, .git/, .svn/, .hg/, id_rsa and friends, .pem/.key,
//	                 .aws/credentials, *.tfstate, .npmrc, wp-config.php.* and
//	                 config.php.bak
//	dump     high    *.sql(.gz|.zip...), *.dump, *.bak, *.old, and zip/tar.gz/7z
//	                 archives named backup, db, site or www
//	admin    medium  /phpmyadmin, /adminer, /admin, /actuator/*, /server-status,
//	                 /debug, /_profiler, /telescope, /horizon, /graphiql,
//	                 /swagger*, /openapi.json, /api-docs
//	misc     low     .DS_Store, /web.config
var rules = []rule{
	// secrets and version-control metadata
	r(ClassSecrets, model.SeverityHigh, "environment file", `(^|/)\.env([._-][^/]*)?$`, false, true),
	r(ClassSecrets, model.SeverityHigh, "Git repository", `^(.*?/\.git)(/|$)`, true, false),
	r(ClassSecrets, model.SeverityHigh, "Subversion metadata", `^(.*?/\.svn)(/|$)`, true, false),
	r(ClassSecrets, model.SeverityHigh, "Mercurial repository", `^(.*?/\.hg)(/|$)`, true, false),
	r(ClassSecrets, model.SeverityHigh, "SSH private key", `(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.(bak|old|orig|txt))?$`, false, true),
	r(ClassSecrets, model.SeverityHigh, "private key or certificate file", `\.(pem|key)$`, false, true),
	r(ClassSecrets, model.SeverityHigh, "AWS credentials file", `(^|/)\.aws/(credentials|config)$`, false, true),
	r(ClassSecrets, model.SeverityHigh, "Terraform state", `\.tfstate(\.backup)?$`, false, true),
	r(ClassSecrets, model.SeverityHigh, "npm configuration", `(^|/)\.npmrc$`, false, true),
	r(ClassSecrets, model.SeverityHigh, "WordPress configuration copy", `(^|/)wp-config\.php(\.[^/]+|~)$`, false, true),
	r(ClassSecrets, model.SeverityHigh, "PHP configuration backup", `(^|/)config\.php\.(bak|old|orig|save|swp|txt)$`, false, true),

	// database and archive dumps, backup copies
	r(ClassDump, model.SeverityHigh, "SQL dump", `\.sql(\.(gz|zip|bz2|xz|7z|tar))?$`, false, true),
	r(ClassDump, model.SeverityHigh, "database dump", `\.dump(\.gz)?$`, false, true),
	r(ClassDump, model.SeverityHigh, "backup file", `\.(bak|old)$`, false, true),
	r(ClassDump, model.SeverityHigh, "site or database archive", `(^|/)([^/]*[-_.])?(backups?|db|database|site|www|website)([-_.][^/]*)?\.(zip|tar\.gz|tgz|7z)$`, false, true),

	// admin and debug surfaces (web root only: nested paths are too ambiguous)
	r(ClassAdmin, model.SeverityMedium, "phpMyAdmin", `^(/phpmyadmin)(/|\.php|$)`, true, false),
	r(ClassAdmin, model.SeverityMedium, "Adminer", `^(/adminer)(/|\.php|$)`, true, false),
	r(ClassAdmin, model.SeverityMedium, "admin area", `^(/admin)(/|$)`, true, false),
	r(ClassAdmin, model.SeverityMedium, "Spring Boot actuator", `^(/actuator)(/|$)`, true, false),
	r(ClassAdmin, model.SeverityMedium, "Apache server-status", `^(/server-status)(/|$)`, true, false),
	r(ClassAdmin, model.SeverityMedium, "debug endpoint", `^(/debug)(/|$)`, true, false),
	r(ClassAdmin, model.SeverityMedium, "Symfony profiler", `^(/_profiler)(/|$)`, true, false),
	r(ClassAdmin, model.SeverityMedium, "Laravel Telescope", `^(/telescope)(/|$)`, true, false),
	r(ClassAdmin, model.SeverityMedium, "Laravel Horizon", `^(/horizon)(/|$)`, true, false),
	r(ClassAdmin, model.SeverityMedium, "GraphiQL", `^(/graphiql)(/|$)`, true, false),
	r(ClassAdmin, model.SeverityMedium, "Swagger UI", `^(/swagger[^/]*)(/|$)`, true, false),
	r(ClassAdmin, model.SeverityMedium, "OpenAPI document", `^/openapi\.json$`, false, false),
	r(ClassAdmin, model.SeverityMedium, "API documentation", `^((?:/v[0-9]+)?/api-docs)(/|$)`, true, false),

	// low-signal leftovers
	r(ClassMisc, model.SeverityLow, "macOS .DS_Store", `(^|/)\.ds_store$`, false, true),
	r(ClassMisc, model.SeverityLow, "IIS web.config", `^/web\.config$`, false, true),
}

// matchRule returns the first rule matching a lower-cased clean path and the
// path to report: the matched directory for subtree rules, else the path.
func matchRule(p string) (rule, string, bool) {
	for _, ru := range rules {
		m := ru.re.FindStringSubmatch(p)
		if m == nil {
			continue
		}
		if ru.root {
			return ru, m[1], true
		}
		return ru, p, true
	}
	return rule{}, "", false
}

// softMIME reports whether a CDX mimetype is an HTML page.
func softMIME(m string) bool {
	m = strings.ToLower(strings.TrimSpace(m))
	return strings.HasPrefix(m, "text/html") || strings.HasPrefix(m, "application/xhtml")
}

// lower returns sev one level lower (info stays info).
func lower(sev model.Severity) model.Severity {
	switch sev {
	case model.SeverityCritical:
		return model.SeverityHigh
	case model.SeverityHigh:
		return model.SeverityMedium
	case model.SeverityMedium:
		return model.SeverityLow
	}
	return model.SeverityInfo
}
