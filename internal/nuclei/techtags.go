package nuclei

import (
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
)

// genericTags is the fallback when no technology hint maps to a template tag.
var genericTags = []string{"exposure", "misconfig", "cve"}

// techTags maps normalised http.probe technology names to nuclei template
// tags. Every tag here must be one nuclei-templates actually uses (checked
// against a real release by the live test): an invented tag selects nothing
// and silently drops coverage. Technologies with no real tag (remix, svelte)
// are deliberately absent; they fall back to the generic set.
var techTags = map[string][]string{
	// web servers, proxies, runtimes
	"nginx": {"nginx"}, "apache": {"apache"}, "apache http server": {"apache"}, "tomcat": {"tomcat"}, "apache tomcat": {"tomcat"},
	"iis": {"iis"}, "microsoft-iis": {"iis"}, "traefik": {"traefik"}, "haproxy": {"haproxy"}, "php": {"php"},
	"nodejs": {"nodejs"}, "express": {"express", "nodejs"},
	// JavaScript frameworks
	"nextjs": {"nextjs", "react"}, "react": {"react"}, "nuxt": {"nuxtjs"}, "vue": {"vue"}, "angular": {"angular"},
	// backend frameworks
	"spring": {"springboot", "spring"}, "spring boot": {"springboot", "spring"}, "struts": {"struts", "struts2"},
	"laravel": {"laravel"}, "django": {"django"}, "rails": {"rails", "ruby"},
	// CMS and commerce
	"wordpress": {"wordpress", "wp"}, "drupal": {"drupal"}, "joomla": {"joomla"}, "magento": {"magento"},
	"nextcloud": {"nextcloud"}, "phpmyadmin": {"phpmyadmin"},
	// developer and ops platforms
	"jenkins": {"jenkins"}, "grafana": {"grafana"}, "gitlab": {"gitlab"}, "jira": {"jira", "atlassian"},
	"confluence": {"confluence", "atlassian"}, "sonarqube": {"sonarqube"}, "argo cd": {"argocd"}, "argocd": {"argocd"},
	"elasticsearch": {"elasticsearch", "elastic"}, "kibana": {"kibana", "elastic"}, "prometheus": {"prometheus"},
	"minio": {"minio"}, "vault": {"vault", "hashicorp"}, "consul": {"consul", "hashicorp"},
	// network appliances
	"citrix": {"citrix", "netscaler"}, "fortinet": {"fortinet"},
}

// techAliases maps other spellings (what header banners and operators write)
// to the canonical names above.
var techAliases = map[string]string{
	"next.js": "nextjs", "next": "nextjs", "reactjs": "react", "react.js": "react",
	"nuxt.js": "nuxt", "nuxtjs": "nuxt", "vue.js": "vue", "vuejs": "vue",
	"angularjs": "angular", "angular.js": "angular", "express.js": "express", "expressjs": "express",
	"node.js": "nodejs", "node": "nodejs", "springboot": "spring boot", "apache struts": "struts", "struts2": "struts",
	"ruby on rails": "rails", "ruby-on-rails": "rails", "netscaler": "citrix", "citrix netscaler": "citrix",
	"citrix gateway": "citrix", "fortigate": "fortinet", "fortios": "fortinet", "atlassian jira": "jira",
	"atlassian confluence": "confluence",
}

// normaliseTech lowercases a technology hint and strips a ":version" or
// "/version" suffix ("WordPress:6.2" -> "wordpress").
func normaliseTech(h string) string {
	name := strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexAny(name, ":/"); i >= 0 {
		name = name[:i]
	}
	return strings.TrimSpace(name)
}

// lookupTech resolves a normalised name through aliases to its tags.
func lookupTech(name string) ([]string, bool) {
	if canon, ok := techAliases[name]; ok {
		name = canon
	}
	tags, ok := techTags[name]
	return tags, ok
}

func techHints(a model.Asset) []string {
	var raw []string
	switch v := a.Attrs["tech"].(type) {
	case []string:
		raw = v
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				raw = append(raw, s)
			}
		}
	}
	return raw
}

// selectTags maps tech hints to template tags (deduplicated, validated),
// falling back to the generic set, then adds operator extra tags.
func selectTags(a model.Asset, extra []string) []string {
	seen := map[string]bool{}
	var tags []string
	add := func(t string) {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" && tagRe.MatchString(t) && !seen[t] {
			seen[t] = true
			tags = append(tags, t)
		}
	}
	for _, h := range techHints(a) {
		name := normaliseTech(h)
		mapped, ok := lookupTech(name)
		if !ok {
			// "apache http server 2.4" style banners: try the first word.
			if i := strings.IndexByte(name, ' '); i > 0 {
				mapped, ok = lookupTech(name[:i])
			}
		}
		if ok {
			for _, t := range mapped {
				add(t)
			}
		}
	}
	if len(tags) == 0 {
		for _, t := range genericTags {
			add(t)
		}
	}
	for _, t := range extra {
		add(t)
	}
	return tags
}
