package probe

import (
	"html"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var spaceRE = regexp.MustCompile(`\s+`)

const maxTitle = 200

// ExtractTitle returns the page <title>, unescaped, whitespace-collapsed and
// capped; "" when absent.
func ExtractTitle(body []byte) string {
	m := titleRE.FindSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.TrimSpace(spaceRE.ReplaceAllString(html.UnescapeString(string(m[1])), " "))
	if len(t) > maxTitle {
		t = t[:maxTitle]
	}
	return t
}

type rule struct {
	tag, needle string
}

// Server / X-Powered-By header substrings (matched lowercased).
var serverRules = []rule{
	{"nginx", "nginx"}, {"openresty", "openresty"}, {"apache", "apache"}, {"iis", "microsoft-iis"},
	{"cloudflare", "cloudflare"}, {"caddy", "caddy"}, {"litespeed", "litespeed"}, {"gunicorn", "gunicorn"},
	{"envoy", "envoy"}, {"kestrel", "kestrel"}, {"jetty", "jetty"}, {"tomcat", "apache-coyote"},
	{"aws-elb", "awselb"}, {"s3", "amazons3"}, {"cowboy", "cowboy"}, {"traefik", "traefik"},
}

var poweredRules = []rule{
	{"express", "express"}, {"php", "php"}, {"asp.net", "asp.net"}, {"nextjs", "next.js"},
	{"django", "django"}, {"phusion-passenger", "phusion passenger"}, {"nuxt", "nuxt"},
}

// Header-presence tags: any response header whose lowercased name starts with
// the needle.
var headerPresence = []rule{
	{"jenkins", "x-jenkins"}, {"kibana", "kbn-name"}, {"grafana", "x-grafana-"},
	{"nextjs", "x-nextjs-"}, {"remix", "x-remix-"}, {"spring", "x-application-context"},
	{"confluence", "x-confluence-"}, {"drupal", "x-drupal-"},
}

// Vary header substrings. The Next.js app router varies on its flight headers.
var varyRules = []rule{
	{"nextjs", "next-router-state-tree"},
}

// Content-Type substrings. text/x-component is the React Server Components
// flight payload.
var contentTypeRules = []rule{
	{"react", "text/x-component"},
}

// Set-Cookie name substrings.
var cookieRules = []rule{
	{"php", "phpsessid"}, {"java", "jsessionid"}, {"asp.net", "asp.net_sessionid"},
	{"grafana", "grafana_session"}, {"express", "connect.sid"}, {"laravel", "laravel_session"},
	{"django", "csrftoken"}, {"citrix", "nsc_"},
}

// Body substrings (matched against the lowercased body).
var bodyRules = []rule{
	{"wordpress", "/wp-content/"}, {"wordpress", "/wp-includes/"}, {"wordpress", `content="wordpress`},
	{"grafana", "window.grafanabootdata"}, {"grafana", "<title>grafana"},
	{"jenkins", "<title>dashboard [jenkins]"}, {"jenkins", "<title>sign in [jenkins]"},
	{"drupal", "drupal-settings-json"}, {"drupal", `content="drupal`},
	{"joomla", `content="joomla`},
	{"nextjs", "/_next/static/"}, {"nextjs", "__next_data__"}, {"nextjs", "self.__next_f"}, {"nextjs", `id="__next"`},
	{"react", "data-reactroot"}, {"react", "data-reactid"}, {"react", "react-dom"},
	{"nuxt", "/_nuxt/"}, {"nuxt", "window.__nuxt__"}, {"nuxt", `id="__nuxt"`},
	{"vue", "data-v-app"}, {"vue", "vue.global"}, {"vue", "vue.runtime"}, {"vue", "vue.min.js"}, {"vue", "data-vue-meta"},
	{"angular", `ng-version="`}, {"angular", "ng-app="}, {"angular", "angular.min.js"},
	{"remix", "__remixcontext"}, {"remix", "__remixmanifest"},
	{"svelte", "__sveltekit"}, {"svelte", "/_app/immutable/"},
	{"spring", "whitelabel error page"}, {"struts", "/struts/"},
	{"django", "csrfmiddlewaretoken"}, {"rails", `name="csrf-param"`},
	{"confluence", "confluence-request-time"}, {"confluence", "com.atlassian.confluence"},
	{"citrix", "citrix gateway"}, {"citrix", "netscaler gateway"}, {"fortinet", "/remote/login?lang="},
	{"gitlab", `content="gitlab`}, {"gitlab", "<title>sign in · gitlab"},
	{"prometheus", "<title>prometheus time series"}, {"prometheus", "<title>prometheus</title>"},
	{"argocd", "<title>argo cd"}, {"sonarqube", "<title>sonarqube"},
	{"phpmyadmin", "phpmyadmin"}, {"kibana", "<title>kibana"},
	{"nginx", "<center>nginx</center>"},
}

// DetectTech derives technology tags from response headers and body. Tags are
// lowercase, deduplicated and sorted; they feed the nuclei template selector.
func DetectTech(h http.Header, body []byte) []string {
	set := map[string]bool{}
	apply := func(haystack string, rules []rule) {
		haystack = strings.ToLower(haystack)
		for _, r := range rules {
			if strings.Contains(haystack, r.needle) {
				set[r.tag] = true
			}
		}
	}
	apply(h.Get("Server"), serverRules)
	apply(h.Get("X-Powered-By"), poweredRules)
	for _, r := range headerPresence {
		for k := range h {
			if strings.HasPrefix(strings.ToLower(k), r.needle) {
				set[r.tag] = true
			}
		}
	}
	if g := strings.ToLower(h.Get("X-Generator")); g != "" {
		for _, t := range []string{"drupal", "wordpress", "joomla"} {
			if strings.Contains(g, t) {
				set[t] = true
			}
		}
	}
	apply(strings.Join(h.Values("Vary"), ","), varyRules)
	apply(h.Get("Content-Type"), contentTypeRules)
	apply(strings.Join(h.Values("Set-Cookie"), "\n"), cookieRules)
	apply(string(body), bodyRules)

	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
