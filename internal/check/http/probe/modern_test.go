package probe

import (
	"net/http"
	"reflect"
	"testing"
)

func TestDetectModernFrameworks(t *testing.T) {
	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			out.Add(kv[i], kv[i+1])
		}
		return out
	}
	cases := []struct {
		name string
		h    http.Header
		body string
		want []string
	}{
		{"next.js powered-by header", h("X-Powered-By", "Next.js"), "", []string{"nextjs"}},
		{"next.js static assets", h(), `<script src="/_next/static/chunks/main-abc.js"></script>`, []string{"nextjs"}},
		{"next.js pages router data", h(), `<script id="__NEXT_DATA__" type="application/json">{}</script>`, []string{"nextjs"}},
		{"next.js app router flight data", h(), `<script>self.__next_f.push([1,"x"])</script>`, []string{"nextjs"}},
		{"next.js root div", h(), `<div id="__next"></div>`, []string{"nextjs"}},
		{"next.js cache header", h("X-Nextjs-Cache", "HIT"), "", []string{"nextjs"}},
		{"next.js app router vary + RSC content type", h("Vary", "RSC, Next-Router-State-Tree, Next-Router-Prefetch", "Content-Type", "text/x-component"), "", []string{"nextjs", "react"}},
		{"react root attribute", h(), `<div data-reactroot=""><h1>hi</h1></div>`, []string{"react"}},
		{"react-dom bundle", h(), `<script src="/static/js/react-dom.production.min.js"></script>`, []string{"react"}},
		{"nuxt assets", h(), `<link rel="preload" href="/_nuxt/entry.js"><div id="__nuxt"></div>`, []string{"nuxt"}},
		{"nuxt powered-by", h("X-Powered-By", "Nuxt"), "", []string{"nuxt"}},
		{"vue bundle", h(), `<script src="https://cdn.example.com/vue.global.prod.js"></script>`, []string{"vue"}},
		{"vue app root", h(), `<div data-v-app=""></div>`, []string{"vue"}},
		{"angular version attribute", h(), `<app-root ng-version="17.3.0"></app-root>`, []string{"angular"}},
		{"angularjs", h(), `<html ng-app="demo"><script src="angular.min.js"></script>`, []string{"angular"}},
		{"remix context", h(), `<script>window.__remixContext = {};</script>`, []string{"remix"}},
		{"remix header", h("X-Remix-Response", "yes"), "", []string{"remix"}},
		{"sveltekit", h(), `<script>__sveltekit_abc = {}</script><link href="/_app/immutable/entry/start.js">`, []string{"svelte"}},
		{"express", h("X-Powered-By", "Express"), "", []string{"express"}},
		{"spring whitelabel", h(), `<html><body><h1>Whitelabel Error Page</h1></body></html>`, []string{"spring"}},
		{"spring application context header", h("X-Application-Context", "app:prod:8080"), "", []string{"spring"}},
		{"struts static path", h(), `<link rel="stylesheet" href="/struts/xhtml/styles.css">`, []string{"struts"}},
		{"laravel cookie", h("Set-Cookie", "laravel_session=abc; path=/; httponly"), "", []string{"laravel"}},
		{"django csrf cookie", h("Set-Cookie", "csrftoken=abc; Path=/; SameSite=Lax"), "", []string{"django"}},
		{"django csrf form field", h(), `<input type="hidden" name="csrfmiddlewaretoken" value="x">`, []string{"django"}},
		{"rails csrf meta", h(), `<meta name="csrf-param" content="authenticity_token" />`, []string{"rails"}},
		{"drupal header", h("X-Drupal-Cache", "HIT"), "", []string{"drupal"}},
		{"confluence header", h("X-Confluence-Request-Time", "1712345678"), "", []string{"confluence"}},
		{"confluence meta", h(), `<meta name="confluence-request-time" content="1">`, []string{"confluence"}},
		{"citrix netscaler cookie", h("Set-Cookie", "NSC_AAAC=abc; path=/; secure"), "", []string{"citrix"}},
		{"citrix gateway page", h(), `<title>Citrix Gateway</title>`, []string{"citrix"}},
		{"fortinet sslvpn", h(), `<script>location="/remote/login?lang=en"</script>`, []string{"fortinet"}},
		{"stack: next + react + nginx", h("Server", "nginx", "X-Powered-By", "Next.js"), `<div id="__next" data-reactroot=""></div>`, []string{"nginx", "nextjs", "react"}},
		// Plain prose mentioning a framework is not a fingerprint.
		{"prose mentions", h(), `<p>We love React, Vue, Angular, Next.js and Django.</p>`, []string{}},
		{"unrelated cookie", h("Set-Cookie", "session=abc"), "", []string{}},
	}
	for _, c := range cases {
		got := DetectTech(c.h, []byte(c.body))
		want := append([]string{}, c.want...)
		sortStrings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: DetectTech = %v, want %v", c.name, got, want)
		}
	}
}

func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

// Every rule table entry is lowercase (haystacks are lowercased before the
// substring test, so an uppercase needle could never match).
func TestRuleTablesAreLowercase(t *testing.T) {
	for name, rules := range map[string][]rule{
		"server": serverRules, "powered": poweredRules, "presence": headerPresence, "cookie": cookieRules, "body": bodyRules,
		"vary": varyRules, "content-type": contentTypeRules,
	} {
		for _, r := range rules {
			if r.needle == "" || r.tag == "" {
				t.Errorf("%s: empty rule %+v", name, r)
			}
			for _, c := range r.needle {
				if c >= 'A' && c <= 'Z' {
					t.Errorf("%s: needle %q has upper case", name, r.needle)
					break
				}
			}
		}
	}
}
