package nuclei

import (
	"slices"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/model"
)

func TestSelectTagsTable(t *testing.T) {
	generic := []string{"exposure", "misconfig", "cve"}
	tests := []struct {
		name  string
		tech  []any
		extra []string
		want  []string
	}{
		{"nextjs probe tag", []any{"nextjs"}, nil, []string{"nextjs", "react"}},
		{"Next.js with version", []any{"Next.js:14.2.3"}, nil, []string{"nextjs", "react"}},
		{"next alias", []any{"next"}, nil, []string{"nextjs", "react"}},
		{"react", []any{"react"}, nil, []string{"react"}},
		{"nuxt maps to the real nuxtjs tag", []any{"nuxt"}, nil, []string{"nuxtjs"}},
		{"nuxt.js alias", []any{"Nuxt.js"}, nil, []string{"nuxtjs"}},
		{"vue", []any{"vue"}, nil, []string{"vue"}},
		{"vue.js alias", []any{"Vue.js"}, nil, []string{"vue"}},
		{"angular", []any{"angular"}, nil, []string{"angular"}},
		{"angularjs alias", []any{"AngularJS"}, nil, []string{"angular"}},
		{"express", []any{"express"}, nil, []string{"express", "nodejs"}},
		{"spring boot", []any{"Spring Boot"}, nil, []string{"springboot", "spring"}},
		{"struts", []any{"struts"}, nil, []string{"struts", "struts2"}},
		{"apache struts alias", []any{"Apache Struts"}, nil, []string{"struts", "struts2"}},
		{"laravel", []any{"laravel"}, nil, []string{"laravel"}},
		{"django", []any{"django"}, nil, []string{"django"}},
		{"ruby on rails alias", []any{"Ruby on Rails"}, nil, []string{"rails", "ruby"}},
		{"wordpress version", []any{"WordPress:6.2"}, nil, []string{"wordpress", "wp"}},
		{"drupal", []any{"drupal"}, nil, []string{"drupal"}},
		{"joomla", []any{"joomla"}, nil, []string{"joomla"}},
		{"confluence", []any{"confluence"}, nil, []string{"confluence", "atlassian"}},
		{"jenkins", []any{"jenkins"}, nil, []string{"jenkins"}},
		{"grafana", []any{"grafana"}, nil, []string{"grafana"}},
		{"gitlab", []any{"gitlab"}, nil, []string{"gitlab"}},
		{"citrix", []any{"citrix"}, nil, []string{"citrix", "netscaler"}},
		{"fortinet", []any{"fortinet"}, nil, []string{"fortinet"}},
		{"multiple, deduplicated, in order", []any{"nextjs", "react", "nginx"}, nil, []string{"nextjs", "react", "nginx"}},
		{"extra tags appended", []any{"grafana"}, []string{"custom", "Grafana"}, []string{"grafana", "custom"}},
		// No real nuclei tag exists for these: they must not invent one.
		{"remix has no tag: generic fallback", []any{"remix"}, nil, generic},
		{"svelte has no tag: generic fallback", []any{"svelte"}, nil, generic},
		{"unknown tech: generic fallback", []any{"weirdframework"}, nil, generic},
		{"no tech: generic fallback", nil, nil, generic},
		{"fallback plus extras", nil, []string{"custom"}, append(slices.Clone(generic), "custom")},
		{"hostile tech value is not a tag", []any{"nextjs; rm -rf /"}, nil, generic},
	}
	for _, tc := range tests {
		a := model.Asset{Kind: model.KindURL, Key: "https://x.example.com"}
		if tc.tech != nil {
			a.Attrs = map[string]any{"tech": tc.tech}
		}
		if got := selectTags(a, tc.extra); !slices.Equal(got, tc.want) {
			t.Errorf("%s: selectTags = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Every table entry must be a valid tag token, and the table must stay free of
// tags nuclei has no templates for (checked against a real release in the
// live test).
func TestTechTagTableIsWellFormed(t *testing.T) {
	for tech, tags := range techTags {
		if tech != normaliseTech(tech) {
			t.Errorf("key %q is not in normalised form", tech)
		}
		if len(tags) == 0 {
			t.Errorf("%q maps to nothing", tech)
		}
		for _, tag := range tags {
			if !tagRe.MatchString(tag) || tag != toLowerTrim(tag) {
				t.Errorf("%q maps to invalid tag %q", tech, tag)
			}
		}
	}
	for alias, canon := range techAliases {
		if _, ok := techTags[canon]; !ok {
			t.Errorf("alias %q points at unknown tech %q", alias, canon)
		}
	}
	for _, tag := range genericTags {
		if !tagRe.MatchString(tag) {
			t.Errorf("generic tag %q invalid", tag)
		}
	}
}

func toLowerTrim(s string) string { return normaliseTech(s) }
