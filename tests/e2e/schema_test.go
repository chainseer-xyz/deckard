//go:build staging

package e2e

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// spec is the parsed docs/openapi.yaml, used to validate live responses.
type spec struct{ root map[string]any }

func loadSpec(path string) (*spec, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path to a test fixture
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	return &spec{root: root}, nil
}

func dig(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

// resolve follows a local $ref chain.
func (s *spec) resolve(v any) map[string]any {
	m, _ := v.(map[string]any)
	for i := 0; i < 10 && m != nil; i++ {
		ref, ok := m["$ref"].(string)
		if !ok {
			return m
		}
		parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
		m, _ = dig(s.root, parts...).(map[string]any)
	}
	return m
}

// flatten merges allOf members into one schema (properties and required unioned).
func (s *spec) flatten(sc map[string]any) map[string]any {
	sc = s.resolve(sc)
	all, ok := sc["allOf"].([]any)
	if !ok {
		return sc
	}
	out := map[string]any{}
	props := map[string]any{}
	var req []any
	for k, v := range sc {
		if k != "allOf" {
			out[k] = v
		}
	}
	for _, part := range all {
		p := s.flatten(s.resolve(part))
		for k, v := range p {
			switch k {
			case "properties":
				for pk, pv := range v.(map[string]any) {
					props[pk] = pv
				}
			case "required":
				req = append(req, v.([]any)...)
			default:
				if _, set := out[k]; !set {
					out[k] = v
				}
			}
		}
	}
	if existing, ok := out["properties"].(map[string]any); ok {
		for pk, pv := range existing {
			props[pk] = pv
		}
	}
	out["properties"] = props
	if len(req) > 0 {
		out["required"] = req
	}
	return out
}

// responseSchema returns the JSON schema of the given operation's response.
func (s *spec) responseSchema(path, method, status string) map[string]any {
	op := dig(s.root, "paths", path, strings.ToLower(method))
	m, _ := op.(map[string]any)
	resp := s.resolve(dig(m, "responses", status))
	sc, _ := dig(resp, "content", "application/json", "schema").(map[string]any)
	return sc
}

// validate checks val against schema and returns human-readable violations.
// Objects that declare properties are strict: an undocumented field is a
// violation, so the spec cannot drift silently from the server.
func (s *spec) validate(schema map[string]any, val any) []string {
	var errs []string
	s.check("$", schema, val, &errs)
	return errs
}

func (s *spec) check(path string, schema map[string]any, val any, errs *[]string) {
	sc := s.flatten(schema)
	if sc == nil {
		return
	}
	if val == nil {
		if nullable, _ := sc["nullable"].(bool); !nullable {
			*errs = append(*errs, path+": null but not nullable")
		}
		return
	}
	if enum, ok := sc["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if fmt.Sprint(e) == fmt.Sprint(val) {
				found = true
			}
		}
		if !found {
			*errs = append(*errs, fmt.Sprintf("%s: %v not in enum %v", path, val, enum))
		}
	}
	typ, _ := sc["type"].(string)
	if typ == "" && sc["properties"] != nil {
		typ = "object"
	}
	switch typ {
	case "object":
		m, ok := val.(map[string]any)
		if !ok {
			*errs = append(*errs, fmt.Sprintf("%s: want object, got %T", path, val))
			return
		}
		props, _ := sc["properties"].(map[string]any)
		if req, ok := sc["required"].([]any); ok {
			for _, r := range req {
				if _, present := m[fmt.Sprint(r)]; !present {
					*errs = append(*errs, fmt.Sprintf("%s: missing required %q", path, r))
				}
			}
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		addl := sc["additionalProperties"]
		for _, k := range keys {
			if ps, ok := props[k]; ok {
				s.check(path+"."+k, s.resolve(ps), m[k], errs)
				continue
			}
			switch a := addl.(type) {
			case map[string]any:
				s.check(path+"."+k, a, m[k], errs)
			case bool:
				if !a {
					*errs = append(*errs, fmt.Sprintf("%s: undocumented field %q", path, k))
				}
			default:
				if len(props) > 0 {
					*errs = append(*errs, fmt.Sprintf("%s: undocumented field %q", path, k))
				}
			}
		}
	case "array":
		a, ok := val.([]any)
		if !ok {
			*errs = append(*errs, fmt.Sprintf("%s: want array, got %T", path, val))
			return
		}
		if items, ok := sc["items"].(map[string]any); ok {
			for i, it := range a {
				s.check(fmt.Sprintf("%s[%d]", path, i), items, it, errs)
			}
		}
	case "string":
		str, ok := val.(string)
		if !ok {
			*errs = append(*errs, fmt.Sprintf("%s: want string, got %T", path, val))
			return
		}
		if sc["format"] == "date-time" {
			if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
				*errs = append(*errs, fmt.Sprintf("%s: %q is not RFC3339", path, str))
			}
		}
	case "integer":
		f, ok := val.(float64)
		if !ok || f != float64(int64(f)) {
			*errs = append(*errs, fmt.Sprintf("%s: want integer, got %v", path, val))
			return
		}
		if mn, ok := sc["minimum"].(int); ok && f < float64(mn) {
			*errs = append(*errs, fmt.Sprintf("%s: %v below minimum %d", path, f, mn))
		}
		if mx, ok := sc["maximum"].(int); ok && f > float64(mx) {
			*errs = append(*errs, fmt.Sprintf("%s: %v above maximum %d", path, f, mx))
		}
	case "number":
		if _, ok := val.(float64); !ok {
			*errs = append(*errs, fmt.Sprintf("%s: want number, got %T", path, val))
		}
	case "boolean":
		if _, ok := val.(bool); !ok {
			*errs = append(*errs, fmt.Sprintf("%s: want boolean, got %T", path, val))
		}
	}
}
