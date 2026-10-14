package assessmentexec

import (
	"bytes"
	"encoding/json"
)

// encoding/json otherwise silently accepts duplicate object keys. Reject them
// at the boundary so no consumer can interpret a different execution grant.
func duplicateJSONKeys(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	return walkJSON(d, 0) != nil
}

func walkJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	token, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
		}
		if walkJSON(d, depth+1) != nil {
			return ErrInvalid
		}
	}
	_, err = d.Token()
	return err
}
