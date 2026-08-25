package aicjwt

import (
	"bytes"
	"encoding/json"
)

// hasDuplicateJSONKeys reports whether the JSON document in raw
// contains an object with duplicate member names.  Duplicate member
// names are ambiguous across implementations (RFC 8725): some parsers
// keep the first value, others the last, and others reject the
// document.  The AIC-JWT validator rejects such documents before any
// claim is interpreted.
func hasDuplicateJSONKeys(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var walk func() bool
	walk = func() bool {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return false
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return false
				}
				key, _ := kt.(string)
				if _, dup := seen[key]; dup {
					return true
				}
				seen[key] = struct{}{}
				if walk() {
					return true
				}
			}
			// consume the closing '}'
			if _, err := dec.Token(); err != nil {
				return false
			}
		case '[':
			for dec.More() {
				if walk() {
					return true
				}
			}
			// consume the closing ']'
			if _, err := dec.Token(); err != nil {
				return false
			}
		}
		return false
	}
	return walk()
}
