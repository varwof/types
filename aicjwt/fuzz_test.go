// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjwt

import (
	"encoding/json"
	"testing"
)

// FuzzAudienceUnmarshal guards the Audience JSON edge cases that were
// found by inspection (e.g. "null" decoding to [""] and passing the
// length check).  Run: go test -fuzz=FuzzAudienceUnmarshal ./aicjwt/
func FuzzAudienceUnmarshal(f *testing.F) {
	for _, s := range []string{
		`"https://as.example.com"`,
		`["https://as.example.com"]`,
		`null`,
		`[""]`,
		`""`,
		`[]`,
		`[1,2]`,
		`{"a":1}`,
		`[null, "x"]`,
		`[["x"]]`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var a Audience
		_ = json.Unmarshal([]byte(s), &a)
		for _, v := range a {
			_ = len(v)
		}
	})
}

// FuzzDAClaimsUnmarshal ensures arbitrary JSON payloads cannot panic
// claim parsing.  Semantic rejection is handled by checkDARequired /
// ValidateDA; this fuzz only guards the decode path.
func FuzzDAClaimsUnmarshal(f *testing.F) {
	for _, s := range []string{
		`{}`,
		`{"ver":2}`,
		`{"ver":2,"iss":"corp.com:zhangsan","sub":"agent:x","aud":["https://as.example.com"],"exp":1,"jti":"n","agent_id":"agent:x","principal":{"realm":"c","id":"z","key_hash":"k"},"reason":{"code":"A","desc":"b"},"capabilities":[],"delegation_mode":"authorized","requested_lifetime":1,"ts":1,"nonce":"n"}`,
		`null`,
		`[]`,
		`"x"`,
		`{"agent_id":1}`,
		`{"ver":"x"}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var d DAClaims
		_ = json.Unmarshal([]byte(s), &d)
	})
}
