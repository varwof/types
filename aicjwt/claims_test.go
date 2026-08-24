// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjwt

import (
	"encoding/json"
	"testing"

	pki "github.com/varwof/types"
)

func TestAudienceUnmarshal(t *testing.T) {
	var a Audience
	if err := json.Unmarshal([]byte(`"https://rs.example.com"`), &a); err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || a[0] != "https://rs.example.com" {
		t.Fatalf("string aud parsed as %v", a)
	}
	var b Audience
	if err := json.Unmarshal([]byte(`["a","b"]`), &b); err != nil {
		t.Fatal(err)
	}
	if len(b) != 2 || !b.Contains("b") {
		t.Fatalf("array aud parsed as %v", b)
	}
	if err := json.Unmarshal([]byte(`42`), &a); err == nil {
		t.Fatal("numeric aud must be rejected")
	}
}

func TestJSONRawEqual(t *testing.T) {
	eq, err := JSONRawEqual(
		json.RawMessage(`{"b":1,"a":[2,{"d":3,"c":4}]}`),
		json.RawMessage(`{"a":[2,{"c":4,"d":3}],"b":1}`),
	)
	if err != nil || !eq {
		t.Fatalf("order-independent JSON must be equal: %v %v", eq, err)
	}
	eq, err = JSONRawEqual(json.RawMessage(`{"a":1}`), json.RawMessage(`{"a":2}`))
	if err != nil || eq {
		t.Fatalf("different JSON must not be equal")
	}
}

func TestCapabilityConverters(t *testing.T) {
	jwtCap := Capability{Scheme: "database", ID: "query:SELECT", Params: json.RawMessage(`{"max_rows":100}`)}
	pkiCap := CapToPKI(jwtCap)
	if pkiCap.SchemeId != "database" || pkiCap.CapabilityId != "query:SELECT" {
		t.Fatalf("bad CapToPKI: %+v", pkiCap)
	}
	round := PKIToCap(pkiCap)
	if round.Scheme != jwtCap.Scheme || round.ID != jwtCap.ID {
		t.Fatalf("bad round-trip: %+v", round)
	}
	if string(round.Params) != string(jwtCap.Params) {
		t.Fatalf("params round-trip mismatch: %s vs %s", round.Params, jwtCap.Params)
	}
	empty := PKIToCap(pki.Capability{SchemeId: "http", CapabilityId: "GET"})
	if len(empty.Params) != 0 {
		t.Fatalf("expected no params, got %s", empty.Params)
	}
}
