package aicjwt

import (
	"encoding/json"
	"testing"
)

// TestCapabilitySubset covers CapabilitySubset: whether a specific agent
// capability is covered by (is a subset of) at least one grant.
func TestCapabilitySubset(t *testing.T) {
	params := func(s string) json.RawMessage { return json.RawMessage(s) }

	cases := []struct {
		name   string
		agent  Capability
		grants []Capability
		want   bool
	}{
		{
			name:  "exact match",
			agent: Capability{Scheme: "database", ID: "query:SELECT"},
			grants: []Capability{
				{Scheme: "database", ID: "query:SELECT"},
			},
			want: true,
		},
		{
			name:  "wildcard grant covers specific agent",
			agent: Capability{Scheme: "database", ID: "query:SELECT"},
			grants: []Capability{
				{Scheme: "database", ID: "query:*"},
			},
			want: true,
		},
		{
			name:  "specific grant does not cover broader agent",
			agent: Capability{Scheme: "database", ID: "query:*"},
			grants: []Capability{
				{Scheme: "database", ID: "query:SELECT"},
			},
			want: false,
		},
		{
			name:  "scheme mismatch",
			agent: Capability{Scheme: "database", ID: "query:SELECT"},
			grants: []Capability{
				{Scheme: "http", ID: "query:*"},
			},
			want: false,
		},
		{
			name:  "params within grant bound",
			agent: Capability{Scheme: "database", ID: "query:SELECT", Params: params(`{"max_rows":500}`)},
			grants: []Capability{
				{Scheme: "database", ID: "query:*", Params: params(`{"max_rows":1000}`)},
			},
			want: true,
		},
		{
			name:  "params exceed grant bound",
			agent: Capability{Scheme: "database", ID: "query:SELECT", Params: params(`{"max_rows":2000}`)},
			grants: []Capability{
				{Scheme: "database", ID: "query:*", Params: params(`{"max_rows":1000}`)},
			},
			want: false,
		},
		{
			name:  "agent param unrestricted by grant",
			agent: Capability{Scheme: "database", ID: "query:SELECT", Params: params(`{"max_rows":100}`)},
			grants: []Capability{
				{Scheme: "database", ID: "query:*"},
			},
			want: true,
		},
		{
			name:  "no grants",
			agent: Capability{Scheme: "database", ID: "query:SELECT"},
			want:  false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CapabilitySubset(c.agent, c.grants); got != c.want {
				t.Fatalf("CapabilitySubset = %v, want %v", got, c.want)
			}
		})
	}
}
