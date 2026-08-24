// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"testing"

	pki "github.com/varwof/types"
)

func TestMatchCapabilityPriority_Levels(t *testing.T) {
	tests := []struct {
		id       string
		pattern  string
		priority int
	}{
		// Exact match
		{"database:query:SELECT", "database:query:SELECT", pki.MatchPriorityExact},
		// Single-segment wildcard
		{"database:query:SELECT", "database:query:*", pki.MatchPrioritySingle},
		{"database:query:SELECT", "database:*:SELECT", pki.MatchPrioritySingle},
		{"database:query:EXPLAIN", "database:*:SELECT", pki.MatchPriorityNoMatch},
		// Multi-segment wildcard
		{"database:query:SELECT", "database:**", pki.MatchPriorityMulti},
		{"database:query:SELECT", "**", pki.MatchPriorityGlobal}, // "**" as a whole is a global wildcard
		{"database:query:SELECT", "database:**:SELECT", pki.MatchPriorityMulti},
		{"database:query:EXPLAIN", "database:**:SELECT", pki.MatchPriorityNoMatch},
		// Scheme wildcard
		{"mysql:query:SELECT", "*:query:SELECT", pki.MatchPriorityScheme},
		{"pgsql:query:SELECT", "*:query:SELECT", pki.MatchPriorityScheme},
		{"mysql:query:EXPLAIN", "*:query:SELECT", pki.MatchPriorityNoMatch},
		// Global wildcard
		{"anything:at:all", "*", pki.MatchPriorityGlobal},
		{"anything:at:all", "**", pki.MatchPriorityGlobal},
		{"anything:at:all", "*:*", pki.MatchPriorityGlobal},
	}
	for _, tt := range tests {
		got := pki.MatchCapabilityPriority(tt.id, tt.pattern)
		if got != tt.priority {
			t.Fatalf("MatchCapabilityPriority(%q, %q) = %d, want %d",
				tt.id, tt.pattern, got, tt.priority)
		}
	}
}

func TestMatchCapabilityPriority_Subsumption(t *testing.T) {
	// Exact > single > multi > scheme > global: when the same id matches multiple rules, the highest priority should win.
	id := "database:query:SELECT"
	rules := []pki.CapabilityRule{
		{Pattern: "**", Deny: true},
		{Pattern: "database:query:*", Deny: true},
		{Pattern: "database:query:SELECT", Deny: false},
	}
	m := pki.MatchCapabilityRules(id, rules)
	if !m.Matched || m.Deny || m.Priority != pki.MatchPriorityExact || m.Pattern != "database:query:SELECT" {
		t.Fatalf("exact should win over global: %+v", m)
	}
}

func TestMatchCapabilityRules_DenyOverridesAllow(t *testing.T) {
	id := "database:query:SELECT"
	rules := []pki.CapabilityRule{
		{Pattern: "database:**", Deny: true},
		{Pattern: "database:query:SELECT", Deny: false},
	}
	// Same priority (multi vs exact, no conflict) — here deny has lower priority, exact allow should win.
	m := pki.MatchCapabilityRules(id, rules)
	if !m.Matched || m.Deny {
		t.Fatalf("exact allow should beat multi deny: %+v", m)
	}

	// At the same priority, deny overrides allow.
	rules2 := []pki.CapabilityRule{
		{Pattern: "database:query:SELECT", Deny: false},
		{Pattern: "database:query:SELECT", Deny: true},
	}
	m2 := pki.MatchCapabilityRules(id, rules2)
	if !m2.Matched || !m2.Deny {
		t.Fatalf("deny should override allow at same priority: %+v", m2)
	}
}

func TestMatchCapabilityRules_NoMatch(t *testing.T) {
	m := pki.MatchCapabilityRules("ca:create", []pki.CapabilityRule{{Pattern: "crl:*"}})
	if m.Matched {
		t.Fatalf("no match expected, got %+v", m)
	}
}

func TestMatchCapabilityPriority_Compatibility(t *testing.T) {
	// Existing MatchCapability boolean semantics should be covered by priority matching (> 0 == true).
	compat := []struct{ id, pattern string }{
		{"gateway:admin", "gateway:admin"},
		{"gateway:admin", "gateway:*"},
		{"ca:issuing:create", "ca:**"},
		{"anything", "**"},
		{"anything", "*"},
	}
	for _, c := range compat {
		if !pki.MatchCapability(c.id, c.pattern) {
			t.Fatalf("MatchCapability(%q,%q) should be true", c.id, c.pattern)
		}
		if pki.MatchCapabilityPriority(c.id, c.pattern) == pki.MatchPriorityNoMatch {
			t.Fatalf("priority should match for %q,%q", c.id, c.pattern)
		}
	}
	// Non-matching cases should also be consistent
	if pki.MatchCapability("ca:create", "crl:*") {
		t.Fatal("should not match")
	}
}
