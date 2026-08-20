package pki_test

import (
	"testing"

	pki "github.com/varwof/types"
)

func TestMatchCapability_ExactMatch(t *testing.T) {
	if !pki.MatchCapability("gateway:admin", "gateway:admin") {
		t.Fatal("expected exact match")
	}
}

func TestMatchCapability_WildcardAll(t *testing.T) {
	if !pki.MatchCapability("anything", "**") {
		t.Fatal("expected ** to match everything")
	}
}

func TestMatchCapability_StarAll(t *testing.T) {
	if !pki.MatchCapability("anything", "*") {
		t.Fatal("expected * to match everything")
	}
}

func TestMatchCapability_PrefixWildcard(t *testing.T) {
	if !pki.MatchCapability("ca:list", "ca:*") {
		t.Fatal("expected ca:* to match ca:list")
	}
	if !pki.MatchCapability("ca:create", "ca:*") {
		t.Fatal("expected ca:* to match ca:create")
	}
}

func TestMatchCapability_SingleSegmentWildcard(t *testing.T) {
	if !pki.MatchCapability("gateway:admin", "gateway:?dmin") {
		t.Fatal("expected ? to match a single char")
	}
}

func TestMatchCapability_NamespaceHierarchy(t *testing.T) {
	// ** matches across segments
	if !pki.MatchCapability("ca:issuing:create", "ca:**") {
		t.Fatal("expected ca:** to match ca:issuing:create")
	}
	if !pki.MatchCapability("ca:issuing:create", "**") {
		t.Fatal("expected ** to match anything")
	}
}

func TestMatchCapability_NoMatch(t *testing.T) {
	if pki.MatchCapability("ca:create", "crl:*") {
		t.Fatal("expected no match for different prefix")
	}
	if pki.MatchCapability("gateway:admin", "gateway:ops") {
		t.Fatal("expected no match for exact mismatch")
	}
}

func TestMatchCapability_DoubleStarPrefix(t *testing.T) {
	if !pki.MatchCapability("x/y/z", "x/**") {
		t.Fatal("expected x/** to match x/y/z")
	}
}

func TestMatchCapability_DoubleStarSuffix(t *testing.T) {
	if !pki.MatchCapability("a/b/c", "**/c") {
		t.Fatal("expected **/c to match a/b/c")
	}
}

func TestMatchCapability_DoubleStarMiddle(t *testing.T) {
	if !pki.MatchCapability("a/b/c/d", "a/**/d") {
		t.Fatal("expected a/**/d to match a/b/c/d")
	}
}

func TestMatchCapability_DoubleStarZeroSegments(t *testing.T) {
	if !pki.MatchCapability("x/y", "x/**/y") {
		t.Fatalf("expected x/**/y to match x/y (zero segments)")
	}
}

func TestMatchCapability_ManyPartsDoubleStar(t *testing.T) {
	// ** with more than 2 parts should fail
	if pki.MatchCapability("a/b/c", "a/**/b/**") {
		t.Fatal("expected false for more than 2 ** parts")
	}
}

func TestMatchCapability_PathMatchVsStar(t *testing.T) {
	// path.Match treats / as separator
	if !pki.MatchCapability("ca:list", "ca:*") {
		t.Fatal("expected ca:* to match ca:list")
	}
}

func TestMatchCapability_EdgeCases(t *testing.T) {
	tests := []struct {
		id      string
		pattern string
		match   bool
	}{
		{"", "", true},
		{"a", "", false},
		{"", "a", false},
		{"a", "a", true},
		{"a", "b", false},
		{"a/b", "a/*", true},
		{"a/b/c", "a/*/c", true},
		{"a/b/c", "a/*", false},
	}
	for _, tt := range tests {
		got := pki.MatchCapability(tt.id, tt.pattern)
		if got != tt.match {
			t.Fatalf("MatchCapability(%q, %q): expected %v, got %v", tt.id, tt.pattern, tt.match, got)
		}
	}
}

func BenchmarkMatchCapability(b *testing.B) {
	b.Run("exact", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pki.MatchCapability("gateway:admin", "gateway:admin")
		}
	})
	b.Run("star", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pki.MatchCapability("ca:list:all", "ca:*")
		}
	})
	b.Run("doublestar", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pki.MatchCapability("ca:issuing:create:all", "ca:**")
		}
	})
}
