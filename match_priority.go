package pki

import (
	"fmt"
	"path/filepath"
	"strings"
)

// MatchPriority defines the priority levels for capabilityId matching (spec P1-B-19 / P2-B-06).
// Higher values are more specific; the highest priority matching rule wins in decisions, deny overrides allow.
const (
	// MatchPriorityNoMatch no match.
	MatchPriorityNoMatch = 0
	// MatchPriorityGlobal global wildcard: pattern is "*", "**", or "*:*".
	MatchPriorityGlobal = 1
	// MatchPriorityScheme scheme wildcard: first segment is "*", remaining segments match exactly (e.g. *:query:SELECT).
	MatchPriorityScheme = 2
	// MatchPriorityMulti multi-segment wildcard: contains "**" segment, matches one or more cross-segment parts (e.g. database:**).
	MatchPriorityMulti = 3
	// MatchPrioritySingle single-segment wildcard: all segments are literals or "*", * matches any single segment content (excluding ':').
	MatchPrioritySingle = 4
	// MatchPriorityExact exact match: id == pattern.
	MatchPriorityExact = 5
)

// CapabilityRule is a matching rule with an action, used for "deny overrides allow" decisions.
type CapabilityRule struct {
	// Pattern matching pattern (supports five-level wildcard syntax).
	Pattern string
	// Deny when true indicates a deny rule; false indicates an allow rule.
	Deny bool
}

// CapabilityRuleMatch is the result of a rule match.
type CapabilityRuleMatch struct {
	// Matched indicates whether a matching rule exists.
	Matched bool
	// Deny indicates whether the rule is a deny rule (deny overrides allow).
	Deny bool
	// Priority is the highest priority level matched (MatchPriority*).
	Priority int
	// Pattern is the matched rule pattern.
	Pattern string
}

// MatchCapabilityPriority determines whether id matches pattern and returns the matched priority level.
//
// Semantics (per spec):
//   - capabilityId is segmented by ':'
//   - '*' matches any single segment content (excluding ':')
//   - '**' matches one or more cross-segment parts
//   - Priority: exact(5) > single-segment-wildcard(4) > multi-segment-wildcard(3) > scheme-wildcard(2) > global-wildcard(1)
//
// Returns MatchPriorityNoMatch(0) if no match.
func MatchCapabilityPriority(id, pattern string) int {
	if id == pattern {
		return MatchPriorityExact
	}
	if pattern == "*" || pattern == "**" || pattern == "*:*" {
		return MatchPriorityGlobal
	}
	idSegs := strings.Split(id, ":")
	patSegs := strings.Split(pattern, ":")
	if len(idSegs) == 0 || len(patSegs) == 0 {
		return MatchPriorityNoMatch
	}
	// Scheme wildcard: first segment "*", remaining segments have no wildcards and match exactly.
	if len(patSegs) >= 2 && patSegs[0] == "*" && !segmentsContainWildcard(patSegs[1:]) {
		if len(idSegs) == len(patSegs) && segmentsEqual(idSegs[1:], patSegs[1:]) {
			return MatchPriorityScheme
		}
	}
	// Multi-segment wildcard: contains "**" segment.
	if segmentsContainDoubleStar(patSegs) {
		if matchDoubleStarSegments(idSegs, patSegs) {
			return MatchPriorityMulti
		}
	}
	// Single-segment wildcard: same number of segments, each segment is a literal or "*" (or intra-segment glob).
	if len(idSegs) == len(patSegs) && matchSingleSegments(idSegs, patSegs) {
		return MatchPrioritySingle
	}
	return MatchPriorityNoMatch
}

// MatchCapabilityRules makes priority-based decisions within a rule set:
// picks the highest priority matching rule; at the same priority, deny overrides allow.
// When no rule matches, returns Matched=false (caller handles per default policy, typically deny).
func MatchCapabilityRules(id string, rules []CapabilityRule) CapabilityRuleMatch {
	var best CapabilityRuleMatch
	for _, r := range rules {
		if p := MatchCapabilityPriority(id, r.Pattern); p > best.Priority {
			best = CapabilityRuleMatch{
				Matched:  true,
				Deny:     r.Deny,
				Priority: p,
				Pattern:  r.Pattern,
			}
		} else if p == best.Priority && p > 0 && r.Deny && !best.Deny {
			// At the same priority, deny overrides allow.
			best = CapabilityRuleMatch{
				Matched:  true,
				Deny:     true,
				Priority: p,
				Pattern:  r.Pattern,
			}
		}
	}
	return best
}

// segmentsContainWildcard checks whether segments contain a wildcard ('*' or '?').
func segmentsContainWildcard(segs []string) bool {
	for _, s := range segs {
		if strings.ContainsAny(s, "*?") {
			return true
		}
	}
	return false
}

// segmentsContainDoubleStar checks whether segments contain a "**" segment.
func segmentsContainDoubleStar(segs []string) bool {
	for _, s := range segs {
		if s == "**" {
			return true
		}
	}
	return false
}

// segmentsEqual performs exact equality comparison of segments.
func segmentsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// matchSingleSegment matches a single segment: literal equality, '*' (matches any single segment), or intra-segment glob (* / ?).
func matchSingleSegment(idSeg, patSeg string) bool {
	if patSeg == "*" {
		return true
	}
	if strings.ContainsAny(patSeg, "*?") {
		ok, _ := filepath.Match(patSeg, idSeg)
		return ok
	}
	return idSeg == patSeg
}

// matchSingleSegments performs single-segment wildcard matching: same number of segments, matched segment by segment (does not handle "**").
func matchSingleSegments(idSegs, patSegs []string) bool {
	for i := range patSegs {
		if patSegs[i] == "**" {
			return false
		}
		if !matchSingleSegment(idSegs[i], patSegs[i]) {
			return false
		}
	}
	return true
}

// matchDoubleStarSegments handles matching with "**" segments.
// "**" matches one or more cross-segment parts; prefix and suffix segments are matched by single-segment wildcard.
func matchDoubleStarSegments(idSegs, patSegs []string) bool {
	// Find the first and last "**".
	first := -1
	last := -1
	for i, s := range patSegs {
		if s == "**" {
			if first == -1 {
				first = i
			}
			last = i
		}
	}
	if first == -1 {
		return false
	}
	// Prefix segments: first segments of idSegs must single-segment match the first segments of patSegs.
	if first > len(idSegs) {
		return false
	}
	for i := 0; i < first; i++ {
		if !matchSingleSegment(idSegs[i], patSegs[i]) {
			return false
		}
	}
	// Suffix segments: the last (len(patSegs)-last-1) segments of idSegs must match the suffix of patSegs.
	suffixLen := len(patSegs) - last - 1
	if first+suffixLen > len(idSegs) {
		return false
	}
	idTail := idSegs[len(idSegs)-suffixLen:]
	patTail := patSegs[last+1:]
	for i := 0; i < suffixLen; i++ {
		if !matchSingleSegment(idTail[i], patTail[i]) {
			return false
		}
	}
	return true
}

// MatchCapabilityPriorityString returns a human-readable name for the priority level (debugging/audit).
func MatchCapabilityPriorityString(p int) string {
	switch p {
	case MatchPriorityNoMatch:
		return "no-match"
	case MatchPriorityGlobal:
		return "global"
	case MatchPriorityScheme:
		return "scheme"
	case MatchPriorityMulti:
		return "multi-segment"
	case MatchPrioritySingle:
		return "single-segment"
	case MatchPriorityExact:
		return "exact"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}
