package aicjwt

import (
	"encoding/json"
	"reflect"
	"strings"
)

// capPattern joins a capability into the "scheme:capabilityId" form.
func capPattern(c Capability) string {
	return c.Scheme + ":" + c.ID
}

// matchPattern matches a target "scheme:id" string against a
// capability pattern and returns (matched, specificity).  Precedence
// per 07-capability: exact(6) > single-segment(5) > multi-segment(4) >
// alternation {a,b}(3) > char class [a-z](2) > scheme-level(1).
//
// The pattern is first split on ":"; each segment is then split on "/"
// so that "*" matches a single path segment (without "/") and "**"
// matches one or more segments (possibly crossing "/").  Within a
// segment, {a,b} alternation and [a-z] character classes are supported
// (see matchToken).
func matchPattern(pattern, target string) (bool, int) {
	ps := strings.Split(pattern, ":")
	ts := strings.Split(target, ":")
	// scheme-level wildcard: pattern is exactly [scheme, "*"]
	if len(ps) == 2 && ps[1] == "*" {
		if len(ts) >= 2 && ts[0] == ps[0] {
			return true, 1
		}
		return false, 0
	}
	if !matchTokens(tokenize(ps), tokenize(ts)) {
		return false, 0
	}
	return true, patternScore(ps)
}

// tokenize turns ":" and "/" separated segments into a flat token
// stream that keeps the separators, so wildcards match exactly one
// literal token (a path or colon segment) and "**" matches across
// separators.
func tokenize(segs []string) []string {
	var out []string
	for i, s := range segs {
		if i > 0 {
			out = append(out, ":")
		}
		if s == "*" || s == "**" {
			out = append(out, s)
			continue
		}
		parts := strings.Split(s, "/")
		for j, part := range parts {
			if j > 0 {
				out = append(out, "/")
			}
			out = append(out, part)
		}
	}
	return out
}

func matchTokens(p, t []string) bool {
	if len(p) == 0 {
		return len(t) == 0
	}
	switch p[0] {
	case "**":
		if len(t) == 0 {
			return false
		}
		for i := 1; i <= len(t); i++ {
			if matchTokens(p[1:], t[i:]) {
				return true
			}
		}
		return false
	case "*":
		if len(t) == 0 || t[0] == "/" || t[0] == ":" {
			return false
		}
		return matchTokens(p[1:], t[1:])
	default:
		if len(t) == 0 {
			return false
		}
		// Literal tokens may carry {a,b} alternation, [a-z] character
		// classes, or an embedded '*' (07-capability).
		if !matchToken(p[0], t[0]) {
			return false
		}
		return matchTokens(p[1:], t[1:])
	}
}

// matchToken matches a single token against a segment pattern that may
// contain:
//
//	'*'       any characters (including empty), within the token
//	'{a,b}'   alternation of literal alternatives
//	'[a-z]'   single character class with ranges
//
// Examples (07-capability): "{GET,POST}" matches GET or POST;
// "[A-Z]*" matches any token starting with an uppercase letter.
func matchToken(pattern, target string) bool {
	return matchTokenAt(pattern, 0, target, 0)
}

func matchTokenAt(p string, pi int, t string, ti int) bool {
	for {
		if pi >= len(p) {
			return ti >= len(t)
		}
		c := p[pi]
		switch {
		case c == '*':
			for k := ti; k <= len(t); k++ {
				if matchTokenAt(p, pi+1, t, k) {
					return true
				}
			}
			return false
		case c == '{':
			end := indexByteFrom(p, pi+1, '}')
			if end < 0 {
				return false // malformed alternation -> no match
			}
			for _, alt := range strings.Split(p[pi+1:end], ",") {
				if ti+len(alt) <= len(t) && t[ti:ti+len(alt)] == alt &&
					matchTokenAt(p, end+1, t, ti+len(alt)) {
					return true
				}
			}
			return false
		case c == '[':
			end := indexByteFrom(p, pi+1, ']')
			if end < 0 || ti >= len(t) {
				return false
			}
			if !inCharClass(p[pi+1:end], t[ti]) {
				return false
			}
			pi, ti = end+1, ti+1
		default:
			if ti >= len(t) || t[ti] != c {
				return false
			}
			pi, ti = pi+1, ti+1
		}
	}
}

// indexByteFrom returns the index of b in s starting at from, or -1.
func indexByteFrom(s string, from int, b byte) int {
	for i := from; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// inCharClass reports whether ch belongs to a class body like "a-z"
// or "0-9ABC".
func inCharClass(body string, ch byte) bool {
	for i := 0; i < len(body); i++ {
		if i+2 < len(body) && body[i+1] == '-' {
			if body[i] <= ch && ch <= body[i+2] {
				return true
			}
			i += 2
			continue
		}
		if body[i] == ch {
			return true
		}
	}
	return false
}

// patternScore ranks a matched pattern's specificity (07-capability
// precedence): exact > single * > multi ** > {a,b} > [a-z] > scheme.
func patternScore(ps []string) int {
	if len(ps) == 2 && ps[1] == "*" {
		return 1 // scheme-level wildcard
	}
	hasDouble, hasStar, hasAlt, hasClass := false, false, false, false
	for _, s := range ps {
		if strings.Contains(s, "**") {
			hasDouble = true
		}
		if strings.Contains(s, "*") {
			hasStar = true
		}
		if strings.Contains(s, "{") {
			hasAlt = true
		}
		if strings.Contains(s, "[") {
			hasClass = true
		}
	}
	switch {
	case hasDouble:
		return 4
	case hasStar:
		return 5
	case hasAlt:
		return 3
	case hasClass:
		return 2
	default:
		return 6
	}
}

// MatchCapabilities evaluates a request capability against the allowed
// capabilities using the glob rules and precedence of draft Section
// 6.2.  The highest-precedence matching rule decides; if no rule
// matches, the request MUST be denied.
func MatchCapabilities(allowed []Capability, req Capability) bool {
	target := capPattern(req)
	best := 0
	for _, c := range allowed {
		ok, score := matchPattern(capPattern(c), target)
		if ok && score > best {
			best = score
		}
	}
	return best > 0
}

// ParamsWithinGrant reports whether agent params stay within the
// grant's parameter bounds (draft Section 6.3).  Numeric values are
// bounded by the grant value (agent <= grant); non-numeric values must
// be equal; arrays must be subsets.  Scheme-specific plugins may
// supply stricter comparators.
func ParamsWithinGrant(grant, agent json.RawMessage) (bool, error) {
	if len(grant) == 0 || string(grant) == "null" {
		return true, nil
	}
	if len(agent) == 0 || string(agent) == "null" {
		return true, nil
	}
	gv, err := decodeNumber(grant)
	if err != nil {
		return false, err
	}
	av, err := decodeNumber(agent)
	if err != nil {
		return false, err
	}
	return paramsWithin(gv, av), nil
}

func paramsWithin(grant, agent any) bool {
	switch g := grant.(type) {
	case map[string]any:
		a, ok := agent.(map[string]any)
		if !ok {
			return false
		}
		for k, av := range a {
			gv, ok := g[k]
			if !ok {
				return false
			}
			if !paramsWithin(gv, av) {
				return false
			}
		}
		return true
	case json.Number:
		an, ok := agent.(json.Number)
		if !ok {
			return false
		}
		gi, gerr := g.Int64()
		ai, aerr := an.Int64()
		if gerr == nil && aerr == nil {
			return ai <= gi
		}
		gf, _ := g.Float64()
		af, _ := an.Float64()
		return af <= gf
	case string:
		a, ok := agent.(string)
		return ok && a == g
	case bool:
		a, ok := agent.(bool)
		return ok && a == g
	case []any:
		a, ok := agent.([]any)
		if !ok {
			return false
		}
		for _, x := range a {
			found := false
			for _, y := range g {
				if reflect.DeepEqual(x, y) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(grant, agent)
	}
}

// CapabilitySubset reports whether an agent capability is a
// capability-level and parameter-level subset of the principal grants
// (draft Section 8.2).
func CapabilitySubset(agent Capability, grants []Capability) bool {
	target := capPattern(agent)
	best := 0
	for _, g := range grants {
		ok, score := matchPattern(capPattern(g), target)
		if !ok || score <= best {
			continue
		}
		within, err := ParamsWithinGrant(g.Params, agent.Params)
		if err != nil || !within {
			continue
		}
		best = score
	}
	return best > 0
}
