// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjwt

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

// RequestContext carries deployment-side inputs for constraint
// evaluation and capability plugins.
type RequestContext struct {
	Now             time.Time
	SourceIP        netip.Addr
	ConcurrentCount int
}

// ConstraintEvaluator evaluates one constraint capability.
type ConstraintEvaluator func(c Capability, ctx RequestContext) error

// BuiltinConstraintIDs maps the built-in constraint types of draft
// Section 7 to evaluators.
var BuiltinConstraintIDs = map[string]ConstraintEvaluator{
	"allowed-cidr":   evalAllowedCIDR,
	"max-concurrent": evalMaxConcurrent,
	"time-window":    evalTimeWindow,
}

func evalAllowedCIDR(c Capability, ctx RequestContext) error {
	var cidrs []string
	if err := json.Unmarshal(c.Params, &cidrs); err != nil {
		return fmt.Errorf("allowed-cidr: params must be a JSON array of CIDR strings: %w", err)
	}
	if !ctx.SourceIP.IsValid() {
		return fmt.Errorf("allowed-cidr: no source IP in request context")
	}
	for _, cidr := range cidrs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("allowed-cidr: invalid CIDR %q: %w", cidr, err)
		}
		if p.Contains(ctx.SourceIP) {
			return nil
		}
	}
	return fmt.Errorf("allowed-cidr: source IP %s not in allowed ranges", ctx.SourceIP)
}

func evalMaxConcurrent(c Capability, ctx RequestContext) error {
	var p struct {
		Max int `json:"max"`
	}
	if err := json.Unmarshal(c.Params, &p); err != nil {
		return fmt.Errorf("max-concurrent: params must be {\"max\": N}: %w", err)
	}
	if p.Max < 1 {
		return fmt.Errorf("max-concurrent: max must be >= 1")
	}
	if ctx.ConcurrentCount >= p.Max {
		return fmt.Errorf("max-concurrent: concurrent count %d exceeds max %d", ctx.ConcurrentCount, p.Max)
	}
	return nil
}

func evalTimeWindow(c Capability, ctx RequestContext) error {
	var p struct {
		Start string `json:"start"`
		End   string `json:"end"`
	}
	if err := json.Unmarshal(c.Params, &p); err != nil {
		return fmt.Errorf("time-window: params must be {\"start\":...,\"end\":...}: %w", err)
	}
	parse := func(s string) (int, error) {
		t, err := time.Parse("15:04", s)
		if err != nil {
			return 0, fmt.Errorf("time-window: invalid HH:MM %q", s)
		}
		return t.Hour()*60 + t.Minute(), nil
	}
	start, err := parse(p.Start)
	if err != nil {
		return err
	}
	end, err := parse(p.End)
	if err != nil {
		return err
	}
	now := ctx.Now.UTC()
	cur := now.Hour()*60 + now.Minute()
	if start <= end {
		if cur < start || cur > end {
			return fmt.Errorf("time-window: now %s outside [%s,%s]", now.Format("15:04"), p.Start, p.End)
		}
	} else if cur < start && cur > end {
		// overnight window, e.g. 22:00-06:00
		return fmt.Errorf("time-window: now %s outside overnight window [%s,%s]", now.Format("15:04"), p.Start, p.End)
	}
	return nil
}

// EvaluateConstraints evaluates all constraints with AND semantics
// (draft Section 7).  Unknown constraint types are ignored with an
// audit note unless strict is true.  Constraint scheme values other
// than varwof/constraint-v1 MUST be rejected.
func EvaluateConstraints(cs []Capability, ctx RequestContext, strict bool) ([]string, error) {
	var notes []string
	for _, c := range cs {
		if c.Scheme != ConstraintScheme {
			return notes, fmt.Errorf("constraint scheme %q not allowed (must be %s)", c.Scheme, ConstraintScheme)
		}
		eval, ok := BuiltinConstraintIDs[c.ID]
		if !ok {
			if strict {
				return notes, fmt.Errorf("unknown constraint type %q (strict mode)", c.ID)
			}
			notes = append(notes, fmt.Sprintf("audit: unknown constraint type %q ignored", c.ID))
			continue
		}
		if err := eval(c, ctx); err != nil {
			return notes, err
		}
	}
	return notes, nil
}
