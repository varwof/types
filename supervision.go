package pki

import (
	"fmt"
	"time"
)

// Supervision events: the unified pre/post/mid-operation supervision schema for
// the AIC SDK (design draft aic-sdk-监督接口设计-事前事中事后, §5).
//
// This type is shared between aic-agent (pre-operation: DA consent / denial)
// and aic-verifier (mid/post-operation: runtime approval, break-glass, override,
// step-up) so that aic-agent never needs to import aic-verifier.  Events are
// reconciled across stages by the two correlation keys:
//
//	operation_id — server-side per-request identifier (mid/post-operation);
//	da_hash      — sha256 hex fingerprint of the signed DA (pre/mid-operation).
//
// Storage is append-only JSONL with the same durability rules as the audit
// chain (critical events never dropped, TSA attachable).

// SupervisionEventType classifies a supervision event.
type SupervisionEventType string

const (
	// SupervisionConsent is the pre-operation event: a human approved the DA.
	SupervisionConsent SupervisionEventType = "consent"
	// SupervisionDenied is the pre/mid-operation event: a human rejected the operation.
	SupervisionDenied SupervisionEventType = "denied"
	// SupervisionStepUp is the event recorded when step-up (secondary authentication) passed.
	SupervisionStepUp SupervisionEventType = "step_up"
	// SupervisionApproval is the mid-operation event: on-site (runtime) human approval.
	SupervisionApproval SupervisionEventType = "approval"
	// SupervisionBreakGlass is the event recorded when a break-glass override was used.
	SupervisionBreakGlass SupervisionEventType = "break_glass"
	// SupervisionOverride is the event recorded when a policy override was applied.
	SupervisionOverride SupervisionEventType = "override"
)

// Valid reports whether t is one of the six defined supervision event types.
func (t SupervisionEventType) Valid() bool {
	switch t {
	case SupervisionConsent, SupervisionDenied, SupervisionStepUp,
		SupervisionApproval, SupervisionBreakGlass, SupervisionOverride:
		return true
	default:
		return false
	}
}

// SupervisionEvent is the unified supervision record shared by aic-agent
// (pre-operation) and aic-verifier (mid/post-operation).  Optional fields are
// omitted from JSON when empty.
type SupervisionEvent struct {
	Type        SupervisionEventType `json:"type"`
	Source      string               `json:"source"` // user-signer | aic-verifier | admin-console
	OperationID string               `json:"operation_id,omitempty"`
	DaHash      string               `json:"da_hash,omitempty"` // sha256 hex (64 lowercase chars)
	AgentID     string               `json:"agent_id,omitempty"`
	Actor       string               `json:"actor"`
	Reason      string               `json:"reason"`
	EvidenceRef string               `json:"evidence_ref,omitempty"`
	Decision    string               `json:"decision"` // approved | denied | pending
	Ts          time.Time            `json:"ts"`
}

// Supervision decisions referenced by SupervisionEvent.Decision.
const (
	SupervisionDecisionApproved = "approved"
	SupervisionDecisionDenied   = "denied"
	SupervisionDecisionPending  = "pending"
)

// ValidateSupervisionEvent validates e fail-closed (nil → error).  Rules:
//
//	Type is one of the six SupervisionEventType constants;
//	Source non-empty, ≤64 bytes;
//	Actor non-empty, ≤128 bytes;
//	Reason optional, ≤512 bytes (recommended for denied but not enforced);
//	Decision ∈ {approved, denied, pending};
//	DaHash non-empty must be 64 lowercase hexadecimal characters (sha256 hex);
//	OperationID ≤128, AgentID ≤256, EvidenceRef ≤256 bytes when non-empty;
//	Ts must be non-zero.
func ValidateSupervisionEvent(e *SupervisionEvent) error {
	if e == nil {
		return fmt.Errorf("supervision_event: nil")
	}
	if !e.Type.Valid() {
		return fmt.Errorf("supervision_event: invalid type %q (must be consent/denied/step_up/approval/break_glass/override)", e.Type)
	}
	if e.Source == "" {
		return fmt.Errorf("supervision_event: source is required")
	}
	if len(e.Source) > 64 {
		return fmt.Errorf("supervision_event: source length %d exceeds 64", len(e.Source))
	}
	if e.Actor == "" {
		return fmt.Errorf("supervision_event: actor is required")
	}
	if len(e.Actor) > 128 {
		return fmt.Errorf("supervision_event: actor length %d exceeds 128", len(e.Actor))
	}
	if len(e.Reason) > 512 {
		return fmt.Errorf("supervision_event: reason length %d exceeds 512", len(e.Reason))
	}
	switch e.Decision {
	case SupervisionDecisionApproved, SupervisionDecisionDenied, SupervisionDecisionPending:
	default:
		return fmt.Errorf("supervision_event: invalid decision %q (must be approved/denied/pending)", e.Decision)
	}
	if e.DaHash != "" && !validLowerHex64(e.DaHash) {
		return fmt.Errorf("supervision_event: da_hash must be 64 lowercase hexadecimal characters")
	}
	if len(e.OperationID) > 128 {
		return fmt.Errorf("supervision_event: operation_id length %d exceeds 128", len(e.OperationID))
	}
	if len(e.AgentID) > 256 {
		return fmt.Errorf("supervision_event: agent_id length %d exceeds 256", len(e.AgentID))
	}
	if len(e.EvidenceRef) > 256 {
		return fmt.Errorf("supervision_event: evidence_ref length %d exceeds 256", len(e.EvidenceRef))
	}
	if e.Ts.IsZero() {
		return fmt.Errorf("supervision_event: ts is required (must be non-zero)")
	}
	return nil
}

// validLowerHex64 reports whether s is exactly 64 lowercase hexadecimal
// characters (the canonical sha256 hex text form).
func validLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
