# types Design Notes: Multi-level Delegation Chain (Design-level Disclosure, Not Currently Implemented)

> Decision record: 2026-08-05 (Plan B of I2)
> Related: `dev-docs/aic/01-asn1.md` §DelegationDepthControl (FUTURE), Patent Claim 12/13, Embodiment 4

## Status

- **Multi-level delegation chain (Agent → sub-Agent) is design-level disclosure**: The specification and patent documents have fully disclosed the recursive verification algorithm, `chainDepth`/`maxDepth` depth control, loop prevention, certificate bomb prevention, CA per-level subset verification and other boundary constraints, but **not currently implemented** (FUTURE).
- **Single-level delegation (Principal → Agent) is the only currently supported path**, with full pipeline implemented and tested:
  - TBS construction/signing: `aic.go`, `core/internal/ca/aic.go` (BuildAIC)
  - Signature verification: `gateway-core/decision.go` VerifyDelegationAuth (ECDSA/RSA/PSS + OID allowlist)
  - SPKI cross-validation: `decision.go` (hashAlgo dispatch)
  - Constraint checking: `decision.go` CheckAuthorizationConstraints
  - Conditional revocation / auto-renewal: `gateway-core/revoker.go`, `shortlived.go`

## Decision Rationale

1. **Legal risk (primary)**: Multi-level delegation chains have complex legal liability attribution — the legal status of intermediate agents, liability for unauthorized actions, and audit actor semantics are all difficult to define, conflicting with Patent 1's core narrative of "accountability traceable to a natural person"; under single-level delegation, the responsibility chain is clear (Principal → Agent), with legal consequences directly attributable to the principal.
2. **Implementation risk**: Recursive verification, cascading revocation propagation, credential bundle size, loop prevention and other implementation complexities are high; the single-level full pipeline is already implemented and tested, serving as a stable baseline.
3. **Patent strategy (Plan B of I2)**: The patent application has disclosed multi-level delegation (Claims 12/13, Embodiment 4); the sufficiency of disclosure does not require "already implemented," only requires "a person skilled in the art can implement it" — the specification has provided the recursive verification algorithm and security constraints; not building a prototype avoids unnecessary implementation exposure at the patent/examination level.

## Future Enablement Path (If Implemented, Depth Limit = 1)

- **Even if implemented in the future, the delegation depth limit is 1**: Only Principal → Agent → sub-Agent is allowed (at most one level below the Agent), i.e., `maxDepth = 1`, `chainDepth ≤ 1`, sub-Agent **must not delegate further**.
- Implementation steps: Implement `DelegationDepthControl` extension (OID `1.3.6.1.4.1.66257.1.1.4`) + gateway recursive signature verification pipeline + CA per-level subset verification; enforce `maxDepth = 1` via CA policy when enabled.

## Points to Clarify During Implementation (FUTURE Implementation Checklist)

1. **Credential bundle size grows linearly with chain length**: Multi-level verification requires the credential bundle to carry the entire delegation chain, chain length N → size ≈ N × single certificate; need to define a chain length limit (`maxDepth` actual deployment recommendation ≤5; per this decision ≤1) or credential bundle size budget.
2. **Under multi-level delegation, `principalUid` semantics become "delegator identifier"**: In single-level delegation it points to the responsible party (natural person), in multi-level it points to the parent Agent; need to clarify audit actor semantics (whether to record the delegation chain or the top-level responsible party) to avoid conflicting with the "accountability traceable to a natural person" narrative.
3. **Cascading revocation propagation rules along the chain**: After revoking a parent (intermediate Agent), whether sub-agents cascade-fail and how propagation works needs explicit definition (the "cascading revocation/principalUid index" approach can be reused).
4. **Loop prevention detection requires full chain visibility**: Offline verification requires the credential bundle to carry the complete delegation chain to detect duplicate signers, tied to point 1 above.

## Specification Locations

- ASN.1: `DelegationDepthControl` (01-asn1.md §DelegationDepthControl, FUTURE)
- Verification rules: 03-validation.md §Delegation Depth Control (Φ1–Φ3, FUTURE)
- Authorization flow: 06-delegation-auth.md §Multi-level Delegation Chain (FUTURE)

> ⚠️ Before adding any "implementation-level" code on this structure, please cross-check against the patent/specification scope first to avoid changing the "design-level disclosure" positioning; if implemented, adhere to this decision's depth limit (`maxDepth = 1`).
