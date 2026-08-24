# types Developer Documentation

## Module Purpose

`types` is the **shared type definition library** for the Varwof PKI suite, providing unified AIC, Capability, Principal, and other core ASN.1 type definitions for `core`, `gateway-core`, and the three gateways.

**Design constraints**: zero external dependencies, pure standard library (including the SM3 pure Go implementation built into types).

## Architecture Overview

```
types (this module)
  │
  ├─ core        — Issue/verify AIC, build DelegationAuthTBS, issue certificates
  ├─ gateway-core — Parse/validate AIC, capability matching, RBAC pipeline
  └─ Three gateways (tcp/http/udp) — Used indirectly via lib
```

Type sharing method: `core` and `gateway-core` reference this module through Go module replace directives, with package alias `pki`.

## File Structure

| File | Responsibility | Key Types/Functions |
|------|------|--------------|
| `aic.go` | AIC core types, parsing, validation, capability matching | `AIC`, `Capability`, `DelegationAuthorization`, `DelegationAuthTBS`, `Reason`, `ParseAIC`, `ValidateAIC`, `MatchCapability` |
| `principal.go` | PrincipalUid construction and parsing | `PrincipalUid`, `ParsePrincipalUid`, `MakePrincipalUidFromCert` |
| `user_permission.go` | PrincipalAuthorization + legacy UserPermission | `PrincipalAuthorization`, `DelegationPolicy`, `ExternalPolicyRef`, `UserPermission` (v1.4 legacy) |
| `oid.go` | OID constant definitions | All `OID*` variables (AIC tree/signing/hashing/extension/national standard/CT) |
| `hash.go` | Hash algorithm utilities | `KeyHashFromSPKI`, `HashOIDName`, `ParseHashAlgo`, `SupportedHashAlgos` |
| `sm3.go` | SM3 national standard hash pure Go implementation (GB/T 32905-2016) | `NewSM3`, `SM3Sum` |
| `gs.go` | GatewaySessionExtension (legacy type, retained for non-AIC use cases) | `GatewaySessionExtension`, `KeyDerivationParams` |
| `match_priority.go` | Five-level priority matching engine | `MatchCapabilityPriority`, `MatchCapabilityRules`, `CapabilityRule` |

## Version Evolution

| Version | Key Changes |
|------|----------|
| v1.4 | Initial `UserPermission` type (with roles) |
| v1.5 | `roles` field removed from PA (now carried by certificate OU); `GatewaySession` moved from AIC standalone extension to `executionConstraints` runtime |
| v1.7.1 | `DelegationAuthorization` required; `Reason` field added (reasonCode + description); `requestedLifetime` required with range 3600-86400; `nonce` required 32 bytes |
| v1.7.2 | `DelegationDepthControl` OID reserved (FUTURE, not currently implemented) |

## ASN.1 Encoding Conventions

- **Tag 0 `[0] EXPLICIT`**: `AuthorizationConstraints`, `KeyDerivation`
- **Tag 1 `[1] EXPLICIT`**: `Extensions` (AIC), `DelegationPolicy` (PA)
- **Tag 2 `[2] EXPLICIT`**: `Extensions` (PA)
- **Default values**: `Version` defaults to 1, `DelegationMode` defaults to 0 (authorized), `MaxAgents` defaults to 1
- **GeneralizedTime**: `DelegationAuthorization.Timestamp` uses ASN.1 GeneralizedTime format

## Capability Matching Engine

### Five-Level Priority

The matching engine (`match_priority.go`) splits capabilityId by `:`, supporting five-level matching priority:

```
Exact match (5) > Single-segment wildcard (4) > Multi-segment wildcard (3) > Scheme wildcard (2) > Global wildcard (1)
```

- **Exact**: `id == pattern`
- **Single-segment wildcard**: same number of segments, each segment is a literal or `*` (e.g. `mysql:SELECT:*`)
- **Multi-segment wildcard**: contains `**` segment, matches one or more segments across boundaries (e.g. `database:**`)
- **Scheme wildcard**: first segment `*`, remaining segments are exact (e.g. `*:query:SELECT`)
- **Global wildcard**: `*`, `**`, or `*:*`

### Decision Rules

`MatchCapabilityRules` makes decisions by priority within a rule set:
1. Takes the highest priority matching rule
2. At the same priority level, **deny overrides allow**
3. When no rules match, returns `Matched=false` (handled by the caller according to default policy)

### Differences from glob

`MatchCapability` (`aic.go`) uses `path.Match` glob semantics (`*` matches any character except `/`), while `MatchCapabilityPriority` (`match_priority.go`) uses `:` delimited structured matching. They apply to different scenarios:
- `MatchCapability`: simple key-value matching (e.g. AIC.HasProtocol / CheckPermission)
- `MatchCapabilityPriority`: policy engine rule evaluation (e.g. allowlist/denylist/rbac plugins)

## Hash Algorithm Support

### Algorithm Tiers

| Tier | Algorithm | Implementation |
|------|------|------|
| Standard library | SHA-256/384/512, SHA3-256/384/512 | `crypto/sha256`, `crypto/sha512`, `crypto/sha3` |
| Built-in pure Go | SM3 (GB/T 32905-2016) | `sm3.go`, zero external dependencies |
| Registered not implemented | BLAKE2/BLAKE3 | `HashAlgoOIDs`/`HashOutputLen` have registered OID and length mappings, but actual computation requires external dependencies |

### SM3 Implementation Notes

SM3 is a national standard hash algorithm (GB/T 32905-2016), producing 32 bytes (256 bits) output with 512-bit message blocks. Implementation highlights:
- 68-word message expansion + 64-round compression
- Padding scheme identical to SHA-256 (0x80 + zero padding to 448 mod 512 + 64-bit big-endian length)
- Verified against standard vectors ("abc"→`66c7f0f4...`) and openssl `dgst -sm3` cross-validation

### keyHash Computation

`keyHash` is the hash digest of the SPKI DER, stored in `PrincipalUid.KeyHash`, used for principal identity binding:
- Default algorithm: SHA-256 (32 bytes)
- Optional algorithm: specified via the `HashAlgoOID` field, supports SM3, etc.
- Validation: `ValidatePrincipalUidKeyHash` validates length by declared algorithm; unsupported algorithms (BLAKE2/BLAKE3) return explicit errors

## Constraint System

### AuthorizationConstraints

Both AIC and PrincipalAuthorization can carry `authorizationConstraints`, reusing the `Capability` container:
- `schemeId` must be `"constraint"` or `"constraint-v1"` (whitelist validation)
- `capabilityId` distinguishes constraint types (e.g. `allowed-cidr`, `time-window`, `max-concurrent`)
- `parameters` is JSON configuration (≤512 bytes)

### max-concurrent Constraint

`ValidateMaxConcurrentParam` validates the `{"max": N}` format, N ∈ [1, 1024].

## Delegation Chain Design (FUTURE)

Multi-level delegation chains (Agent → sub-Agent) are currently **publicly designed but not implemented**:
- Single-level delegation (Principal → Agent) is the only supported path currently
- Even if implemented in the future, the depth limit is `maxDepth = 1`
- OID `DelegationDepthControl` (`.1.1.4`) is reserved
- See `DESIGN-NOTES.md` for details

## Test Strategy

- **Standard vector verification**: SM3 hash verified against GB/T 32905-2016 standard vectors + openssl cross-validation
- **Field boundary testing**: `ValidateAIC` covers positive/negative cases for all constant boundaries
- **Matching engine testing**: five-level priority × deny-overrides-allow rules × empty rule set × boundary cases
- **ASN.1 encode/decode round-trip testing**: AIC/PA/GS structure encode/decode consistency
- **Legacy compatibility testing**: `UserPermission` v1.4 backward-compatible code paths

## Known Limitations

1. **SM3 is limited to use within this module**: other modules call `pki.SM3Sum` / `pki.NewSM3` and do not directly depend on SM3's internal implementation
2. **BLAKE2/BLAKE3 cannot be computed**: OIDs and lengths are registered but no implementation exists; `KeyHashFromSPKI` returns an explicit error when called
3. **DelegationDepthControl is not implemented**: OID is reserved, `ValidateAIC` does not validate this extension
4. **`UserPermission.HasRole` always returns false**: after v1.5, roles are carried by certificate OU
