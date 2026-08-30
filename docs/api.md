# types API Reference

> Package: `pki` | Module: `github.com/varwof/types` | Zero external dependencies

## Exported Types

### AIC (Agent Identity Certificate)

X.509v3 extension ASN.1 structure (v1.7.1 spec), the core identity carrier for Agents.

```go
type AIC struct {
    Version                  int                      `asn1:"default:1"`
    AgentId                  string                   `asn1:"utf8"`
    PrincipalUid             PrincipalUid             `asn1:""`
    Capabilities             []Capability             `asn1:"sequence"`
    DelegationMode           DelegationMode           `asn1:"default:0"`
    AuthorizationConstraints []Capability             `asn1:"optional,omitempty,contextspecific,explicit,tag:0"`
    DelegationAuthorization  DelegationAuthorization  `asn1:"optional,omitempty"`
    Extensions               []ExtField               `asn1:"optional,omitempty,contextspecific,explicit,tag:1"`
}
```

**Methods:**

| Method | Signature | Description |
|------|------|------|
| `Principal` | `func (a *AIC) Principal() string` | Returns a human-readable principal identifier (`realm:identifier:fingerprint`) |
| `HasProtocol` | `func (a *AIC) HasProtocol(schemeId string) bool` | Checks whether the specified schemeId capability is held |
| `CheckPermission` | `func (a *AIC) CheckPermission(required string) bool` | Glob-matching check for the specified CapabilityId |
| `IntersectPermissions` | `func (a *AIC) IntersectPermissions(pa *PrincipalAuthorization) []string` | Returns the intersection of AIC capabilities and PA grants |
| `IntersectPermissionsStr` | `func (a *AIC) IntersectPermissionsStr(upPerms []string) []string` | Glob-matching intersection with a given pattern list |
| `IntersectPermissionsStrAny` | `func (a *AIC) IntersectPermissionsStrAny(upPerms string) []string` | Comma/space-separated string version |

### PrincipalUid

Structured principal identity identifier, ASN.1 encoded, with communication format `{realm}:{identifier}:{keyFingerprint}`.

```go
type PrincipalUid struct {
    Version    int                 `asn1:"default:1"`
    Realm      string              `asn1:"utf8"`
    Identifier string              `asn1:"utf8"`
    KeyHash    []byte              `asn1:"octet"`
    HashAlgo   AlgorithmIdentifier `asn1:"optional,omitempty,explicit,tag:0"`
}
```

**Methods:**

| Method | Signature | Description |
|------|------|------|
| `String` | `func (pu PrincipalUid) String() string` | Returns communication format `realm:identifier:base64url(keyHash)` |
| `HashAlgoOID` | `func (pu PrincipalUid) HashAlgoOID() asn1.ObjectIdentifier` | Returns the effective hash algorithm OID (nil/empty defaults to SHA-256) |

### Capability

Protocolized capability container. `schemeId` determines routing (which executor to use), `capabilityId` is the matching subject.

```go
type Capability struct {
    SchemeId     string `json:"scheme_id" asn1:"utf8"`
    CapabilityId string `json:"capability_id" asn1:"utf8"`
    Parameters   []byte `json:"parameters,omitempty" asn1:"optional,omitempty,contextspecific,explicit,tag:0"`
}
```

- `SchemeId`: 1-128 bytes, scheme identifier (e.g. `mysql`, `http`, `constraint`)
- `CapabilityId`: 1-256 bytes, capability identifier (e.g. `SELECT:*`, `GET:/api/users`)
- `Parameters`: 0-4096 bytes, JSON parameters consumed by the executor, not used for matching

### DelegationAuthorization

User authorization cryptographic evidence (v1.7.1 spec §3), required in AIC.

```go
type DelegationAuthorization struct {
    Reason             Reason               `asn1:""`
    RequestedLifetime  int                  `asn1:"default:0"`
    Timestamp          time.Time            `asn1:"generalized"`
    Nonce              []byte               `asn1:"octet"`
    SignatureAlgorithm AlgorithmIdentifier  `asn1:""`
    SignatureValue     []byte               `asn1:"octet"`
}
```

**Methods:**

| Method | Signature | Description |
|------|------|------|
| `IsPresent` | `func (d DelegationAuthorization) IsPresent() bool` | Checks whether it has been actually set (non-zero value) |

### Reason

Delegation authorization reason (v1.7.1 spec §Reason), both fields are required, used only for audit/display, not involved in permission determination.

```go
type Reason struct {
    ReasonCode  string `asn1:"utf8"` // ≤64 bytes
    Description string `asn1:"utf8"` // ≤512 bytes
}
```

### DelegationAuthTBS

To-Be-Signed data for DelegationAuthorization signature.

```go
type DelegationAuthTBS struct {
    Version                  int            `asn1:"default:1"`
    AgentId                  string         `asn1:"utf8"`
    PrincipalUid             PrincipalUid   `asn1:""`
    Reason                   Reason         `asn1:""`
    Capabilities             []Capability   `asn1:"sequence"`
    DelegationMode           DelegationMode `asn1:"default:0"`
    AuthorizationConstraints []Capability   `asn1:"optional,omitempty,contextspecific,explicit,tag:0"`
    RequestedLifetime        int            `asn1:"default:0"`
    Timestamp                time.Time      `asn1:"generalized"`
    Nonce                    []byte         `asn1:"octet"`
}
```

### DelegationMode

```go
type DelegationMode int

const (
    DelegationAuthorized     DelegationMode = 0 // Authorized-only mode
    DelegationRepresentative DelegationMode = 1 // Representative mode
)
```

### AlgorithmIdentifier

ASN.1 algorithm identifier.

```go
type AlgorithmIdentifier struct {
    Algorithm  asn1.ObjectIdentifier
    Parameters asn1.RawValue `asn1:"optional"`
}
```

### ExtField

A single extension field in the AIC extension slot.

```go
type ExtField struct {
    ExtnID    asn1.ObjectIdentifier `asn1:"objectidentifier"`
    Critical  bool                   `asn1:"default:false"`
    ExtnValue []byte                 `asn1:"octet"`
}
```

### PrincipalAuthorization (User Authorization)

v1.7.1 user authorization structure, carried via certificate extension OID `.1.2`.

```go
type PrincipalAuthorization struct {
    Version                  int                `asn1:"default:1"`
    Grants                   []Capability       `asn1:"optional,omitempty"`
    AuthorizationConstraints []Capability       `asn1:"optional,omitempty,contextspecific,explicit,tag:0"`
    DelegationPolicy         DelegationPolicy   `asn1:"optional,explicit,tag:1"`
    Extensions               []ExtField         `asn1:"optional,omitempty,contextspecific,explicit,tag:2"`
}
```

**Methods:**

| Method | Signature | Description |
|------|------|------|
| `GrantIds` | `func (pa *PrincipalAuthorization) GrantIds() []string` | Flattens all Grants' CapabilityId values |
| `HasRole` | `func (pa *PrincipalAuthorization) HasRole(role string) bool` | Always returns false after v1.5 (roles now carried by certificate OU) |
| `AllowsRepresentative` | `func (pa *PrincipalAuthorization) AllowsRepresentative() bool` | Checks whether representative delegation mode is allowed |

### DelegationPolicy

Delegation policy control.

```go
type DelegationPolicy struct {
    Version         int  `asn1:"default:1"`
    MaxAgents       int  `asn1:"default:1"`          // 0-255
    AllowedMode     int  `asn1:"enum,default:0"`      // 0=authorizedOnly, 1=representativeAllowed
    MaxSessionHours int  `asn1:"optional,omitempty,explicit,tag:0"` // 0=absent
}
```

### ExternalPolicyRef

External policy system reference.

```go
type ExternalPolicyRef struct {
    RefType   string `asn1:"utf8"`
    RefUrl    string `asn1:"utf8"`
    RefDigest []byte `asn1:"optional,omitempty"`
}
```

### GatewaySessionExtension

Gateway session extension (OID `.1.5`), a pre-v1.5 legacy structure, retained as a runtime type for non-AIC use cases.

```go
type GatewaySessionExtension struct {
    Version       int                   `asn1:"default:1"`
    MaxConcurrent int                   `asn1:"optional,omitempty"`
    HardTimeout   int                   `asn1:"optional,omitempty"`
    AllowedCIDRs  []string              `asn1:"optional,omitempty"`
    MaxRetries    int                   `asn1:"optional,omitempty"`
    KeyDerivation []KeyDerivationParams `asn1:"optional,explicit,tag:0"`
}
```

**Methods:**

| Method | Signature | Description |
|------|------|------|
| `MaxConcurrentLimit` | `func (g *GatewaySessionExtension) MaxConcurrentLimit() int` | Maximum concurrent connections |
| `HardTimeoutLimit` | `func (g *GatewaySessionExtension) HardTimeoutLimit() int` | Session hard timeout (seconds) |
| `CIDRAllowed` | `func (g *GatewaySessionExtension) CIDRAllowed(ip string) bool` | Whether the IP is within the allowed CIDR range (empty list = no restriction) |
| `MaxRetriesLimit` | `func (g *GatewaySessionExtension) MaxRetriesLimit() int` | Maximum retry count |
| `ValidateKeyDerivation` | `func (g *GatewaySessionExtension) ValidateKeyDerivation() error` | Validates KDF salt length (16-32 bytes) |

### KeyDerivationParams

Session key derivation parameters.

```go
type KeyDerivationParams struct {
    KDFAlgorithm asn1.ObjectIdentifier `asn1:"objectidentifier"`
    KeyLength    int                    `asn1:"default:32"`
    Salt         []byte                 `asn1:"octet"`
    Info         string                 `asn1:"utf8,optional"`
}
```

### CapabilityRule / CapabilityRuleMatch

Action-bearing matching rules, used for "deny overrides allow" decision-making.

```go
type CapabilityRule struct {
    Pattern string // Matching pattern (supports five-level wildcards)
    Deny    bool   // true=deny rule, false=allow rule
}

type CapabilityRuleMatch struct {
    Matched  bool   // Whether a matching rule exists
    Deny     bool   // Whether it is a deny rule (deny overrides allow)
    Priority int    // Highest matched priority level
    Pattern  string // Matched rule pattern
}
```

### Legacy Types (v1.4 Backward Compatibility)

```go
type UserPermission struct { ... }    // v1.4 legacy user permission
type PermissionLevel int              // PermissionAuto / PermissionRequiresApproval
type PermissionDef struct { ... }     // Permission definition
type RoleDef struct { ... }           // Role definition
type ResourceScope struct { ... }     // Resource scope
```

> **Note**: `UserPermission` is a v1.4 legacy type; new code should use `PrincipalAuthorization`. `HasRole` always returns false after v1.5.

## Exported Functions

### Parsing and Construction

| Function | Signature | Description |
|------|------|------|
| `ParseAIC` | `func ParseAIC(cert *x509.Certificate) (*AIC, error)` | Parses the AIC extension from a certificate (returns nil, nil if not found) |
| `ParsePrincipalUid` | `func ParsePrincipalUid(s string) (PrincipalUid, error)` | Parses PrincipalUid from a communication format string |
| `MakePrincipalUidFromCert` | `func MakePrincipalUidFromCert(realm, identifier string, cert *x509.Certificate) PrincipalUid` | Constructs PrincipalUid from a certificate (SHA-256) |
| `MakePrincipalUidFromCertWithAlgo` | `func MakePrincipalUidFromCertWithAlgo(realm, identifier string, cert *x509.Certificate, algo asn1.ObjectIdentifier) (PrincipalUid, error)` | Constructs PrincipalUid with a specified hash algorithm |
| `ParseUserPermissionExtension` | `func ParseUserPermissionExtension(cert *x509.Certificate) (*PrincipalAuthorization, error)` | Parses the PrincipalAuthorization extension from a certificate |
| `ParseGatewaySessionExtension` | `func ParseGatewaySessionExtension(cert *x509.Certificate) (*GatewaySessionExtension, error)` | Parses the GatewaySession extension from a certificate |

### Validation

| Function | Signature | Description |
|------|------|------|
| `ValidateAIC` | `func ValidateAIC(aic *AIC) error` | Validates all AIC field constraints (v1.7.1) |
| `ValidatePrincipalAuthorization` | `func ValidatePrincipalAuthorization(pa *PrincipalAuthorization) error` | Validates PrincipalAuthorization field constraints |
| `ValidatePrincipalUidKeyHash` | `func ValidatePrincipalUidKeyHash(pu PrincipalUid) error` | Validates that keyHash length matches the declared hash algorithm |
| `ValidateMaxConcurrentParam` | `func ValidateMaxConcurrentParam(raw []byte) error` | Validates the max-concurrent constraint parameter |

### Capability Matching

| Function | Signature | Description |
|------|------|------|
| `MatchCapability` | `func MatchCapability(id, pattern string) bool` | Glob wildcard matching (supports `*`/`?`/`**`) |
| `MatchCapabilityPriority` | `func MatchCapabilityPriority(id, pattern string) int` | Returns the matched priority level (0-5) |
| `MatchCapabilityRules` | `func MatchCapabilityRules(id string, rules []CapabilityRule) CapabilityRuleMatch` | Rule set decision (deny overrides allow) |
| `MatchCapabilityPriorityString` | `func MatchCapabilityPriorityString(p int) string` | Human-readable name for the priority level |

### Hash Algorithms

| Function | Signature | Description |
|------|------|------|
| `KeyHashFromSPKI` | `func KeyHashFromSPKI(algo asn1.ObjectIdentifier, spkiDER []byte) ([]byte, error)` | Computes SPKI DER digest by algorithm OID |
| `KeyHashFromCertSPKI` | `func KeyHashFromCertSPKI(algo asn1.ObjectIdentifier, cert *x509.Certificate) ([]byte, error)` | Computes keyHash from certificate public key |
| `HashOIDName` | `func HashOIDName(oid asn1.ObjectIdentifier) string` | OID → algorithm name (returns empty string if unknown) |
| `ParseHashAlgo` | `func ParseHashAlgo(s string) (asn1.ObjectIdentifier, error)` | String → algorithm OID |
| `DefaultHashAlgo` | `func DefaultHashAlgo() asn1.ObjectIdentifier` | Returns the SHA-256 OID |
| `SupportedHashAlgos` | `func SupportedHashAlgos() []string` | Returns the list of computable algorithm names |
| `SigAlgoToOID` | `func SigAlgoToOID(algo x509.SignatureAlgorithm) AlgorithmIdentifier` | x509 signature algorithm → AlgorithmIdentifier |

### SM3 National Standard Hash

| Function | Signature | Description |
|------|------|------|
| `NewSM3` | `func NewSM3() hash.Hash` | Returns an SM3 hash.Hash instance (GB/T 32905-2016) |
| `SM3Sum` | `func SM3Sum(data []byte) [32]byte` | Convenience function that returns the SM3 digest |

## OID Constants

### AIC Tree

| Variable | OID | Description |
|------|-----|------|
| `OIDAIC` | `1.3.6.1.4.1.66257.1.1` | AIC root |
| `OIDAICAgentIdentity` | `1.3.6.1.4.1.66257.1.1.1` | Agent identity |
| `OIDAICDelegationAuthorization` | `1.3.6.1.4.1.66257.1.1.2` | Delegation authorization signature |
| `OIDDelegationDepthControl` | `1.3.6.1.4.1.66257.1.1.4` | Delegation depth control (FUTURE) |
| `OIDDDCChainDepth` | `1.3.6.1.4.1.66257.1.1.4.1` | chainDepth |
| `OIDDDCMaxDepth` | `1.3.6.1.4.1.66257.1.1.4.2` | maxDepth |

### Signature Algorithms

| Variable | Algorithm |
|------|------|
| `OIDSigECDSAWithSHA256/384/512` | ECDSA + SHA-2 |
| `OIDSigRSAWithSHA256/384/512` | RSA + SHA-2 |
| `OIDSigRSAPSSWithSHA256` | RSA-PSS + SHA-256 |
| `OIDSigEd25519` | Ed25519 |

### Hash Algorithms

| Variable | OID |
|------|-----|
| `OIDSHA256` | `2.16.840.1.101.3.4.2.1` |
| `OIDSHA384` | `2.16.840.1.101.3.4.2.2` |
| `OIDSHA512` | `2.16.840.1.101.3.4.2.3` |

### Extension OIDs

| Variable | OID | Description |
|------|-----|------|
| `OIDPrincipalAuthorization` | `1.3.6.1.4.1.66257.1.2` | Principal authorization |
| `OIDCapabilitySchemeRegistry` | `1.3.6.1.4.1.66257.1.3` | Capability scheme registry (reserved) |
| `OIDVendorExtensionRegistry` | `1.3.6.1.4.1.66257.1.4` | Vendor extension registry (reserved) |
| `OIDRenewalToken` | `1.3.6.1.4.1.66257.1.6` | Renewal token |

### National Standard / Certification Extensions / Certificate Transparency

| Variable | Description |
|------|------|
| `OIDSM2Sig` / `OIDSM3Hash` / `OIDSM4Enc` / `OIDSM2SM3Sig` | GM algorithms |
| `OIDMarketAccessId` / `OIDTrustLevel` / `OIDCrossBorder` | Certification extensions |
| `OIDCTSCT` / `OIDCTLog` | Certificate transparency |

## Hash Algorithm Mapping

### HashAlgoOIDs

Algorithm name → OID mapping table:

| Name | Output Length |
|------|----------|
| `sha256` | 32 bytes |
| `sha384` | 48 bytes |
| `sha512` | 64 bytes |
| `sha3-256` | 32 bytes |
| `sha3-384` | 48 bytes |
| `sha3-512` | 64 bytes |
| `sm3` | 32 bytes |

### HashOutputLen

Algorithm name → output byte length mapping table (same as above).

## Constants

### Certificate Size and Structure Limits

| Constant | Value | Description |
|------|-----|------|
| `MaxCapabilities` | 256 | Maximum number of AIC.capabilities entries |
| `MaxAuthorizationConstraints` | 8 | Default recommended limit for authorization constraint count |
| `MaxExtensionsSlots` | 32 | Maximum capacity of AIC.extensions slots |
| `MaxGrantEntries` | 256 | Maximum number of PrincipalAuthorization.grants entries |
| `MaxConstraintParams` | 512 | Maximum bytes per constraint parameters |
| `MaxCapParams` | 4096 | Maximum bytes per Capability parameters |
| `MaxNonceLen` | 32 | Fixed length of DelegationAuthorization.nonce |
| `MaxRequestedLifetime` | 86400 | Upper bound for requestedLifetime (seconds, 24h) |
| `MinRequestedLifetime` | 3600 | Recommended lower bound for requestedLifetime (seconds, 1h) |
| `MaxRecommendedCertDERSize` | 12288 | Recommended upper bound for AIC certificate DER (12KB) |
| `MaxHardCertDERSize` | 16384 | Hard reject upper bound for AIC certificate DER (16KB) |
| `MaxConcurrentMin` | 1 | Minimum value for max-concurrent constraint |
| `MaxConcurrentMax` | 1024 | Maximum value for max-concurrent constraint |
| `ConstraintConcurrentKey` | `"max-concurrent"` | capabilityId for the max-concurrent constraint |

### Match Priority

| Constant | Value | Description |
|------|-----|------|
| `MatchPriorityNoMatch` | 0 | No match |
| `MatchPriorityGlobal` | 1 | Global wildcard (`*`/`**`/`*:*`) |
| `MatchPriorityScheme` | 2 | Scheme wildcard (`*:query:SELECT`) |
| `MatchPriorityMulti` | 3 | Multi-segment wildcard (containing `**`) |
| `MatchPrioritySingle` | 4 | Single-segment wildcard (`*` matches one segment) |
| `MatchPriorityExact` | 5 | Exact match |

## Error Handling

All validation functions return `error`; parsing functions return `(nil, nil)` when the extension is not found. Main error scenarios:

- `ParseAIC`: AIC extension exists but DelegationAuthorization is empty
- `ValidateAIC`: field length out of bounds, Capability count exceeded, constraint scheme appears in capabilities, extensions contain unknown critical OID, keyHash length doesn't match declared algorithm, requestedLifetime out of bounds
- `ValidatePrincipalAuthorization`: grants count exceeded, capability field length out of bounds, constraint schemeId not in whitelist, DelegationPolicy values out of bounds
- `ValidatePrincipalUidKeyHash`: keyHash is empty, hashAlgo unsupported, keyHash length doesn't match algorithm output
- `MatchCapability` / `MatchCapabilityPriority`: do not return error; return false / 0 when no match

## Usage Examples

```go
package main

import (
    "crypto/x509"
    "fmt"
    pki "github.com/varwof/types"
)

func inspectAIC(cert *x509.Certificate) error {
    aic, err := pki.ParseAIC(cert)
    if err != nil {
        return fmt.Errorf("parse AIC: %w", err)
    }
    if aic == nil {
        fmt.Println("Certificate does not contain AIC extension")
        return nil
    }

    // Validation
    if err := pki.ValidateAIC(aic); err != nil {
        return fmt.Errorf("validate AIC: %w", err)
    }

    fmt.Printf("Agent: %s\n", aic.AgentId)
    fmt.Printf("Principal: %s\n", aic.Principal())

    // Capability check
    if aic.HasProtocol("mysql") {
        fmt.Println("Holds mysql protocol capability")
    }
    if aic.CheckPermission("SELECT:*") {
        fmt.Println("Holds SELECT wildcard permission")
    }

    // Priority matching
    rules := []pki.CapabilityRule{
        {Pattern: "mysql:DROP:*", Deny: true},
        {Pattern: "mysql:*", Deny: false},
    }
    result := pki.MatchCapabilityRules("mysql:SELECT:users", rules)
    if result.Matched && !result.Deny {
        fmt.Printf("Allowed (matched %s, priority %d)\n",
            result.Pattern, result.Priority)
    }

    return nil
}
```

```go
// PrincipalUid construction and parsing
uid := pki.MakePrincipalUidFromCert("acme", "alice", cert)
fmt.Println(uid.String()) // acme:alice:base64url(keyHash)

parsed, err := pki.ParsePrincipalUid("acme:alice:abc123")
if err != nil {
    log.Fatal(err)
}

// SM3 national standard hash
digest := pki.SM3Sum([]byte("hello"))
fmt.Printf("SM3: %x\n", digest)
```
