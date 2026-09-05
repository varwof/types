# AIC-JWT: JSON Web Token Profile for AI Agent Identity Certificates

**Title**: AI Agent Identity Certificate (AIC) JSON Web Token Profile

**Abbreviation**: AIC-JWT

**Document name**: draft-wei-aic-jwt-01

**Category**: Experimental

**Submission type**: Independent

**Author**: Jijie Wei (Individual), pki@varwof.com, https://varwof.com

**IPR**: trust200902

---

# Abstract

This document defines the JSON Web Token (JWT) profile of the AI Agent
Identity Certificate (AIC), a companion specification to
[AIC].  The AIC X.509 extension binds an AI
Agent's cryptographic identity to a responsible principal, carries a
structured capability container, authorization boundary constraints,
delegation mode, and principal-signed delegation evidence, and enables
fully offline authorization decisions at the TLS layer.

AIC-JWT encodes the same data model as an application-layer JWT so that
the same authorization semantics can be enforced by HTTP APIs, web
applications, and OAuth 2.0 ecosystems where transport-layer
certificate presentation is not available.  The specification defines:

* a nested JWS structure that preserves the two-layer signature model
  of AIC -- a principal-signed DelegationAuthorization (DA) JWT
  embedded in and covered by an issuer-signed outer JWT;
* a namespaced `aic` claim carrying agent identity, principal binding,
  structured capabilities, delegation mode, and authorization
  constraints;
* principal binding by SPKI hash or JWK thumbprint, with optional
  credential bundle presentation in PKI deployments;
* issuance flows for both PKI-based CAs and OAuth 2.0 authorization
  servers, including [RFC7523] assertion exchange and [RFC8693] token
  exchange;
* validation rules, IANA registrations, and security considerations
  aligned with the OAuth 2.0 and JOSE specifications.

---

# 1. Introduction

## 1.1. Problem Statement

The AIC X.509 extension defined in [AIC]
answers five questions at TLS handshake time: who delegated the
authorization, which operations were authorized, under which
constraints the Agent may run, how long the authorization is valid, and
who is accountable for the Agent's actions.  Its design goal is that
the complete authorization decision can be made offline, from the
certificate and its credential bundle alone.

Many deployment contexts cannot present X.509 certificates at the
transport layer:

* third-party APIs and web applications consume HTTP Authorization
  headers rather than mTLS client certificates;
* web and mobile clients cannot manage client certificates;
* OAuth 2.0 [RFC6749] ecosystems use bearer tokens and token exchanges;
* serverless and managed gateways terminate TLS on behalf of the
  application.

In these contexts the AIC data model must be carried in an
application-layer token.  This document defines that token as a JWT
[RFC7519] secured by JWS [RFC7515], and names it **AIC-JWT**.

## 1.2. Relationship to the X.509 AIC Extension

AIC-JWT is a companion profile, not a replacement.  The X.509 AIC
extension remains the transport-layer profile used during TLS
handshakes in managed, regulated, and air-gapped environments.  AIC-JWT
carries the same semantic model at the application layer:

| Concern | X.509 AIC (transport) | AIC-JWT (application) |
|---------|------------------------|------------------------|
| Encoding | ASN.1/DER | JSON (JWT claims) |
| Signature framework | X.509 / [RFC5280] | JWS / RFC 7515 |
| Principal signature | DelegationAuthorization | Inner DA JWT (`typ=aic+da+jwt`) |
| Issuer coverage | CA signature over TBSCertificate | Outer JWT signature over the full payload |
| Key binding | X.509 subject public key | `cnf` claim (RFC 7800) |
| Revocation | CRL / OCSP / short lifetime | Token Status List / short lifetime |
| Trust bootstrap | Certificate chain | JWKS / `x5c` / credential bundle |
| Transport | TLS handshake (mTLS) | HTTP Authorization header |

The two profiles share: `agentId`, `principalUid`, the Capability
container (`schemeId`/`capabilityId`/`parameters`), `delegationMode`,
`authorizationConstraints`, the DelegationAuthorization structure, the
permission intersection model, capability glob matching, and the
credential bundle verification model.

## 1.3. Scope

The following sections are normative: token structure, claims
definition, DA JWT definition, issuance flows, validation pipeline,
credential bundle requirements, and IANA registrations.  Deployment
models, implementation status, and performance characteristics are
informative.

As in the X.509 AIC specification, this document deliberately separates
cryptographic delegation from authorization semantics: AIC-JWT defines
the representation and cryptographic binding of authorization-related
information.  Whether an operation is permitted is determined by
capability schemes and deployment policy, not by this specification.

## 1.4. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
capitals, as shown here.

## 1.5. Terminology

This document uses the terms defined in [AIC]
(AIC, Agent, Principal, Delegation Mode, Capability, Capability Scheme,
Credential Bundle, DelegationAuthorization, DelegationAuthTBS,
PrincipalAuthorization, authorizationConstraints, SPKI, PEN).  In
addition:

AIC-JWT:
: The outer JWT defined by this specification (`typ=aic+jwt`), signed by
  a CA or an OAuth authorization server.

DA JWT:
: The inner JWT (`typ=aic+da+jwt`) signed by the principal, the JSON
  equivalent of DelegationAuthorization / DelegationAuthTBS.

PA JWT:
: An optional companion JWT (`typ=aic+pa+jwt`) carrying the JSON
  equivalent of the PrincipalAuthorization extension.

Issuer:
: The entity that signs the outer AIC-JWT.  It is either a CA (PKI
  mode) or an OAuth authorization server (AS mode).

Audit actor vs. OAuth actor:
: The audit actor recorded per Section 8.1 is the principal in
  `representative` mode (the agent is the executor).  This is distinct
  from the RFC 8693 `act` claim (Section 5.1.1), which names the
  executing agent on tokens whose `sub` is the resource owner.

## 1.6. Related Work

[DAAP] (`draft-mishra-oauth-agent-grants`) defines a delegated agent
authorization protocol with DID-based agent identity, JWT grant tokens,
and online verification.  AIC-JWT differs in that identity is anchored
to a PKI/AS trust root, and the principal's consent is a nested
principal-signed JWT covered by the issuer signature.  Principal key
resolution is online by default (JWKS) or, in PKI deployments, via the
optional credential bundle.

[OBO] (`draft-oauth-ai-agents-on-behalf-of-user`) extends OAuth 2.0
flows with `requested_actor` and `actor_token` parameters.  AIC-JWT is a
token format that can be produced by such flows.

[WIMSE] (`draft-ietf-wimse-s2s-protocol`) defines workload identity
tokens carrying `iss`, `sub`, `exp`, `jti`, and `cnf`.  WIMSE tokens
identify workloads but do not carry authorization semantics; AIC-JWT
adds the AIC authorization model on top of the same JOSE primitives.

[ATN], [PEDIGREE], and [HDP] carry delegation information in
application-layer JWS/DID documents but rely on online discovery or
flat scope representations.  AIC-JWT keeps the structured capability
container, the nested principal signature, and authorization
constraints of AIC.

---

# 2. Design Principles

This specification is guided by five orthogonal principles, carried
over from the X.509 AIC specification:

1. **Two-layer signature nesting.**  The principal signs the DA JWT;
   the issuer signs the outer AIC-JWT covering the complete payload
   including the DA JWT.  Neither party can modify the authorization
   content unilaterally.  A compromised CA/AS cannot forge a
   principal-signed DA; a compromised principal key cannot mint a
   valid outer token.

2. **One container, three contexts.**  The Capability structure
   (`schemeId`/`capabilityId`/`parameters`) is reused in
   `aic.capabilities`, `aic.constraints`, and `grants` of the PA JWT.
   Gateways route evaluation by `schemeId` to scheme-specific plugins;
   the certificate format stays frozen while semantics evolve through
   registries.

3. **Online-first, OAuth-native verification.**  Verification follows
   standard OAuth/JOSE practice: issuer keys come from JWKS (optionally
   cached), token status from Token Status Lists [TSL], and sender binding
   from `cnf`/DPoP.  Offline self-contained verification is NOT a
   design goal of the JSON profile; it is the domain of the X.509 AIC
   (mTLS) profile.

4. **Delegation mode as a cryptographically bound field.**
   `delegation_mode` distinguishes `authorized` (agent acts in its own
   name) from `representative` (agent acts in the principal's name),
   with different runtime checks and audit semantics, exactly as in
   the X.509 profile.

5. **OAuth alignment.**  Standard JOSE and OAuth primitives are reused
   wherever possible: `iss`/`sub`/`aud`/`iat`/`exp`/`jti` claims,
   `cnf` (RFC 7800), DPoP (RFC 9449), Rich Authorization Requests
   (RFC 9396), token exchange [RFC8693], JWT assertions [RFC7523],
   and Token Status Lists [TSL].

---

# 3. Overview

## 3.1. Token Roles and Trust Model

The AIC-JWT trust model has four roles:

* **Principal**: the natural person or organization that signs the DA
  JWT.  The principal's public key is identified by
  `aic.principal.key_hash`.  In `representative` mode the principal is
  the resource owner and is the subject (`sub`) of the DA and of the
  issued token; a deployment whose accountable operator differs from
  the resource owner MUST represent that operator separately and MUST
  NOT place it in the grant subject (Section 10.2).
* **Agent**: the AI agent presenting the token.  The agent key is
  bound by `cnf`.  In `representative` mode the agent is the OAuth
  actor/client (`act` / `client_id`), not the subject; in `authorized`
  mode the agent MAY be the subject (`sub`) as the authorized accessor
  (RFC 7523 Section 3, item 2A).
* **Issuer**: the CA (PKI mode) or OAuth authorization server (AS
  mode) that validates the DA JWT and signs the outer AIC-JWT.
* **Verifier/Gateway**: the policy enforcement point that validates
  the token and makes the access decision.

The issuer's public key comes from configured JWKS/`x5c` material
(optionally cached).  The principal's public key comes either from an
online JWKS or, in PKI deployments, from the credential bundle
presented with the token.

## 3.2. Relationship to OAuth 2.0 Roles

| AIC-JWT role | OAuth 2.0 role |
|--------------|----------------|
| Principal | Resource Owner / subject |
| Agent | Client / actor |
| Issuer (AS mode) | Authorization Server |
| Verifier/Gateway | Resource Server |

Role placement is mode-dependent.  In `representative` mode the
resource owner / principal is the subject (`sub`) of the DA and of the
issued token and the agent is the RFC 8693 actor (`act`) / OAuth
client; in `authorized` mode the agent occupies `sub` as the
authorized accessor (RFC 7523 Section 3, item 2A), with the principal
as the signing issuer.  The AIC-JWT can serve as an access token
(RFC 9068-style), an assertion [RFC7523], or the output of a token
exchange [RFC8693].

The OAuth `act` claim names the executing agent; it is distinct from
the audit actor of Section 8.1 (the principal, in `representative`
mode).

## 3.3. Relationship to mTLS

AIC-JWT does not require mutual TLS (mTLS).  Sender binding is provided
at the application layer by the `cnf` claim (Section 5.1.1) and MAY be
strengthened with DPoP [RFC9449].  Where a deployment uses mTLS, the
verifier MAY additionally check that the mTLS client certificate key
corresponds to `cnf` (for example, by comparing the JWK thumbprint of
the certificate public key with the `jkt` member).  Whether and how
mTLS is deployed is a deployment decision and outside the scope of this
specification; in particular, offline handshake-time decisions remain
the domain of the X.509 AIC (mTLS) profile.

---

# 4. Token Structure

## 4.1. Nested JWS Construction

The AIC-JWT is a nested JWS per Section 5.2 of [RFC7515]:

1. The principal creates the DA JWT (Section 5.2) and signs it with the
   principal's private key.
2. The agent or issuer constructs the outer payload (Section 5.1)
   containing the `da` claim whose value is the complete DA JWT
   string.
3. The issuer signs the outer payload, producing the AIC-JWT.

The outer signature covers the complete inner JWT string.  Any
modification of the inner token invalidates the outer signature.

The AIC-JWT uses the JWS compact serialization.  The inner DA JWT uses
the JWS compact serialization as well.

## 4.2. Outer JOSE Header

The outer header MUST contain:

* `alg`: a JOSE algorithm from the allowlist in Section 4.5.  The value
  `none` MUST NOT be used.
* `typ`: the string `aic+jwt`.
* `kid`: the identifier of the issuer's signing key, per [RFC7515]
  Section 4.1.4.

The outer header SHOULD contain `x5c` or `x5t` when the issuer's key is
an X.509 certificate (PKI mode), to bridge X.509 trust anchors.

## 4.3. Inner DA JOSE Header

The DA JWT header MUST contain:

* `alg`: a JOSE algorithm from the allowlist in Section 4.5.
* `typ`: the string `aic+da+jwt`.
* `kid`: the identifier of the principal's signing key.

The DA JWT MUST NOT be accepted as a standalone access token; the
distinct `typ` value prevents confusion with the outer token.

## 4.4. PA JOSE Header

When the optional PA JWT (Section 5.4) is used, its header MUST
contain:

* `alg`: a JOSE algorithm from the allowlist in Section 4.5.
* `typ`: the string `aic+pa+jwt`.
* `kid`: the issuer's signing key identifier.

## 4.5. Algorithm Allowlist

The following JOSE algorithms are permitted, mirroring the signature
algorithm policy of the X.509 AIC specification:

| JOSE `alg` | Requirement | X.509 counterpart |
|------------|-------------|-------------------|
| `ES256` | MUST | ecdsa-with-SHA256 |
| `ES384` | MAY | ecdsa-with-SHA384 |
| `ES512` | MAY | ecdsa-with-SHA512 |
| `RS256` | MUST | sha256WithRSAEncryption |
| `RS384` | MAY | sha384WithRSAEncryption |
| `RS512` | MAY | sha512WithRSAEncryption |
| `PS256` | MAY | RSASSA-PSS with SHA-256 |
| `PS384` | MAY | RSASSA-PSS with SHA-384 |
| `PS512` | MAY | RSASSA-PSS with SHA-512 |
| `EdDSA` (Ed25519) | MAY | Ed25519 |

The allowlist is the union of the SPIFFE JWT-SVID algorithm set
([RFC7518] Sections 3.3-3.5) and EdDSA, so that a token can be
verified by both JWT-SVID and AIC-JWT validators.  ES256 and RS256 are
the common MUST-level core shared with RFC 9068 and JWT-SVID;
interoperable deployments SHOULD use ES256 or RS256.

Implementations MUST reject all other algorithms.  Implementations
MUST follow the JSON Web Algorithm Confusion prevention guidance of
[RFC8725]: the `alg` header MUST be validated against the allowlist,
the `kid` MUST be resolved to the expected key, and symmetric
algorithms such as `HS256` MUST NOT be accepted for AIC-JWT.

---

# 5. Claims

## 5.1. Outer Claims

The outer payload is a JSON object.  AIC-specific claims are carried
inside the namespaced `aic` claim to avoid collisions with registered
JWT and OAuth claims.

### 5.1.1. Standard Claims

* `iss` (REQUIRED): the issuer identifier, a URL per [RFC9068] and
  [RFC9207].
* `sub` (REQUIRED): mode-dependent.  In `authorized` mode it is the
  `agentId`; the agent is the authorized accessor (RFC 7523 Section 3,
  item 2A).  In `representative` mode it is the resource owner /
  principal identifier (`realm:id`), matching the DA `sub`, and the
  agent appears in the `act` member below.  The agent is always bound
  to the token by `cnf`.  SPIFFE JWT-SVID projections (Section 18)
  replace `sub` with the SPIFFE ID for that projection only.
  In OAuth deployments the AS MAY require `sub` to be the subject
  identifier it registers for the resource owner; the `realm:id` form
  is this profile's canonical default and MUST be resolvable to that
  account.
* `act` (OPTIONAL): present in `representative` mode only, an object
  with a `sub` member equal to the `agentId` (RFC 8693 actor).  MUST
  be absent in `authorized` mode.
* `aud` (REQUIRED): a string or array of strings identifying the
  intended resource servers or gateways.  Verification follows RFC 9068
  Section 4.  Deployments that base decisions solely on capability
  evaluation MUST still include a deployment-scoped audience to prevent
  audience confusion.
* `iat` (REQUIRED): NumericDate of issuance.
* `exp` (REQUIRED): NumericDate of expiry.  The lifetime
  `exp - iat` MUST NOT exceed the DA's `requested_lifetime`, which MUST
  NOT exceed 86400 seconds (1 day).  Where a DA JWT is present, the
  outer `exp` MUST NOT exceed the DA `exp` (`ts + requested_lifetime`),
  so that an issued token never outlives the principal-signed grant;
  where the `da` claim is absent (Section 10.3), the lifetime is
  bounded by issuer policy instead.
* `nbf` (OPTIONAL): NumericDate before which the token MUST NOT be
  accepted.
* `jti` (REQUIRED): a unique token identifier used for replay
  prevention and status lists.  When a DA JWT is present, `jti` MUST
  equal the DA `nonce` (carried in the DA as `jti`).
* `cnf` (REQUIRED): a confirmation claim per [RFC7800] binding the
  token to the Agent's proof-of-possession key.  The `jkt` member
  ([RFC7638] thumbprint) is RECOMMENDED.  When DPoP [RFC9449] is used,
  the `jkt` member MUST match the DPoP proof key thumbprint.  Where a
  deployment uses mTLS, the verifier MAY cross-check the mTLS client
  certificate key against `cnf` (Section 3.3).
* `scope` (OPTIONAL): an OAuth scope string projection of the
  capabilities, for interoperability with generic OAuth resource
  servers.  The `aic.capabilities` claim remains the canonical
  authorization input.
* `client_id` (OPTIONAL): the OAuth client identifier in AS mode,
  per RFC 9068.
* `status` (OPTIONAL): a Token Status List reference per
  [TSL], with `idx` and `uri` members.
* `authorization_details` (OPTIONAL): a Rich Authorization Requests
  [RFC9396] projection of `aic.capabilities`, for consumption by
  standard OAuth resource servers.

### 5.1.2. The `aic` Claim

The `aic` claim (REQUIRED) is a JSON object:

```
"aic": {
  "ver": 1,
  "principal": {
    "realm": "corp.com",
    "id": "zhangsan",
    "key_hash": "<base64url of SPKI hash>",
    "hash_alg": "sha-256"
  },
  "delegation_mode": "authorized" | "representative",
  "capabilities": [ ... ],
  "constraints": [ ... ],
  "chain_depth": 0,
  "max_depth": 1,
  "extensions": { ... }
}
```

* `ver` (REQUIRED): AIC-JWT profile version, currently 1.
* `principal` (REQUIRED): the principal binding, with members:
  * `realm` (REQUIRED): globally unique namespace, 1 to 128 characters;
  * `id` (REQUIRED): identifier within the realm, 1 to 256 characters,
    MUST NOT contain raw PII (see Section 14);
  * `key_hash` (REQUIRED): the principal binding hash, either
    (a) the base64url [RFC4648] encoding of `hash_alg(SPKI)` where SPKI is the
    DER SubjectPublicKeyInfo of the principal's X.509 certificate, or
    (b) the [RFC7638] JWK thumbprint (`jkt`) of the principal's JWK in
    pure-JSON deployments.  The `hash_alg` member disambiguates.
  * `hash_alg` (REQUIRED when `key_hash` is an SPKI hash): the hash
    algorithm name (e.g., `sha-256`, `sha-384`, `sha-512`, `sha3-256`,
    `sm3`) or its ASN.1 OID string.  When the key is a JWK thumbprint,
    `hash_alg` MUST be `"jkt"`.
* `delegation_mode` (REQUIRED): `"authorized"` (default) or
  `"representative"`.
* `capabilities` (REQUIRED, 1 to 256 entries): the Agent's declared
  capabilities; each entry is a Capability object (Section 6).
* `constraints` (OPTIONAL, 0 to 32 entries): authorization boundary
  constraints; each entry is a Capability object whose `scheme` MUST be
  `varwof/constraint-v1`.
* `chain_depth` (OPTIONAL, 0 to 255): current delegation depth,
  default 0.
* `max_depth` (OPTIONAL, 0 to 255): maximum delegation depth; MUST NOT
  exceed 1 as a best practice; `chain_depth` MUST NOT exceed
  `max_depth`.
* `extensions` (OPTIONAL, 0 to 32 entries): an object keyed by OID
  strings; each value is `{ "critical": boolean, "value": <JSON> }`.
  Unknown extensions with `critical: true` MUST cause rejection;
  unknown extensions with `critical: false` (default) MAY be ignored.

### 5.1.3. The `da` Claim

The `da` claim (CONDITIONAL) contains the complete DA JWT string.  It
is REQUIRED in the full profile.  It MAY be omitted only in the
lightweight consumer profile (Section 10.3) where the delegation mode
is `authorized`, risk is low, and the deployment does not require
principal non-repudiation.

When present, the verifier MUST validate the DA JWT and MUST check
consistency between the DA JWT payload and the outer `aic` claim
(Section 13).

## 5.2. DA JWT Payload (DelegationAuthTBS Equivalent)

The DA JWT payload is the JSON equivalent of DelegationAuthTBS.  In
addition to the AIC members below, every DA JWT MUST carry the RFC 7523
claims `iss`, `sub`, `aud`, `exp` and `jti`:

```
{
  "ver": 2,
  "iss": "corp.com:zhangsan",
  "sub": "corp.com:zhangsan",
  "aud": "https://as.example.com",
  "exp": 1755503600,
  "iat": 1755500000,
  "jti": "<same value as nonce>",
  "agent_id": "agent:db-analyst-01",
  "principal": { ... same structure as aic.principal ... },
  "reason": {
    "code": "DATA_ANALYSIS",
    "desc": "Scheduled data analysis window"
  },
  "capabilities": [ ... ],
  "delegation_mode": "representative",
  "constraints": [ ... ],
  "requested_lifetime": 3600,
  "ts": 1755500000,
  "nonce": "<base64url of 32 random bytes>"
}
```

* `ver` (REQUIRED): 2.  `ver=2` is the DA claim set defined by this
  revision (-01); `ver=1` is the -00 claim set and MUST be rejected by
  -01 implementations (fail closed rather than silently downgraded).
* `iss` (REQUIRED): the principal identifier `realm:id`; MUST equal
  the realm and id of the `principal` binding (RFC 7523 issuer).
* `sub` (REQUIRED): mode-dependent grant subject.  In `authorized`
  mode MUST equal `agent_id`; in `representative` mode MUST equal the
  resource owner / principal `realm:id` (RFC 7523 Section 3, item 2A
  allows the resource owner or an authorized delegate).
* `aud` (REQUIRED): MUST identify the intended authorization server
  (token endpoint) that will redeem the grant.
* `exp` (REQUIRED): MUST equal `ts + requested_lifetime` (a single,
  canonical expiry expression).
* `iat` (OPTIONAL): if present MUST equal `ts`.
* `jti` (REQUIRED): MUST equal `nonce` (RFC 7519 replay identifier).
* `agent_id` (REQUIRED): the agent identifier.  In `authorized` mode
  it MUST equal the outer `sub`; in `representative` mode it MUST
  equal the outer `act.sub` and the OAuth `client_id`.
* `principal` (REQUIRED): MUST equal the outer `aic.principal`.
* `reason` (REQUIRED): `code` (1 to 64 characters, controlled
  vocabulary, e.g., `SCHEDULED_MAINTENANCE`, `AUTO_RENEWAL`,
  `DATA_ANALYSIS`) and `desc` (1 to 512 characters, human readable).
* `capabilities` (REQUIRED): MUST equal the outer `aic.capabilities`.
* `delegation_mode` (REQUIRED): MUST equal the outer
  `aic.delegation_mode`.
* `constraints` (OPTIONAL): MUST equal the outer `aic.constraints`.
* `requested_lifetime` (REQUIRED): 1 to 86400 seconds; SHOULD be
  3600 to 86400.
* `ts` (REQUIRED): NumericDate of the principal's signature.
* `nonce` (REQUIRED): base64url encoding of 32 bytes from a CSPRNG,
  used for replay prevention.  The issuer MUST check uniqueness and
  persist used nonces.

The signing input is the UTF-8 encoding of the JWS payload as defined
by RFC 7515 (that is, the payload is not a DER encoding; JSON field
order in the signed payload is the order produced by the JWS
serialization and MUST be preserved as signed).

## 5.3. PA JWT Payload (PrincipalAuthorization Equivalent)

The optional PA JWT carries the JSON equivalent of the
PrincipalAuthorization extension.  It is REQUIRED in
`representative` mode when no principal X.509 certificate with the
PrincipalAuthorization extension is present in the bundle:

```
{
  "ver": 1,
  "principal": { ... same structure as aic.principal ... },
  "grants": [ ... capabilities ... ],
  "constraints": [ ... ],
  "delegation_policy": {
    "max_agents": 1,
    "allowed_mode": "authorized_only" | "representative_allowed",
    "max_session_hours": 24
  },
  "extensions": { ... }
}
```

* `principal` (REQUIRED): the principal to which the PA JWT belongs.
* `grants` (REQUIRED, 0 to 256 entries): the principal's capability
  grants; the upper bound `P_grants`.
* `constraints` (OPTIONAL): principal-level authorization boundary
  constraints, evaluated independently from `aic.constraints`.
* `delegation_policy` (OPTIONAL): `max_agents` (default 1),
  `allowed_mode` (`authorized_only` default or
  `representative_allowed`), and optional `max_session_hours`.
* `extensions` (OPTIONAL): same structure as `aic.extensions`.

Alternatively, in PKI mode, the principal's X.509 certificate carrying
the PrincipalAuthorization extension MAY be presented in the bundle as
`x5c`; the verifier then evaluates the ASN.1 form.

## 5.4. Mapping from ASN.1

| X.509 AIC (ASN.1) | AIC-JWT |
|--------------------|---------|
| version | `aic.ver` |
| agentId | `sub` (outer), `agent_id` (DA) |
| principalUid.realm | `aic.principal.realm` |
| principalUid.identifier | `aic.principal.id` |
| principalUid.keyHash | `aic.principal.key_hash` |
| principalUid.hashAlgo | `aic.principal.hash_alg` |
| capabilities (Capability) | `aic.capabilities` |
| delegationMode | `aic.delegation_mode` |
| authorizationConstraints | `aic.constraints` |
| DelegationDepthControl | `aic.chain_depth`, `aic.max_depth` |
| extensions | `aic.extensions` |
| DelegationAuthorization | `da` (inner JWT) |
| DelegationAuthTBS | DA JWT payload |
| PrincipalAuthorization | PA JWT or principal `x5c` |
| notBefore / notAfter | `nbf` / `exp` |
| serialNumber / nonce | `jti` / DA `nonce` |
| -- (no ASN.1 counterpart) | DA `iss`, `sub`, `aud`, `exp`, `iat`, `jti` (RFC 7523 claims) |

---

# 6. Capabilities and Matching

## 6.1. Capability Object

Each capability is a JSON object:

```
{
  "scheme": "http",
  "id": "GET:/api/v1/users",
  "params": { "max_rows": 100 }
}
```

* `scheme` (REQUIRED): the capability scheme identifier, 1 to 128
  characters.  Semantics are defined by the scheme, not by this
  specification.  Unknown schemes are routed to scheme-specific
  plugins; requests referencing unknown schemes MUST be rejected
  (fail-closed).
* `id` (REQUIRED): the capability identifier within the scheme, 1 to
  256 characters, supporting glob wildcards (Section 6.2).
* `params` (OPTIONAL): a JSON value (object, array, string, number, or
  boolean) whose semantics are defined by the scheme.  When serialized,
  `params` MUST NOT exceed 512 bytes.

The Capability object is the unified container reused in three
contexts: `aic.capabilities`, `aic.constraints`, and PA `grants`.

## 6.2. Glob Matching

Capability matching uses the same rules as the X.509 AIC
specification:

| Pattern | Meaning | Example |
|---------|---------|---------|
| `scheme:method:path` | exact | `http:GET:/api/v1/users` |
| `scheme:method:path/*` | single segment (no `/`) | `http:GET:/api/v1/*` |
| `scheme:method:path/**` | multi segment | `http:GET:/api/v1/**` |
| `scheme:{a,b}:path` | alternation | `http:{GET,POST}:/api/*` |
| `scheme:[a-z]*:path` | character class | `http:[A-Z]*:/api/*` |
| `scheme:*:path` | single-segment wildcard in the method position | `http:*:/api/v1/*` |
| `scheme:*` | scheme-level wildcard | `http:*` |

Matching precedence (highest to lowest): exact, single-segment
wildcard, multi-segment wildcard, alternation `{a,b}`, character class
`[a-z]`, scheme-level wildcard.  When multiple rules match, the
highest-precedence rule applies.  If no rule matches, the capability
MUST be denied.

Bare `*` without a scheme namespace MUST NOT be allowed.

Matching is implemented as a two-level token stream: the pattern and
the target are first split on `:`; each segment is then split on `/`.
`*` matches exactly one path segment that does not contain `/` (or one
colon-segment in the method position), while `**` matches one or more
segments and MAY cross `/` boundaries.  Within a literal segment,
`{a,b}` alternation matches one of the alternatives and `[a-z]`
character classes match a single character in the class; an embedded
`*` matches any characters within the segment (for example,
`[A-Z]*`).  This algorithm was verified by the reference
implementations (Go and TypeScript/WebCrypto) against the examples in
this section.

## 6.3. Parameter Intersection

When matching `P_grants` against `C_agent`:

* if `C_agent.params` exceeds the bounds of `P_grants.params`, the
  capability entry is invalid and MUST be filtered or rejected;
* otherwise the agent-specified `params` value is adopted in full.

Example: `P_grants.params = {"max_rows": 1000}` with
`C_agent.params = {"max_rows": 100}` is accepted with `max_rows=100`;
with `max_rows=5000` it is rejected.

---

# 7. Authorization Constraints

`aic.constraints` is an optional array of Capability objects whose
`scheme` MUST be `varwof/constraint-v1`; other scheme values MUST be
rejected.  The `id` distinguishes constraint types; the following types
are defined as examples, extensible through the capability scheme
registry:

| `id` | `params` format | Description |
|------|-----------------|-------------|
| `allowed-cidr` | `["10.0.0.0/8", "192.168.0.0/16"]` | Allowed IP ranges |
| `max-concurrent` | `{"max": 5}` | Maximum concurrent agent instances |
| `time-window` | `{"start": "22:00", "end": "06:00"}` | Allowed execution window (UTC) |

Constraints are evaluated with logical AND: all constraints MUST be
satisfied.  The constraint count MUST NOT exceed 32.  Unknown
constraint types default to audit-and-ignore for forward compatibility;
deployments MAY configure strict rejection.

`aic.constraints` (execution boundaries) and PA `constraints`
(authorization boundaries) are evaluated independently; there is no
subset relationship between them.

Runtime policy (timeouts, retries, rate limits, routing) MUST NOT be
placed in `authorizationConstraints`; it remains in gateway local
policy configuration.

---

# 8. Delegation Model

## 8.1. Delegation Modes

**authorized** (default): the Agent acts in its own name.  The audit
log records `sub` (agentId) as the actor and `aic.principal.id` as the
authorizing principal.  The capability set is locked at issuance; no
runtime `P_grants` superset check is performed.  Narrow scope x longer
lifetime (up to 24 hours with renewed DA on renewal).

**representative**: the Agent acts in the principal's name.  The audit
log records `aic.principal.id` as the actor and `act.sub` (the
agentId) as the executor.  The bundle MUST contain the principal's PA
material.  At issuance and at runtime, `C_agent` MUST be a subset of
`P_grants`.  Wide scope x short lifetime, with runtime `P_grants`
intersection at each operation.

## 8.2. Permission Intersection

The effective permission set is the intersection of principal grants
and agent capabilities:

```
P_effective = P_grants (AND) C_agent
```

In `authorized` mode the intersection was verified at issuance and
locked into the token.  In `representative` mode the intersection is
computed at runtime for each operation.  Gateway local runtime policy
(`T_policy`) is an additional enforcement layer and MUST NOT be
confused with the `P (AND) C` intersection.

## 8.3. Multi-level Delegation

Single-level delegation (Principal -> Agent, `chain_depth=0`) is the
default and recommended deployment mode.  Depth-1 chains
(Principal -> Agent -> sub-Agent, `chain_depth=1`) are supported
optionally; each hop produces an independently signed DA JWT whose
signer is the delegating agent.  Capabilities are recursively
intersected along the chain.  Any `chain_depth` MUST NOT exceed
`max_depth`; `max_depth` MUST NOT exceed 1 as a best practice.  A
sub-agent MUST NOT delegate further.

Recursive verification: starting from the presented token, verify each
DA JWT with the signer's key (identified by the previous level's
`principal`/`cnf`), check that declared capabilities are a subset of
the delegator's effective capabilities, and repeat until the original
principal or the depth limit is reached.  Cycles are prevented by
strictly monotonic `chain_depth`; credential bomb attacks are limited
by a gateway-configured maximum bundle size (default 8 certificates or
equivalent tokens).

---

# 9. Credential Bundle (Optional)

## 9.1. Bundle Composition

The credential bundle is an optional deployment mechanism and the JSON
analog of the X.509 credential bundle.  It is presented with the
AIC-JWT to avoid online principal key resolution.  It is RECOMMENDED in
PKI deployments and in deployments where the principal's key is not
reliably resolvable online; when online resolution is available (for
example, from a principal JWKS), the bundle MAY be omitted.  The bundle
contains:

* the AIC-JWT (outer token);
* the principal key material:
  * in PKI mode: the principal's X.509 certificate chain (`x5c`), from
    which the verifier extracts the SPKI and computes
    `hash_alg(SPKI)`; or
  * in pure-JSON mode: the principal's JWK, from which the verifier
    computes the RFC 7638 thumbprint;
* in `representative` mode: the PA JWT or the principal certificate
  carrying the PrincipalAuthorization extension;
* optionally, intermediate CA certificates or issuer JWKS entries.

## 9.2. Principal Binding Check

The verifier MUST compute the binding from the principal key material
(from the credential bundle, an online JWKS, or a locally cached copy)
and MUST compare it to `aic.principal.key_hash`.  The binding method is
determined by `hash_alg`:

* SPKI hash: `key_hash = base64url(hash_alg(SPKI))`, with
  `hash_alg` defaulting to SHA-256.  Only hash algorithms with output
  length not exceeding 64 bytes are supported (SHA-2/SHA-3 family, SM3,
  BLAKE2/BLAKE3).
* JWK thumbprint: `key_hash = jkt` per RFC 7638, `hash_alg = "jkt"`.

Mismatch MUST cause rejection (fail-closed).  The same SPKI-hash
design rationale as the X.509 profile applies: certificate renewal with
the same key pair preserves the binding; key rotation invalidates all
existing delegations without broadcast revocation.

## 9.3. Deployment Note: Offline Operation

AIC-JWT is designed for online verification and does not claim offline
self-contained verification.  In air-gapped deployments that still use
the JSON profile, the verifier MUST accept the risk that a token
revoked after its last status check may be accepted until the next
cache refresh; mitigations include short lifetime windows (RECOMMENDED
<= 1 hour) and locally cached status lists.  Deployments that require
offline self-contained authorization decisions SHOULD use the X.509
AIC (mTLS) profile instead.

## 9.4. Browser Key Material

Browsers have no native ASN.1/DER or X.509 parsing API.  Consequently,
the `x5c` bundle path (SPKI hash of an X.509 certificate) is not
available in browser-only deployments without a third-party ASN.1
library or a server-side helper (Section 10.5, Mode B).  Browser
deployments SHOULD use the JWK thumbprint form (`hash_alg: "jkt"`)
exclusively and SHOULD rely on a server-side helper to convert any
X.509 key material to JWK before it reaches the browser.

---

# 10. Issuance Flows

## 10.1. PKI Mode

In PKI mode the DA is presented to a CA rather than redeemed at an
authorization server: `aud` (Section 5.2) identifies the issuing CA or
its relying-party domain, and the CA validates it when configured.

1. The Agent generates a key pair and constructs an issuance request
   containing the desired capabilities, delegation mode, constraints,
   and a 32-byte nonce.
2. The principal reviews the request (least privilege; wildcard
   capabilities require explicit confirmation), signs the DA JWT
   (Section 5.2), and returns it to the Agent.
3. The Agent submits the DA JWT to the CA.
4. The CA validates: the DA JWT signature against the principal key
   identified by `principal.key_hash`; nonce uniqueness (persisted);
   in `representative` mode, that `capabilities` are a capability-level
   and parameter-level subset of `P_grants`.
5. The CA constructs and signs the outer AIC-JWT, with
   `exp - iat = min(requested_lifetime, local policy cap)` and `exp`
   not exceeding the DA `exp` (Section 5.1.1).

## 10.2. OAuth Authorization Server Mode

1. The principal provides consent through the standard OAuth flow
   (authorization code with `requested_actor`, or an OBO-style flow).
2. The Agent presents the principal-signed DA JWT with the token
   request.  The primary presentation is the [RFC7523] authorization
   grant (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`,
   the DA JWT as the `assertion` parameter).  A `scope` parameter MAY
   accompany the grant but MUST NOT extend the capabilities carried in
   the DA JWT.  In `authorized` mode the DA JWT MAY alternatively be
   presented as a `client_assertion`/`client_assertion_type` pair: the
   DA `sub` then equals the `agent_id`, which the AS has registered as
   the OAuth `client_id` of that agent, satisfying RFC 7523 Section 3,
   item 2B.  A `representative`-mode DA JWT MUST NOT be used as a
   client assertion: its `sub` is the resource owner, not the
   `client_id`.  In this issuance flow the client assertion
   accompanies the authorization grant; it authenticates the agent as
   client and does not by itself request a token.
3. The AS validates the DA JWT as an RFC 7523 assertion: signature by
   the principal key, `iss` equal to the principal identifier, `aud`
   containing this AS, `exp` equal to `ts + requested_lifetime` and
   not yet passed (subject to configured clock skew), `jti`/`nonce`
   uniqueness, and the per-mode `sub` rules (Section 5.2).  It then
   issues the outer AIC-JWT signed with the AS key, with `exp` bounded
   per Section 5.1.1 and role placement per Section 3.2.  An AS MAY
   require the DA `sub` to equal the subject identifier it registers
   for the resource owner, verifying the mapping from the principal
   binding before issuance.
4. The AS MAY expose a JWKS endpoint and Token Status List [TSL] for
   verification and revocation.

The AS MUST NOT sign the outer token without a valid principal-signed
DA JWT (full profile), preserving the two-layer trust model.

If the DA JWT is invalid or cannot be validated, the AS MUST return
the `invalid_grant` error as required by RFC 7523 Section 3.1.  Where
the DA JWT is presented as a client assertion and client
authentication fails, the AS MUST return `invalid_client` per RFC 7523
Section 3.2.  If client credentials are included in the request in
addition to the assertion, the AS MUST validate them (RFC 7523
Section 3.1).

Where the accountable operator of the agent differs from the resource
owner (for example an enterprise-operated agent acting on an end
user's data), the operator MUST be represented by a separate binding
outside the grant subject.  This profile records that binding as
future work and does not conflate the two parties.

## 10.3. Lightweight Consumer Profile

For low-risk consumer deployments, the DA JWT MAY be omitted and
`delegation_mode` MUST be `authorized`.  The issuer signs the outer
token directly from principal consent recorded in the issuance
process.  This profile mirrors the consumer model of the X.509
specification and MUST NOT be used in `representative` mode.

## 10.4. Token Exchange Usage

An AIC-JWT MAY be produced or consumed through [RFC8693] token
exchange:

* `subject_token`: the principal's credential (e.g., an OAuth access
  token or a principal-bound JWT);
* `actor_token`: the Agent's AIC-JWT (or a workload identity token);
* `subject_token_type` / `actor_token_type`: the registered token
  types, including `urn:ietf:params:oauth:token-type:aic+jwt` for
  AIC-JWT.

The exchanged token SHALL carry the AIC claims of the actor and the
intersection of the actor's capabilities with the subject's grants.

Role mapping in the exchanged token follows the AIC authorized-mode
semantics rather than the RFC 8693 default shape: the issued token
keeps the agent as `sub` (with the authorizing principal in
`aic.principal`) and the capability set is the intersection above.
The `subject_token` is a grants source, not the issued token's
subject; an RP that requires a resource-owner-subject token MUST use
the representative issuance path (Section 10.2) instead.  A
`representative`-mode AIC-JWT MUST NOT be used as an `actor_token`:
its `sub` is the resource owner, so it is not an actor credential.
This deviation from the RFC 8693 subject/actor mapping is intentional
and this section is normative for AIC-JWT deployments.

## 10.5. Deployment Architectures

Three deployment architectures are supported and MAY be combined:

**Mode A - Pure OAuth/JSON (no X.509).**  All key material is JWK;
principal binding uses `hash_alg: "jkt"`; trust bootstrap uses JWKS;
revocation uses Token Status Lists [TSL].  No ASN.1/DER or X.509 processing
is required anywhere in the stack.  This is the RECOMMENDED mode for
browser, web, and OAuth-native deployments.

**Mode B - Hybrid with a server-side PKI helper.**  A browser or
application-layer client performs what WebCrypto supports natively
(JWS verification, JWK thumbprints, DPoP), while a server-side helper
(an authorization server, a gateway, or a dedicated service such as a
Go reference implementation) performs the PKI operations that browsers
cannot: X.509 certificate parsing and chain validation, CRL/OCSP
processing, hardware-key-backed signing, and mTLS client-certificate
cross-checks.  The helper MAY translate X.509 AIC credentials into
AIC-JWTs (Section 10.6) or expose principal keys as JWKs so that
browser verifiers only ever handle JWK material.

**Mode C - PKI (X.509) mode.**  The original
[AIC] profile with mTLS is used; the JSON
profile is not.

## 10.6. X.509 AIC Interoperability

When the same authorization is carried in both profiles, the following
equivalences apply:

* key binding: `aic.principal.key_hash` with a SHA-2 `hash_alg`
  (SPKI hash) and the [RFC7638] JWK thumbprint of the same key are two
  encodings of the same binding; a helper MAY convert a presented
  X.509 certificate to a JWK and a verifier MAY accept either form;
* DelegationAuthorization: the ASN.1 DelegationAuthTBS and the DA JWT
  payload carry the same ten AIC fields; the DA JWT additionally
  carries the RFC 7523 claims `iss`, `sub`, `aud`, `exp`, `iat`, and
  `jti`, which have no ASN.1 counterpart in the X.509 profile.  A PKI
  helper MAY translate between the two for issuance, verification, or
  audit;
* PrincipalAuthorization: the ASN.1 extension and the PA JWT carry the
  same grants, constraints, and delegation policy;
* issuance: a server-side helper MAY accept an X.509 AIC credential
  bundle and issue the equivalent AIC-JWT (Mode B), so that a single
  authorization can be presented at the transport layer (mTLS) and at
  the application layer (Bearer) with identical semantics.

Interoperability between the two profiles is a deployment mechanism,
not a new token format; both profiles share the data model defined by
[AIC].

---

# 11. Validation Pipeline

The verifier/gateway MUST execute the following steps in order after
receiving the AIC-JWT and bundle:

1. **JWS verification**: verify the outer signature using the issuer's
   key resolved from `kid` (JWKS or `x5c`), per RFC 7515.
2. **Header checks**: validate `typ == "aic+jwt"`, `alg` in the
   allowlist, and reject `none` and symmetric algorithms (RFC 8725).
3. **Time checks**: `nbf <= now <= exp` (with deployment-configured
   clock skew); `exp - iat <= requested_lifetime <= 86400`.
4. **DA validation** (full profile): verify the inner DA JWT signature
   with the principal key material (credential bundle, online JWKS, or
   a locally cached copy); check `key_hash` against that key material;
   check that the DA `nonce` decodes to 32 bytes; validate the RFC 7523
   claims per Section 5.2 (`iss` equal to the principal identifier,
   the per-mode `sub`, `aud` consistent with the issuer that redeemed
   the grant (the outer token's `iss`), canonical `exp = ts +
   requested_lifetime`, and `jti` equal to `nonce`).  For multi-level
   delegation (Section 8.3), this step applies recursively to each DA
   JWT in the chain, each verified against its delegator's key
   material.  The DA nonce uniqueness check is performed
   by the ISSUER at issuance (Section 10) and MUST NOT be treated as
   single-use by the verifier: the same
   access token is legitimately presented multiple times within its
   lifetime.  A verifier MAY keep an optional local replay cache for
   additional detection, but such a cache MUST NOT reject a valid token
   on legitimate reuse.  Per-request single-use replay protection at
   the verifier is provided by DPoP proof `jti` (Section 13.2), not by
   the DA nonce.
5. **Consistency checks**: mode-dependent.  In `authorized` mode, DA
   `agent_id` MUST equal the outer `sub`; in `representative` mode,
   DA `sub` MUST equal the outer `sub` (resource owner / principal)
   and DA `agent_id` MUST equal the outer `act.sub`.  In both modes,
   DA `principal == aic.principal`, DA `capabilities ==
   aic.capabilities`, DA `delegation_mode == aic.delegation_mode`, DA
   `constraints == aic.constraints`.  Any mismatch MUST cause
   rejection.
6. **PA check** (`representative` mode): load the PA JWT or principal
   certificate from the bundle; verify `allowed_mode` permits
   representative delegation; verify `C_agent` is a subset of
   `P_grants` (with parameter intersection per Section 6.3).
7. **Constraint evaluation**: evaluate `aic.constraints` with AND
   semantics (IP ranges, concurrency, time windows), then PA
   constraints independently.  Constraint evaluation precedes
   capability evaluation for fast rejection.
8. **Delegation depth check**: verify `chain_depth <= max_depth`.
9. **Capability evaluation**: route the capability required by the
   current request to the scheme plugin registered for its `scheme`.
   Unknown schemes or unknown capabilities MUST be rejected
   (fail-closed).  Capabilities irrelevant to the current request MUST
   NOT affect the decision.
10. **Status check** (optional): if a `status` claim is present, fetch
    or use a cached Token Status List [TSL] and verify the referenced token
    is valid.
11. **Decision**: if all steps pass, permit; otherwise deny and log
    sufficient diagnostic information for audit.

---

# 12. Examples

## 12.1. Outer AIC-JWT

Header:

```
{
  "alg": "ES256",
  "typ": "aic+jwt",
  "kid": "ca-2026-01"
}
```

Payload:

```
{
  "iss": "https://ca.example.com/aic",
  "sub": "corp.com:zhangsan",
  "act": { "sub": "agent:db-analyst-01" },
  "aud": ["https://gw.example.com"],
  "iat": 1755500000,
  "exp": 1755503500,
  "jti": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdef",
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyHnXgk7dNsQo0c1V3iR4vY" },
  "aic": {
    "ver": 1,
    "principal": {
      "realm": "corp.com",
      "id": "zhangsan",
      "key_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "hash_alg": "sha-256"
    },
    "delegation_mode": "representative",
    "capabilities": [
      { "scheme": "database", "id": "query:SELECT", "params": { "max_rows": 100 } }
    ],
    "constraints": [
      { "scheme": "varwof/constraint-v1", "id": "allowed-cidr", "params": ["10.0.0.0/8"] }
    ],
    "chain_depth": 0,
    "max_depth": 1
  },
  "da": "<DA JWT from Section 12.2>"
}
```

## 12.2. Inner DA JWT

Header:

```
{
  "alg": "ES256",
  "typ": "aic+da+jwt",
  "kid": "principal-zhangsan-2026"
}
```

Payload:

```
{
  "ver": 2,
  "iss": "corp.com:zhangsan",
  "sub": "corp.com:zhangsan",
  "aud": "https://ca.example.com/aic",
  "exp": 1755503500,
  "iat": 1755499900,
  "jti": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdef",
  "agent_id": "agent:db-analyst-01",
  "principal": {
    "realm": "corp.com",
    "id": "zhangsan",
    "key_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "hash_alg": "sha-256"
  },
  "reason": {
    "code": "DATA_ANALYSIS",
    "desc": "Scheduled production data analysis window"
  },
  "capabilities": [
    { "scheme": "database", "id": "query:SELECT", "params": { "max_rows": 100 } }
  ],
  "delegation_mode": "representative",
  "constraints": [
    { "scheme": "varwof/constraint-v1", "id": "allowed-cidr", "params": ["10.0.0.0/8"] }
  ],
  "requested_lifetime": 3600,
  "ts": 1755499900,
  "nonce": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdef"
}
```

---

# 13. Security Considerations

## 13.1. Algorithm Confusion

Follow [RFC8725]: validate the `alg` allowlist, resolve `kid` to the
expected key, reject `none` and symmetric algorithms, and reject
unexpected `typ` values.  AIC-JWT MUST always be asymmetric.

## 13.2. Token Theft and Replay

AIC-JWT is a bearer token by default.  Deployments MUST use TLS.  The
token MUST carry `cnf` binding it to the Agent key, and deployments
SHOULD additionally use DPoP [RFC9449] to prevent token theft and
replay.  Where higher assurance is required, the AS MAY challenge the principal with step-up authentication [RFC9470] before issuing or refreshing tokens.  Where mTLS is deployed, the verifier MAY cross-check the mTLS
client certificate key against `cnf` (Section 3.3).  Replay is
additionally bounded by the DA `nonce`/`jti` uniqueness check at
issuance and by the short lifetime.  The nonce is a signed input of the
DA JWT, not a plaintext parameter.

## 13.3. Audience Confusion

The `aud` claim MUST be validated per RFC 9068.  Issuers MUST use
distinct issuer identifiers per trust domain (RFC 9207) so that a token
issued by one AS cannot be accepted by another.

## 13.4. Nested Token Confusion

The DA JWT and the AIC-JWT use distinct `typ` values (`aic+da+jwt` vs
`aic+jwt`).  A DA JWT MUST NOT be accepted as an AIC-JWT, and an
AIC-JWT MUST NOT be accepted as a DA JWT.  Verification of the inner
token MUST use the principal key identified by the DA's `principal`,
never the issuer key.

## 13.5. Principal Key Binding

The principal binding is a hash of the principal's SPKI (or JWK
thumbprint).  Under the security assumptions of the selected hash
algorithm, collisions are computationally infeasible.  The hash is a
locating and binding mechanism, not a trust anchor: trust comes from
the bundle key material cross-check and the DA signature verification.

## 13.6. Threat Model

The threat model of the X.509 AIC specification applies:

* network attacker (no private keys): mitigated by TLS, signatures,
  and token binding;
* malicious Agent (valid token, attempts escalation): mitigated by
  capability subset checks, constraint evaluation, and fail-closed
  capability routing;
* compromised Principal (key leak): mitigated by SPKI-hash binding --
  key rotation invalidates all existing delegations;
* compromised CA/AS: mitigated by the two-layer signature -- the
  attacker still cannot forge a principal-signed DA JWT.

## 13.7. Size Limits

* `aic.capabilities`: 1 to 256 entries; more MUST be rejected.
* `aic.constraints`: 0 to 32 entries; more MUST be rejected.
* `params` when serialized: at most 512 bytes.
* `aic.extensions`: at most 32 entries.
* Recommended total token size: 16 KB (compact); hard limit 64 KB.
  Unlike the X.509 profile, no TLS handshake limit applies at the
  application layer, but excessive sizes MUST be rejected to prevent
  denial of service.

## 13.8. Web Browser Runtime Considerations

The reference TypeScript implementation uses WebCrypto only
(`crypto.subtle`, `TextEncoder`/`TextDecoder`, `btoa`/`atob`,
`BigInt`) and was verified in Node and in WebCrypto-compatible
runtimes.  The following browser constraints were verified and MUST be
taken into account by browser implementations:

* All cryptographic operations are asynchronous; the validation
  pipeline MUST be implemented with promises/async.
* WebCrypto ECDSA signatures are raw R||S, which is JOSE-compatible;
  no DER conversion is required.
* A DPoP proof header MUST carry the public key only.  Including the
  private JWK (with `d` and `key_ops: ["sign","verify"]`) causes key
  import with `usages: ["verify"]` to fail in WebCrypto
  implementations.
* When importing a JWK (from a DPoP header or elsewhere), `key_ops`
  MUST be removed or aligned with the requested usages.
* RSA-PSS signing and verification require an RSA-PSS key; a key
  generated for RSASSA-PKCS1-v1_5 MUST NOT be used for PS256.
* Ed25519 WebCrypto support varies by runtime and browser version;
  implementations MUST feature-detect Ed25519 before using `EdDSA`.
* WebCrypto hash algorithms are limited to SHA-1/SHA-256/SHA-384/
  SHA-512.  `sha3-*`, `sm3`, and BLAKE2/BLAKE3 are NOT available and
  require WASM libraries when those `hash_alg` values are used.
* Browsers cannot access TPM/HSM/smart-card keys directly.  WebAuthn
  covers only RP-scoped challenge signing and MUST NOT be assumed to
  sign arbitrary DA payloads; hardware-backed principal signing in
  browser scenarios SHOULD be delegated to a server-side helper
  (Section 10.5, Mode B).
* Browsers do not expose the mTLS client certificate to script; the
  Section 3.3 cnf/mTLS cross-check is therefore not available in
  browsers.  DPoP is the sender-binding mechanism for browser
  deployments.
* Long-running background agents are constrained by page and service
  worker lifecycles; browser-hosted agents SHOULD be session-scoped,
  with long-running execution delegated to a backend.

---

# 14. Privacy Considerations

The GDPR / right-to-be-forgotten considerations of the X.509 AIC
specification apply:

1. `aic.principal.id` MUST NOT contain raw PII (full names, national
   identifiers, email addresses).  Pseudonymous identifiers (UUIDs)
   MUST be used, with the mapping table stored in a compliant,
   deletable database.
2. Revocation (Token Status List [TSL] or short lifetime) is the mechanism
   for expressing "the principal no longer authorizes this Agent";
   revocation does not erase the token itself.
3. AIC-JWT is a stateless credential: it MAY be parsed and validated
   in memory and discarded, without persistence.
4. Audit logs MUST be minimized: session binding fingerprint, operation
   summary, decision, and pseudonymous identifier are sufficient.
5. Cryptographic evidence is independent of log mappings: deleting the
   pseudonym mapping table does not invalidate the DA JWT signature.
6. Sensitive data MUST NOT be placed in any claim; all AIC-JWT data is
   visible to any party that receives the token.

---

# 15. IANA Considerations

## 15.1. Media Type Registration

Register the media type `application/aic+jwt`, following the template
of RFC 9068's `application/at+jwt`.

## 15.2. JWT Claims Registration

Register the following JWT claims in the IANA JSON Web Token Claims
registry:

| Claim | Description |
|-------|-------------|
| `aic` | AIC-JWT namespaced claims object |
| `da` | Principal-signed DelegationAuthorization JWT |
| `aic+da` (inner payload members) | DelegationAuthTBS equivalent, plus the RFC 7523 claims `iss`, `sub`, `aud`, `exp`, `iat`, `jti` |
| `aic+pa` (payload members) | PrincipalAuthorization equivalent |

## 15.3. OAuth Token Type URN

Register `urn:ietf:params:oauth:token-type:aic+jwt` for use with RFC
[RFC8693] token exchange and [RFC7523] assertions.

## 15.4. OAuth Authorization Server Metadata

Consider registering metadata entries indicating AIC-JWT support, such
as `aic_jwt_supported` and `aic_jwt_profiles_supported`
(`pki` | `oauth-as`), following the OAuth Authorization Server Metadata
specification.

---

# 16. Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate
Requirement Levels", BCP 14, RFC 2119, March 1997.

[RFC4648] Josefsson, S., "The Base16, Base32, and Base64 Data
Encodings", RFC 4648, October 2006.

[RFC6749] Hardt, D., "The OAuth 2.0 Authorization Framework",
RFC 6749, October 2012.

[RFC7515] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature
(JWS)", RFC 7515, May 2015.

[RFC7519] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token
(JWT)", RFC 7519, May 2015.

[RFC7523] Jones, M., Campbell, B., and C. Mortimore, "JSON Web Token
(JWT) Profile for OAuth 2.0 Client Authentication and Authorization
Grants", RFC 7523, May 2015.

[RFC7638] Jones, M. and N. Sakimura, "JSON Web Key (JWK) Thumbprint",
RFC 7638, September 2015.

[RFC7800] Jones, M., Bradley, J., and H. Tschofenig, "Proof-of-
Possession Key Semantics for JSON Web Tokens (JWTs)", RFC 7800,
April 2016.

[RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119
Key Words", BCP 14, RFC 8174, May 2017.

[RFC8693] Jones, M., et al., "OAuth 2.0 Token Exchange", RFC 8693,
January 2020.

[RFC8725] Sheffer, Y., Hardt, D., and M. Jones, "JSON Web Token Best
Current Practices", BCP 225, RFC 8725, February 2020.

[RFC9068] Bertocci, V., "JSON Web Token (JWT) Profile for OAuth 2.0
Access Tokens", RFC 9068, October 2021.

[RFC9207] Meyer zu Selhausen, K. and D. Fett, "OAuth 2.0 Authorization
Server Issuer Identification", RFC 9207, April 2022.

[RFC9396] Lodderstedt, T., et al., "OAuth 2.0 Rich Authorization
Requests", RFC 9396, May 2023.

[RFC9449] Fett, D., Campbell, B., Bradley, J., Lodderstedt, T., Jones,
M., and D. Waite, "OAuth 2.0 Demonstrating Proof of Possession (DPoP)",
RFC 9449, September 2023.

[RFC9470] Fett, D. and B. Campbell, "OAuth 2.0 Step Up Authentication
Challenge Protocol", RFC 9470, September 2023.

[TSL] Looker, T., Bastian, P., and C. Bormann, "Token Status List",
draft-ietf-oauth-status-list-21, June 2026.

[AIC] Wei, J., "AI Agent Identity Certificate (AIC) X.509 v3
Extension", draft-wei-aic-identity-cert-00, August 2026.

---

# 17. Informative References

[DAAP] Kumar, S., "Delegated Agent Authorization Protocol (DAAP)",
draft-mishra-oauth-agent-grants-01, March 2026.

[OBO] Dissanayaka, A., "OAuth 2.0 Extension: On-Behalf-Of User
Authorization for AI Agents", draft-oauth-ai-agents-on-behalf-of-
user-02, August 2025.

[WIMSE] Campbell, B., et al., "WIMSE Service to Service
Authentication", draft-ietf-wimse-s2s-protocol, work in progress.

[ATN] Somoza, J., "ATN Agent Trust Negotiation",
draft-somoza-atn-agent-trust-negotiation, work in progress.

[PEDIGREE] Rampalli, V., "PEDIGREE Verifiable Delegated Identity",
draft-rampalli-pedigree, work in progress.

[HDP] "Human Delegation Provenance Protocol",
draft-helixar-hdp-agentic-delegation, work in progress.

[RFC5280] Cooper, D., et al., "Internet X.509 Public Key Infrastructure
Certificate and Certificate Revocation List (CRL) Profile",
RFC 5280, May 2008.

---

# 18. Compatibility with the Varwof Unified JWT Profile

The internal design note "AIC x SPIFFE x OAuth/OIDC Interop"
(`dev-docs/aic/11-spiffe-oauth-interop.md`) defines a Unified JWT
Profile that projects one AIC identity onto SPIFFE JWT-SVID and
RFC 9068 access tokens simultaneously.  This section maps the AIC-JWT
claims of this specification to that profile.  The two documents use
different naming; the mapping below keeps them interoperable:

| AIC-JWT (this document) | Unified JWT Profile (11) | SPIFFE JWT-SVID / RFC 9068 view |
|-------------------------|--------------------------|---------------------------------|
| `iss` (CA or AS URL) | `iss` (OAuth URL) | -- (JWT-SVID validators do not process `iss`; trust domain anchored by `sub` + bundle) |
| `sub` (authorized) = agentId; `sub` (representative) = resource owner + `act` = agentId | `sub` = `spiffe://<td>/agent/<id>`, `agent_id` | `sub` (SPIFFE); `sub` (RFC 9068) |
| `aud` | `aud` | `aud` |
| `iat` / `exp` / `nbf` / `jti` | same | same |
| `aic.principal` | `principal_uid` | -- |
| `aic.capabilities` | `scope` + `capabilities` | `scope` |
| `aic.delegation_mode` | `delegation_mode` | -- |
| `aic.constraints` | -- (deployment-side) | -- |
| `da` (nested principal-signed JWT) | -- (11 has no DA; this document keeps the two-layer signature) | -- |
| `cnf` / DPoP | -- | RFC 9068 + DPoP |

Projection rules for interoperable deployments:

* in SPIFFE mode (`is_spiffe=true`), the AIC certificate's `agentId`
  is itself the SPIFFE ID (`spiffe://<td>/agent/<agentId>`) and is
  dual-written to the certificate SAN URI; the AIC-JWT `sub` inherits
  that SPIFFE ID directly and no conversion is required;
* SPIFFE JWT-SVID projection is defined for `authorized` mode only:
  a `representative`-mode token carries the resource owner in `sub`
  and MUST NOT be projected to a JWT-SVID (whose subject is the agent
  workload) without first issuing an authorized-mode projection;
* when the AIC X.509 certificate carries a SPIFFE URI SAN but the
  AIC-JWT was issued with a bare `agentId`, a converter MAY emit `sub`
  as the SPIFFE ID (`spiffe://<td>/agent/<agentId>`) while keeping
  `aic.principal` unchanged;
* `aic.capabilities` MAY be projected to the OAuth `scope` string
  (space-separated `scheme:capabilityId` entries) for generic
  resource servers; `aic.capabilities` remains canonical;
* the two-layer signature (principal-signed `da` covered by the issuer
  signature) is preserved in AIC-JWT and is NOT represented in the 11
  profile; verifiers requiring principal non-repudiation MUST use the
  `da` claim;
* the AIC-JWT `iss` remains the OAuth/RFC 9068 issuer URL; JWT-SVID
  validators do not process `iss` -- the trust domain is anchored by
  the `sub` SPIFFE ID and the SPIFFE bundle used for signature
  verification.  Deployments requiring RFC 9068 conformance MUST NOT
  replace `iss` with `spiffe://<td>`;
* the issuer signing key SHOULD be published both in the OAuth JWKS
  and as a JWT-SVID bundle entry (`use=jwt-svid`), so that the same
  token can be verified by OAuth resource servers (JWKS) and
  SPIFFE/JWT-SVID validators (bundle) without conversion;
* the AIC-JWT `typ` remains `aic+jwt`.  A JWT-SVID validator that
  enforces the JWT-SVID `typ` restriction (only `JWT` or `JOSE`) will
  reject the token; deployments presenting AIC-JWT to such validators
  SHOULD issue a projected token with `typ` `JWT` and a single-value
  `aud`.

---

# Intellectual Property

This document is subject to BCP 79 (RFC 8179). The author has filed
patent applications related to the technologies described in the
companion X.509 profile (`draft-wei-aic-identity-cert`), including
Chinese patent applications CN2026112384541 and CN2026112384607
(filed with the China National Intellectual Property Administration).
IPR disclosure 7553, filed for the companion profile, grants a
Royalty-Free, Reasonable and Non-Discriminatory license to all
implementers; the author will file an IPR disclosure covering this
document on the same terms in accordance with BCP 79. Any applicable
IPR disclosures are available through the IETF IPR disclosure system.

# Implementation Status

Per [RFC7942], reference implementations exist and were used to verify
this specification:

* A Go reference implementation (standard library only) implements the
  claims model, the 11-step validation pipeline, capability matching,
  constraints, key binding, and the OAuth scenarios (RFC 9068, RFC
  7523, RFC 8693, RFC 9449, OBO-style flows, and Token Status Lists [TSL]).
  Test suites in types/aicjwt and the aic-jwt repository pass
  (go test ./...).
* A TypeScript/WebCrypto reference implementation implements the same
  pipeline for browser-compatible runtimes, including EdDSA and
  RSA-PSS coverage with feature detection.  Test suite: 15 cases, all
  passing (node --test ts/aicjwt.test.ts).

The Go core is maintained in github.com/varwof/types (package
types/aicjwt); the wrapper, OAuth protocol-layer simulation, and the
TypeScript/WebCrypto implementation are in
https://github.com/varwof/aic-jwt.  Findings verified by these
implementations are incorporated in Sections 6.2, 9.4, 10.5, 10.6,
11, and 13.8.

---

# Acknowledgements

The author thanks the IETF community for ongoing discussion of agent
identity and accountability frameworks.

# Change Log

draft-wei-aic-jwt-01 (2026-09-05):

* The DA JWT now carries the RFC 7523 claims `iss`, `sub`, `aud`,
  `exp` and `jti` (jti = nonce; exp = ts + requested_lifetime), making
  the Section 10.2 jwt-bearer presentation interoperable (resolves
  review by I. Schrock, OAuth WG, 2026-09-04).
* Role placement is mode-dependent: representative mode places the
  resource owner / principal in `sub` and the agent in `act` (RFC 8693
  actor / OAuth client); authorized mode places the agent in `sub` as
  the authorized accessor (RFC 7523 Section 3, item 2A).  The X.509
  convention that the certificate subject is the agent is retained in
  authorized mode only and stated as such (resolves review by J.
  Lombardo, OAuth WG, 2026-09-04).
* A deployment whose accountable operator differs from the resource
  owner MUST represent the operator separately; recorded as future
  work.
* Token exchange mapping clarified (Section 10.4): the exchanged token
  keeps authorized-mode AIC semantics (agent as `sub`, principal in
  `aic.principal`); a representative-mode token is rejected as an
  `actor_token`; operator binding remains future work.
* DA `ver` bumped to 2 for the -01 claim set; `ver=1` is the -00 shape
  and is rejected, making the schema break explicit.
* Reference implementations (Go and TypeScript/WebCrypto) updated with
  regression tests for the claims and role model above.
* RFC 7523 conformance completion: jwt-bearer grant is the primary
  token-endpoint presentation and client-assertion use is restricted
  to authorized mode (Section 10.2); `invalid_grant` /
  `invalid_client` error handling and client-credential validation
  stated (Section 10.2); the outer `exp` is bounded by the DA `exp`
  (Section 5.1.1); DA `aud` and multi-level recursion added to the
  validation pipeline (Section 11); the Section 12 examples updated
  to the -01 claims set; cross-references and ASN.1 mapping table
  corrected.

draft-wei-aic-jwt-00 (2026-08-24, revision 5):

* Section 18: clarified that the AIC-JWT `iss` remains the OAuth URL
  and is not processed by JWT-SVID validators (trust domain is anchored
  by `sub` + SPIFFE bundle); added the SPIFFE-mode `sub` inheritance
  rule, the key dual-publication rule (OAuth JWKS + JWT-SVID bundle
  entry) and the `typ` projection rule.

draft-wei-aic-jwt-00 (2026-08-24, revision 4):

* Added PS384 and PS512 to the algorithm allowlist (Section 4.5) to
  align with the SPIFFE JWT-SVID algorithm set; EdDSA remains a MAY
  extension beyond the JWT-SVID set.

draft-wei-aic-jwt-00 (2026-08-23, revision 3):

* Added compatibility mapping with the Varwof Unified JWT Profile
  (Section 18), keeping AIC-JWT interoperable with SPIFFE JWT-SVID and
  RFC 9068 projections.

draft-wei-aic-jwt-00 (2026-08-23, revision 2):

* Clarified the two-level capability matching algorithm (Section 6.2).
* Clarified that DA nonce uniqueness is enforced at issuance and MUST
  NOT be treated as single-use by the verifier (Section 11).
* Added deployment architectures, including pure OAuth/JSON, hybrid
  server-side PKI helper, and X.509 interoperability (Sections
  10.5-10.6).
* Added browser key-material guidance (Section 9.4) and WebCrypto
  runtime constraints (Section 13.8).
* Added implementation status for the Go and TypeScript/WebCrypto
  reference implementations.

draft-wei-aic-jwt-00 (2026-08-23):

* Initial individual draft.
