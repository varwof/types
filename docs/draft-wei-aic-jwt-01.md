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

The AI Agent Identity Certificate (AIC) [AIC] defines a data model in
which the cryptographic identity of an AI agent is bound to a
responsible principal, together with a structured capability
container, delegation mode, authorization constraints, and
principal-signed delegation evidence.  The normative definition of
this model is specified by [AIC], where it is encoded in ASN.1 and
carried in X.509 certificates, enabling authorization decisions at
the transport layer, including fully offline operation.

Many HTTP, web, and OAuth 2.0 [RFC6749] deployments cannot present
X.509 certificates at the transport layer.  This document therefore
defines AIC-JWT as a JWT-based application-layer representation of
the AIC data model defined by [AIC].  AIC-JWT is a companion
representation, not a replacement for the X.509 form and not a new
authorization model.

AIC-JWT uses the standard JWT [RFC7519] and JWS [RFC7515] mechanisms
as its carrier and cryptographic envelope.  Its authorization
semantics are inherited from the AIC model rather than defined by
JWT or OAuth.  In particular, the outer AIC-JWT is issuer-signed and
carries the principal-signed DA JWT as the value of the top-level
`da` claim, preserving the two-layer signature model
of AIC.

The normative content of this document is limited to:

* a mapping from the X.509 AIC extension fields to JWT claims that
  preserves the AIC data model and its two-layer signature model;
* representation and key-binding rules for the principal-signed
  DelegationAuthorization;
* validation rules for AIC-JWT, including claim consistency,
  audience, and key-binding checks; and
* a thin OAuth 2.0 consumption profile defining presentation of the
  DA at a token endpoint as an [RFC7523] JWT bearer authorization
  grant and the projection of the AIC `authorized` and
  `representative` delegation modes into OAuth roles.

Authorization semantics, policy evaluation, obligations, and
cross-vocabulary equivalence of capabilities are outside the scope
of this document; they are determined by the AIC capability schemes
and deployment policies referenced by [AIC].  IANA registrations and
security considerations for the AIC-JWT representation are included.

---

# 1. Introduction

## 1.1. Problem Statement

The AIC X.509 extension defined in [AIC] binds an AI agent's
cryptographic identity to a responsible principal and carries the
information needed to determine whether a requested operation is
authorized, including the delegated authority, capabilities,
authorization constraints, validity, and accountability information.
Its design goal is that the authorization decision can be made offline
from the certificate and its credential bundle alone, including at the
TLS layer.

Many deployment contexts cannot present X.509 certificates at the
transport layer:

* third-party APIs and web applications consume HTTP Authorization
  headers rather than mTLS client certificates;
* web and mobile clients cannot manage client certificates;
* OAuth 2.0 [RFC6749] ecosystems use bearer tokens and token exchanges;
* serverless and managed gateways terminate TLS on behalf of the
  application.

In these contexts, the AIC data model needs an application-layer
carrier.  This document defines that carrier as a JSON Web Token (JWT)
[RFC7519] secured by JSON Web Signature (JWS) [RFC7515], and names it
**AIC-JWT**.

## 1.2. Relationship to the X.509 AIC Extension

AIC-JWT is a companion profile of the AIC X.509 extension, not a
replacement and not a new authorization model.  The X.509 AIC
extension remains the transport-layer representation used during TLS
handshakes in managed, regulated, and air-gapped environments.
AIC-JWT carries the same AIC semantic model at the application layer:

| Concern | X.509 AIC (transport) | AIC-JWT (application) |
|---------|------------------------|------------------------|
| Encoding | ASN.1/DER | JSON (JWT claims) |
| Signature framework | X.509 / [RFC5280] | JWS / [RFC7515] |
| Principal signature | DelegationAuthorization | Inner DA JWT (`typ=aic+da+jwt`) |
| Issuer signature coverage | CA signature over the TBSCertificate | JWS signature over the protected header and payload |
| Agent key binding | Subject public key (SPKI) | `cnf` claim ([RFC7800]) |
| Revocation / status | CRL / OCSP / short lifetime | Token Status List / short lifetime |
| Trust establishment | Certificate chain | Trusted JWKS, `x5c`, or credential bundle |
| Transport | TLS handshake (mTLS) | HTTP Authorization header |

The two profiles share the same semantic elements, including the
agent identity, principal identity, the Capability container
(`schemeId`/`capabilityId`/`parameters`), delegation mode,
authorization constraints, the DelegationAuthorization structure, the
permission intersection model, capability glob matching, and the
credential-bundle verification semantics.

[AIC] is the authoritative specification for AIC semantics.  This
document does not redefine those semantics.  Where this document and
[AIC] could otherwise be read as disagreeing about the AIC model,
[AIC] governs the semantics, while this document governs the JWT
representation, JWT-specific validation, and OAuth-facing projection.

AIC-JWT is a credential representation, not a policy engine.  It
carries the AIC delegation and constraint semantics for the consumer
to evaluate; how a relying party combines those semantics with its
own local execution policy is a deployment decision outside this
document.

## 1.3. Scope

AIC-JWT is a JWT [RFC7519] profile and does not require OAuth-specific
processing, an RFC 9068 access-token profile, or token-exchange
semantics.  An AIC-aware validator applies the additional validation
rules defined by this document to the AIC-JWT claims.

This document defines the JWT carrier mapping of the AIC model
specified in [AIC], together with the OAuth-facing consumption
constraints needed to present that carrier at existing OAuth 2.0
endpoints.  The AIC data model -- including delegation modes, capability
container semantics, permission intersection, and principal/agent role
definitions -- is defined by the AIC specification [AIC] and is not
restated or extended here.

Normative content includes token structure, claim definitions, the
mapping of the AIC data model to JWT claims (Section 5.4), the
validation pipeline, credential bundle requirements, the OAuth
consumption profile, and IANA registrations.  Design principles,
deployment architectures, and performance characteristics are
informative.

Out of scope:

* authorization semantics and policy evaluation -- this document does
  not define or modify how capabilities, grants, or authorization
  constraints are evaluated; those semantics are defined by [AIC] and
  deployment policy;
* obligations, PDP behavior, or any mechanism that changes the scopes
  or the authority of an issued token after issuance;
* semantic equivalence between capabilities expressed in different
  vocabularies or across service domains;
* new OAuth 2.0 flows or protocols: AIC-JWT is consumed through the
  existing [RFC7523] JWT bearer grant mechanism.  Integration with
  [RFC8693], DPoP [RFC9449], Token Status Lists [TSL], or [RFC9068]
  access tokens is deployment-specific and outside this specification.

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
  the configured AIC issuer.

DA JWT:
: The inner JWT (`typ=aic+da+jwt`) signed by the principal, carrying
  the principal-signed delegation authorization content defined by
  [AIC].

PA JWT:
: An optional companion JWT (`typ=aic+pa+jwt`) carrying the
  application-layer representation of the PrincipalAuthorization
  extension defined by [AIC].  When present, it is part of the
  credential bundle and is not itself the outer AIC-JWT.

Issuer:
: The entity that signs the outer AIC-JWT.  In PKI deployments, the
  issuer is a CA or other configured PKI issuer; in OAuth deployments,
  it is an authorization server (AS).

Audit actor vs. OAuth actor:
: The audit actor recorded per Section 8.1 is the principal in
  `representative` mode (the agent is the executor).  This is distinct
  from the RFC 8693 `act` claim (Section 5.1.1), which names the
  executing agent on tokens whose `sub` is the resource owner.  The
  terms "audit actor" and OAuth `act` are not semantically equivalent.

## 1.6. Related Work

[DAAP] (`draft-mishra-oauth-agent-grants`) defines a delegated agent
authorization protocol with DID-based agent identity and JWT grant
tokens.  AIC-JWT differs in architecture: identity is anchored to a
PKI/AS trust root, and the principal's consent is carried as a nested
principal-signed DA JWT covered by the issuer signature, rather than
as a standalone grant produced by a delegated-agent flow.  Principal
public key resolution may use JWKS in OAuth deployments or a
credential bundle in PKI deployments; the trust model is defined by
the validation rules of this specification.

[OBO] (`draft-oauth-ai-agents-on-behalf-of-user`) extends OAuth 2.0
flows with `requested_actor` and `actor_token` parameters.  AIC-JWT is a
token format that can be produced by such flows.

The WIMSE working group separates workload identifiers
(draft-ietf-wimse-identifier) from workload credentials (X.509 WIC
and JWT WIT forms; draft-ietf-wimse-workload-creds).  These documents
identify workloads and do not carry delegation or authorization data.
AIC-JWT is the JWT mapping of the AIC model defined in [AIC]; it
composes with WIMSE/SPIFFE workload identities at the credential
layer, and it does not add authorization semantics of its own.  In
this composition, WIMSE/SPIFFE identifies the workload; AIC expresses
what that agent is authorized to do and by whom.

Other delegation-oriented application-layer credential formats,
including [ATN], [PEDIGREE], and [HDP], explore related mechanisms for
representing delegation and provenance.  AIC-JWT instead defines the
JWT representation of the AIC model specified in [AIC], including its
structured capability container, nested principal authorization, and
authorization constraints.

---

# 2. Design Principles

This specification is guided by five orthogonal principles, carried
over from the AIC specification [AIC]:

1. **Two-layer signature nesting.**  The principal signs the DA JWT,
   which carries the delegated authorization defined by [AIC].  The
   issuer then signs the outer AIC-JWT, covering the complete payload
   including the DA JWT.  The principal's delegation authorization
   therefore cannot be modified by the issuer without invalidating the
   principal signature, and a principal key alone cannot mint a valid
   outer AIC-JWT.  Where the AIC profile binds the delegated
   authorization to the Agent key within the DA, that binding is
   covered by the principal signature as well; otherwise the outer
   token's `cnf` claim binds the presenting Agent key at consumption
   time.

2. **One container, three contexts.**  The Capability structure
   (`schemeId`/`capabilityId`/`parameters`) is reused in
   `aic.capabilities`, `aic.constraints`, and `grants` of the PA JWT.
   Each occurrence has the semantic role defined by [AIC]; reuse of the
   container does not imply semantic equivalence.  Gateways route
   evaluation by `schemeId` to scheme-specific processing, allowing
   capability semantics to evolve through their respective registries
   without changing the AIC-JWT container.

3. **Application-layer, JWT-native verification.**  AIC-JWT uses
   standard JWT and JOSE mechanisms for cryptographic verification.
   Key discovery, credential status, and sender-constraining mechanisms
   such as JWKS, Token Status Lists [TSL], and DPoP [RFC9449] MAY be
   used according to deployment requirements; they are deployment-
   specific and are not intrinsic to the AIC-JWT representation.
   Fully self-contained offline verification is a deployment property
   of the X.509 AIC profile and its credential bundle.

4. **Delegation mode as a cryptographically bound field.**
   `delegation_mode` distinguishes `authorized` (the Agent acts in its
   own name) from `representative` (the Agent acts in the principal's
   name), with the corresponding runtime and audit semantics defined
   by [AIC].  AIC-JWT carries this distinction without redefining it.

5. **Protocol interoperability.**  AIC-JWT uses standard JWT and JOSE
   mechanisms and defines a thin OAuth 2.0 consumption profile.  Standard
   claims such as `iss`, `sub`, `aud`, `iat`, `exp`, and `jti`, together
   with `cnf` [RFC7800], are used where required by the AIC-JWT
   representation.  The OAuth profile uses the existing [RFC7523] JWT
   bearer grant mechanism.  Integration with DPoP [RFC9449], Rich
   Authorization Requests [RFC9396], token exchange [RFC8693], Token
   Status Lists [TSL], and RFC 9068 access tokens is deployment-specific
   and outside the core AIC-JWT specification.

---

# 3. Overview

## 3.1. Token Roles and Trust Model

The AIC-JWT trust model has four roles:

* **Principal**: the natural person or organization that signs the DA
  JWT.  The principal's public key is identified by
  `aic.principal.key_hash`.  In `representative` mode, the Principal is
  projected as the OAuth resource owner and is the subject (`sub`) of
  the DA and, where applicable, of the issued token; a deployment whose
  accountable operator differs from the resource owner MUST represent
  that operator separately and MUST NOT place it in the grant subject
  (Section 10.2).
* **Agent**: the AI agent presenting the token.  The Agent key is bound
  by `cnf` at presentation time.  In `representative` mode, the Agent
  is projected as the OAuth actor and MAY also be the OAuth client
  presenting the credential; in `authorized` mode, the Agent MAY
  occupy `sub` as the authorized accessor, consistent with the
  authorization-grant semantics of RFC 7523 Section 3, item 2A.
* **Issuer**: the CA (PKI mode) or OAuth authorization server (AS
  mode) that validates the DA JWT and signs the outer AIC-JWT.  The
  Principal is not the issuer of the outer AIC-JWT; the Principal
  signs only the DA JWT.
* **Verifier/Gateway**: the policy enforcement point that validates
  the AIC-JWT and its credential bundle and makes the access decision
  according to [AIC] and deployment policy.

The issuer's verification key is obtained from configured or otherwise
trusted JWKS/`x5c` material and MAY be cached.  The principal's
verification key is resolved from trusted JWKS material or, in PKI
deployments, from the credential bundle presented with the token.  Key
resolution does not by itself establish trust; the trust relationship
for the resolved key MUST be established by the deployment before the
DA is accepted.

## 3.2. Relationship to OAuth 2.0 Roles

| AIC-JWT role | OAuth projection |
|--------------|------------------|
| Principal | Resource Owner / `sub` in `representative` mode |
| Agent | `sub` in `authorized` mode; `act` in `representative` mode; MAY also be the OAuth client |
| Issuer | Authorization Server in AS mode |
| Verifier/Gateway | Resource Server / policy enforcement point |

In `representative` mode, the Principal is projected as the resource
owner and the Agent as the OAuth actor; the Agent MAY also be the
OAuth client presenting the credential.  In `authorized` mode, the
Agent is the authorized accessor and MAY occupy `sub`, consistent with
the RFC 7523 authorization-grant semantics (Section 3, item 2A).  RFC
7523 distinguishes this authorization-grant use from client
authentication, for which `sub` identifies the OAuth client.

AIC-JWT is a self-contained credential: the authorization claims and the
principal-signed DA travel inside the token.  Self-containment of the
credential does not imply offline self-contained verification
(Section 9.3).  This document does not define an RFC 9068 access-token
profile and does not modify RFC 8693.
Deployments MAY present AIC-JWT within existing OAuth flows (for
example, the DA as an RFC 7523 authorization grant) where their
deployment profile permits; conformance of such presentations to RFC
9068 or RFC 8693 is outside this specification.

The OAuth `act` claim identifies the executing Agent in the
`representative` projection; it is distinct from the audit actor
defined in Section 8.1, which identifies the Principal represented by
the Agent in `representative` mode.

## 3.3. Relationship to mTLS

AIC-JWT does not require mutual TLS (mTLS).  Sender binding MAY be
enforced at the application layer using the `cnf` claim (Section
5.1.1) and, where applicable, DPoP [RFC9449].  Where a deployment uses
mTLS, the verifier MAY additionally check that the mTLS client
certificate public key corresponds to the key identified by `cnf`, for
example by comparing the JWK thumbprint of the certificate public key
with the `jkt` member.  Whether and how mTLS is deployed is a
deployment decision and outside the scope of this specification; in
particular, offline handshake-time decisions remain the domain of the
X.509 AIC (mTLS) profile.

---

# 4. Token Structure

## 4.1. Nested JWS Construction

The AIC-JWT is a nested JWT in which the inner Delegation
Authorization (DA) JWT is carried as a claim value in an outer JWS.
The nested JWT model is defined by [RFC7519], and the signatures use
the JWS mechanisms defined by [RFC7515].

1. The principal creates the DA JWT (Section 5.2) and signs it with the
   principal's private key.
2. The agent or issuer constructs the outer payload (Section 5.1)
   containing the `da` claim whose value is the complete
   compact-serialized DA JWT string.
3. The issuer signs the outer payload, producing the AIC-JWT.

The outer JWS therefore provides integrity protection over the complete
DA JWT string as carried in the `da` claim.  Any modification of the
inner JWT -- including its JOSE header, payload, or signature -- changes
the outer payload and causes outer signature verification to fail.

The AIC-JWT uses the JWS compact serialization, as does the inner DA
JWT.

The `da` claim value MUST be processed as the exact compact-serialized
DA JWT string received in the outer payload.  A verifier MUST NOT
reconstruct or reserialize the DA JWT before performing inner JWS
signature verification.

## 4.2. Outer JOSE Header

The outer header MUST contain:

* `alg`: a JOSE algorithm permitted by Section 4.5.  The value `none`
  MUST NOT be used.
* `typ`: the string `aic+jwt`.
* `kid`: the identifier of the issuer's signing key, per [RFC7515]
  Section 4.1.4.

The outer header MAY contain `x5c` or `x5t` when the issuer's signing
key is represented by an X.509 certificate.  An `x5c` value MAY provide
the X.509 certificate chain needed for certificate-based key
validation; an `x5t` value identifies an X.509 certificate by its
thumbprint.  The presence of `x5c` or `x5t` MUST NOT by itself
establish trust; verifiers MUST validate the issuer key against their
configured trust policy.

## 4.3. Inner DA JOSE Header

The DA JWT header MUST contain:

* `alg`: a JOSE algorithm permitted by Section 4.5.
* `typ`: the string `aic+da+jwt`.
* `kid`: the identifier of the principal's signing key.

The DA JWT MUST NOT be accepted as a standalone AIC-JWT or access
token.  Verifiers operating in an AIC-JWT context MUST validate the
`typ` value and apply the DA-specific validation rules defined by this
specification.  The distinct `typ` value provides explicit JWT typing
and helps prevent cross-type token confusion.

## 4.4. PA JOSE Header

When the optional PA JWT (Section 5.3) is used, its header MUST
contain:

* `alg`: a JOSE algorithm permitted by Section 4.5.
* `typ`: the string `aic+pa+jwt`.
* `kid`: the identifier of the PA signing key.

In pure-JSON and OAuth deployments, the PA JWT is signed by the issuer
that attests the principal identity; in the AS mode of Section 10.2
this is the same issuer that signs the outer AIC-JWT.  In PKI
deployments the PrincipalAuthorization is carried in the principal's
X.509 certificate rather than as a PA JWT, and the PA JWT form is not
used.  Verifiers MUST validate the PA signing key and its trust
relationship before accepting the PA (Section 5.3).

## 4.5. Algorithm Allowlist

The following JOSE algorithms are permitted, mirroring the signature
algorithm policy of the X.509 AIC specification:

| JOSE `alg` | Requirement | X.509 counterpart |
|------------|-------------|-------------------|
| `ES256` | MUST | ECDSA P-256 with SHA-256 |
| `ES384` | MAY | ECDSA P-384 with SHA-384 |
| `ES512` | MAY | ECDSA P-521 with SHA-512 |
| `RS256` | MUST | RSA PKCS#1 v1.5 with SHA-256 |
| `RS384` | MAY | RSA PKCS#1 v1.5 with SHA-384 |
| `RS512` | MAY | RSA PKCS#1 v1.5 with SHA-512 |
| `PS256` | MAY | RSA-PSS with SHA-256 |
| `PS384` | MAY | RSA-PSS with SHA-384 |
| `PS512` | MAY | RSA-PSS with SHA-512 |
| `EdDSA` (Ed25519) | MAY | Ed25519 |

The allowlist is based on the algorithm set of the SPIFFE JWT-SVID
specification ([RFC7518] Sections 3.3-3.5), with EdDSA added so that
tokens can be verified by both JWT-SVID and AIC-JWT validators and by
Ed25519-based deployments.  Interoperable deployments SHOULD use ES256
or RS256.

Implementations MUST reject all other algorithms, including symmetric
MAC algorithms such as `HS256`.  Implementations MUST follow the JWT
Best Current Practices of [RFC8725]: the `alg` value MUST be validated
against the allowlist before signature verification, and the selected
verification key MUST be compatible with the declared algorithm and key
type.

The `kid` value is used only to select a candidate verification key
from a trusted and appropriately scoped key set.  A `kid` value MUST
NOT by itself establish trust.

---

# 5. Claims

## 5.1. Outer Claims

The outer payload is a JSON object.  AIC-specific claims are carried
inside the namespaced `aic` claim to avoid collisions with registered
JWT and OAuth claims.

### 5.1.1. Standard Claims

* `iss` (REQUIRED): the issuer identifier per [RFC7519].  Where the
  token is issued by an OAuth authorization server, the identifier
  SHOULD be a URL unique to that issuer per [RFC9207].
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
  intended resource servers or gateways.  Verification follows
  [RFC7519] audience semantics and the deployment's audience policy.
  Deployments that base decisions solely on capability evaluation MUST
  still include a deployment-scoped audience to prevent audience
  confusion.
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
  prevention and status lists.  This profile uses a one-DA-per-issued-
  token model: when a DA JWT is present, `jti` MUST equal the DA
  `nonce` (carried in the DA as `jti`), the nonce is consumed at first
  issuance, and it MUST NOT be reused for a second outer token.
* `cnf` (REQUIRED): a confirmation claim per [RFC7800] binding the
  token to the Agent's proof-of-possession key.  The `jkt` member
  ([RFC7638] thumbprint) is RECOMMENDED.  When DPoP [RFC9449] is used,
  the `jkt` member MUST match the DPoP proof key thumbprint.  Where a
  deployment uses mTLS, the verifier MAY cross-check the mTLS client
  certificate key against `cnf` (Section 3.3).  In this revision the
  principal-signed DA binds the delegated authorization to the Agent
  identity (`agent_id`); a DA-level binding of the Agent key
  (requiring the key identified by `cnf` to match a DA agent-key
  binding) is reserved for a future DA claim-set revision aligned with
  the X.509 AIC DA v2.
* `scope` (OPTIONAL): an OAuth scope string projection of the
  capabilities, for interoperability with generic OAuth resource
  servers.  The `aic.capabilities` claim remains the canonical
  authorization input.
* `client_id` (OPTIONAL): the OAuth client identifier, present when
  the token is issued in OAuth AS mode.
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
(Section 11).

## 5.2. DA JWT Payload

The DA JWT payload carries the principal-signed delegation
authorization content defined by [AIC]; it is the JWT counterpart of
the X.509 DelegationAuthTBS signing structure, not a byte-level
encoding of it.  In addition to the AIC members below, every DA JWT
MUST carry the RFC 7523 claims `iss`, `sub`, `aud`, `exp` and `jti`:

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
  `da.ver` is the DA claim-set version and is distinct from `aic.ver`
  (the AIC-JWT profile version).
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
* `principal` (REQUIRED): MUST equal the outer `aic.principal`.  The
  key used to verify the DA JWT signature MUST correspond to the
  principal key identified by `principal.key_hash` and
  `principal.hash_alg`.
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
* `nonce` (REQUIRED): the unpadded base64url encoding of exactly 32
  octets from a CSPRNG, used for replay prevention.  The issuer MUST
  check uniqueness and persist used nonces.

The signing input is the UTF-8 encoding of the JWS payload as defined
by RFC 7515 (that is, the payload is not a DER encoding; JSON field
order in the signed payload is the order produced by the JWS
serialization and MUST be preserved as signed).

## 5.3. PA JWT Payload

The optional PA JWT carries the JSON representation of the
PrincipalAuthorization extension defined by [AIC].  It is REQUIRED in
`representative` mode when no principal X.509 certificate with the
PrincipalAuthorization extension is present in the bundle.

In pure-JSON and OAuth deployments, the PA JWT MUST be signed by the
issuer that attests the principal identity; in the AS mode of Section
10.2 this is the same issuer that signs the outer AIC-JWT, and the PA
JOSE header `kid` (Section 4.4) identifies that signing key.  In PKI
deployments the PrincipalAuthorization is carried in the principal's
X.509 certificate, and the PA JWT form is not used:

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
  characters.  The scheme is the namespace that defines the semantics
  of the capability, including identifier matching and parameter
  subset rules.  The `scheme` value MUST be matched exactly; wildcards
  MUST NOT be used in the `scheme` member, and a capability with
  `scheme="*"` MUST NOT be used (a bare `*` is not a cross-scheme
  capability).  Unknown schemes MUST be rejected unless the verifier
  has an explicit scheme-specific implementation or plugin for that
  scheme (fail-closed).
* `id` (REQUIRED): the capability identifier within the scheme, 1 to
  256 characters.  The syntax and matching semantics of `id` are
  defined by the capability scheme; the HTTP-style examples in this
  section use the identifier matching rules of Section 6.2.
* `params` (OPTIONAL): a JSON value (object, array, string, number, or
  boolean) whose semantics are defined by the scheme.  When serialized,
  `params` MUST NOT exceed 512 bytes.

The Capability object is the unified container reused in three
contexts: `aic.capabilities`, `aic.constraints`, and PA `grants`.
Although the container is the same, the authorization role of each
context is defined by the AIC semantic model; reuse does not imply
semantic equivalence.

Capability matching and parameter-subset evaluation define the
effective AIC authorization input; they are not the final execution
decision of a resource server or gateway.  Deployment-local execution
policy is outside the AIC-JWT credential.

## 6.2. Identifier Matching

For schemes that use the HTTP-style capability syntax, the matchable
identifier is the full identifier `scheme + ":" + id` (for example,
`http:GET:/api/v1/users`).  The `scheme` member is the exact first
component of the full identifier and MUST NOT be wildcarded; the glob
operators below apply to the `id` portion after the scheme prefix.

| Pattern | Meaning | Example |
|---------|---------|---------|
| `http:GET:/api/v1/users` | exact | `http:GET:/api/v1/users` |
| `http:GET:/api/v1/*` | single path segment (no `/`) | `http:GET:/api/v1/users` |
| `http:GET:/api/v1/**` | one or more path segments | `http:GET:/api/v1/users/admin` |
| `http:{GET,POST}:/api/*` | alternation within a segment | `http:GET:/api/users` |
| `http:[A-Z]*:/api/*` | character class and embedded wildcard | `http:GET:/api/users` |
| `http:*:/api/v1/*` | wildcard method position | `http:GET:/api/v1/users` |

A scheme-level wildcard (`scheme:*`) MUST NOT be used; `scheme` is
always exact.  A bare `*` without a scheme prefix MUST NOT be
interpreted as a cross-scheme capability.

The full identifier is matched as a two-level token stream: the
pattern and target are first split on `:` into the scheme and id
components, and each id component is then split on `/`.  `*` matches
exactly one path segment that does not contain `/` (or one
colon-segment in the method position), while `**` matches one or more
segments and MAY cross `/` boundaries.  Within a literal segment,
`{a,b}` alternation matches one of the alternatives and `[a-z]`
character classes match a single character in the class; an embedded
`*` matches any characters within the segment (for example,
`[A-Z]*`).

Precedence is limited to specificity: literal segments are more
specific than `*`, and `*` is more specific than `**`.  Alternation
and character classes are per-segment matching operators and do not
by themselves define an authorization precedence.  If more than one
capability pattern matches, the scheme defines whether and how the
matching entries combine, and the result MUST be deterministic.  If no
capability grant matches the requested capability, the capability MUST
be denied.

The exact syntax, escaping rules, and matching algorithm for a given
capability scheme are defined by that scheme; the HTTP-style rules in
this section MUST NOT be assumed for an unknown or unrelated scheme.
This algorithm is verified by the reference implementations (Go and
TypeScript/WebCrypto) against the examples in this section.

## 6.3. Capability Subset and Parameter Semantics

Authorization between a principal grant and an agent capability is a
subset relation:

    C_agent <= P_grant

meaning the agent capability is within the authority granted by the
principal grant.  The definition of this relation is scheme-specific:
a capability scheme MUST define how identifiers and `params` are
compared and what constitutes a valid subset.

For example, an HTTP-style scheme MAY treat
`P_grant.params.max_rows = 1000` and `C_agent.params.max_rows = 100`
as a valid subset (`100 <= 1000`), and `max_rows = 5000` as invalid.

If `C_agent.params` is not a valid subset of `P_grants.params` under
the scheme-defined relation, the credential MUST be rejected; a
verifier MUST NOT silently filter or rewrite the signed agent
capability.  Where the subset relation holds, the effective parameter
value is the agent value (which is at least as restrictive as the
grant), evaluated according to scheme semantics.

This specification does not define a universal ordering or
intersection operation over arbitrary JSON values; scheme-specific
implementations MUST define subset semantics for every parameter type
they support.

The effective AIC authorization is obtained by evaluating agent
capabilities against principal grants and the applicable AIC
authorization constraints (Section 7).  The final execution decision
MAY additionally be restricted by deployment-local gateway or
resource-server policy, which is outside the AIC-JWT credential.

---

# 7. Authorization Constraints

`aic.constraints` is an optional array of Capability objects whose
`scheme` MUST be `varwof/constraint-v1`; other scheme values MUST be
rejected.  Within that scheme, `id` names the constraint type and
`params` carries constraint-specific parameters.  This revision
defines the following constraint types as the initial set of the
`varwof/constraint-v1` scheme; new types are added within this scheme
namespace, and incompatible semantics require a new scheme version
(e.g., `varwof/constraint-v2`) rather than a change to `id` alone:

| `id` | `params` format | Description |
|------|-----------------|-------------|
| `allowed-cidr` | `["10.0.0.0/8", "192.168.0.0/16"]` | Allowed IP ranges |
| `max-concurrent` | `{"max": 5}` | Maximum concurrent agent instances |
| `time-window` | `{"start": "22:00", "end": "06:00"}` | Allowed execution window (UTC) |

Constraints are evaluated with logical AND: all constraints MUST be
satisfied.  The constraint count MUST NOT exceed 32.  Unknown
constraint types MUST be rejected: a verifier that cannot interpret a
constraint cannot establish that the constraint is satisfied.
Forward-compatible extension is achieved through explicit scheme
versioning and type registration, not by ignoring unknown security
constraints.

Constraint semantics that depend on evaluation scope or time MUST be
unambiguous.  For `max-concurrent`, the default scope is the number of
concurrent executions of the agent identified by this credential at
the evaluating verifier; a deployment MAY define a different scope
(per principal, per DA, or deployment-wide) and MUST document it.  For
`time-window`, times are expressed in UTC at minute precision; when
`start > end` the window crosses midnight, and `start == end` denotes
a full 24-hour window.

`aic.constraints` are credential-bound authorization constraints
carried with the token; they are not deployment-local execution
policy.  PA `constraints` are principal-level authorization
boundaries.  The two are evaluated independently; there is no subset
relationship between them.

Runtime policy (timeouts, retries, rate limits, routing) MUST NOT be
placed in `authorizationConstraints`; it remains in gateway local
policy configuration.  The authorization layers are therefore:

```
P_aic = P_grants (AND) C_agent
Permit_AIC(request) = CapabilityMatch(request, P_aic)
                      (AND) ConstraintsSatisfied(request, aic.constraints)
Permit(request) = Permit_AIC(request)
                  (AND) GatewayPolicy(request, T_policy)
```

where `T_policy` is the deployment-local gateway or resource-server
policy.

---

# 8. Delegation Model

## 8.1. Delegation Modes

**authorized** (default): the Agent acts in its own name.  The audit
log records `sub` (agentId) as the actor and `aic.principal.id` as the
authorizing principal.  The effective capability set is established at issuance and
cryptographically bound to the credential; unless a deployment
explicitly requires dynamic grant evaluation, the verifier does not
re-fetch or re-evaluate the principal's grants for each operation.
Narrow scope x longer lifetime (up to 24 hours with renewed DA on
renewal).

**representative**: the Agent acts in the principal's name.  The audit
log records `aic.principal.id` as the actor and `act.sub` (the
agentId) as the executor.  The bundle MUST contain the principal's PA
material.  At issuance and at runtime, `C_agent` MUST be a subset of the
principal's current grants `P_grants(t)`.  Wide scope x short
lifetime, with runtime `P_grants(t)` intersection at each operation.

## 8.2. Permission Intersection

The effective AIC authority is the intersection of principal grants
and agent capabilities, further restricted by the token's AIC
constraints:

```
P_aic = P_grants (AND) C_agent
Permit_AIC(request) = CapabilityMatch(request, P_aic)
                      (AND) ConstraintsSatisfied(request, aic.constraints)
```

In `authorized` mode the intersection is established at issuance
(`P_grants(t0)`) and locked into the token.  In `representative` mode
the intersection is computed at runtime against the principal's
current grants `P_grants(t)` for each operation.  Gateway local
runtime policy (`T_policy`) is an additional enforcement layer and
MUST NOT be confused with the AIC authorization layers:

```
Permit(request) = Permit_AIC(request) (AND) GatewayPolicy(request, T_policy)
```

## 8.3. Multi-level Delegation

Single-level delegation (Principal -> Agent, `chain_depth=0`) MUST be
supported and is the default.  Depth-1 chains (Principal -> Agent ->
sub-Agent, `chain_depth=1`) MAY be supported.  Multi-level delegation
requires an explicit delegation authority at each delegating level:
an agent may delegate only if the DA that authorized it carries an
explicit right to delegate (for example, a may-delegate capability or
a delegation-policy allowance with an explicit depth bound); an agent
without that right MUST NOT sign a DA for a sub-agent.

Each hop in a supported chain produces an independently signed DA JWT.
The signer of a hop is the delegating agent; the original principal
remains the root authorizing party and MUST be identified separately
from the hop signer (delegator vs. delegate vs. root principal).  The
delegator's own DA MUST record the delegation right and the current
`chain_depth`; capabilities are recursively narrowed along the chain.
Verification of a hop MUST establish all of the following: the hop
signer holds an explicit delegation authority; the delegated
capabilities are a subset of the delegator's effective capabilities;
`chain_depth` increases by exactly one per hop; and `chain_depth` does
not exceed `max_depth`.  Cycles are prevented by strictly monotonic
`chain_depth`.  Deployments SHOULD use `max_depth = 1`; larger values
MAY be supported only with equivalent chain-size, capability-
narrowing, and resource limits.  A sub-agent at the configured
`max_depth` MUST NOT delegate further.  Credential bomb attacks are
limited by a gateway-configured maximum bundle size (default 8
certificates or equivalent tokens).

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
  `hash_alg` defaulting to SHA-256.  The default binding is SHA-256
  over the DER-encoded SPKI; additional hash algorithms MAY be
  specified by the AIC registry.
* JWK thumbprint: `key_hash = jkt` per RFC 7638, `hash_alg = "jkt"`.
  The value `jkt` denotes the RFC 7638 JWK Thumbprint binding method
  (computed with SHA-256 over the canonical JWK members); it is not
  itself a hash algorithm name.

Mismatch MUST cause rejection (fail-closed).  A successful binding
check does not by itself establish trust in the Principal; the
resolved key MUST also satisfy the verifier's configured trust
policy.  The same SPKI-hash design rationale as the X.509 profile
applies: certificate renewal with
the same key pair preserves the binding; key rotation invalidates all
existing delegations without broadcast revocation.

## 9.3. Cached Verification and Disconnected Deployments

AIC-JWT is designed primarily for application-layer verification with
online or cached trust and status information; it does not claim
offline self-contained verification (that property belongs to the
X.509 AIC profile and its credential bundle).  In air-gapped
deployments that still use
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
exclusively.  When the originating credential is X.509-based, a
trusted server-side component MAY perform the X.509-to-JWK conversion
before key material reaches the browser.

---

# 10. Issuance Flows

## 10.1. PKI Mode

In PKI mode the DA is presented to a CA rather than redeemed at an
authorization server: `aud` (Section 5.2) identifies the configured
AIC issuance service that is authorized to accept the DA, and the CA
validates it when configured.

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

Where a DA-level Agent key binding is present (a future DA claim-set
revision aligned with the X.509 AIC DA v2), the CA MUST verify that
the key identified by `cnf` matches that binding before signing; in
this revision the presented Agent key is bound by `cnf` at
consumption time.

## 10.2. OAuth Authorization Server Mode

1. The principal provides consent through an applicable OAuth
   authorization or delegation flow (for example, an authorization-code
   flow combined with a deployment-specific actor/delegation
   mechanism, or an OBO-style flow).
2. The Agent presents the principal-signed DA JWT with the token
   request as an [RFC7523] authorization grant
   (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, the DA
   JWT as the `assertion` parameter).  A `scope` parameter MAY
   accompany the grant but MUST NOT extend the capabilities carried in
   the DA JWT.  Client authentication at the token endpoint follows
   standard OAuth 2.0 practice and is outside this specification.
3. The AS validates the DA JWT under both the JWT bearer assertion
   requirements of RFC 7523 (signature, `iss`, `aud`, and expiry) and
   the AIC-JWT DA rules of Section 5.2: `exp` MUST equal
   `ts + requested_lifetime` and MUST NOT have passed (subject to
   configured clock skew); the DA identifier (`jti`/`nonce`) MUST be
   unique within the configured replay-detection window; and the
   per-mode `sub` rules of Section 5.2 apply.  It then
   issues the outer AIC-JWT signed with the AS key, with `exp` bounded
   per Section 5.1.1 and role placement per Section 3.2.  An AS MAY
   require the DA `sub` to equal the subject identifier it registers
   for the resource owner, verifying the mapping from the principal
   binding before issuance.
4. The AS MAY expose a JWKS endpoint and Token Status List [TSL] for
   verification and revocation.

The AS MUST NOT sign the outer token without a valid principal-signed
DA JWT (full profile), preserving the two-layer trust model.  Where a
DA-level Agent key binding is present (a future DA claim-set revision
aligned with the X.509 AIC DA v2), the AS MUST verify that the key
identified by `cnf` matches that binding before signing; in this
revision the presented Agent key is bound by `cnf` at consumption
time.

If the DA JWT is invalid or cannot be validated, the AS MUST return
the `invalid_grant` error as required by RFC 7523 Section 3.1.

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

The lightweight profile does not provide the cryptographic principal
authorization attestation of the full profile; its trust depends on
the issuer's authenticated consent-recording process.  A token
without a `da` claim is valid only under this profile and MUST NOT be
accepted under full-profile validation, which requires the `da` claim
(Section 5.1.3).

## 10.4. Token Exchange Usage

This section is informative.  Deployments that already use [RFC8693]
MAY carry an AIC-JWT as an actor or subject token.  Role mapping
follows RFC 8693; AIC claims are carried in the token unchanged.  This
specification does not alter RFC 8693 semantics and does not define an
RFC 8693 profile for AIC-JWT.

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

**Mode C - PKI (X.509) mode.**  The X.509 AIC profile with mTLS is
used as the primary carrier; an AIC-JWT MAY still be generated as an
application-layer representation when an application protocol requires
it (Section 10.6).

## 10.6. X.509 AIC Interoperability

When the same authorization is carried in both profiles, the following
equivalences apply:

* key binding: `aic.principal.key_hash` with a SHA-2 `hash_alg`
  (SPKI hash) and the [RFC7638] JWK thumbprint of the same key are two
  interoperable representations of a public key binding for the same
  underlying key; a helper MAY convert a presented X.509 certificate
  to a JWK and a verifier MAY accept either form;
* DelegationAuthorization: the ASN.1 DelegationAuthTBS and the DA JWT
  payload carry the AIC DelegationAuthorization semantic fields
  defined by [AIC]; the DA JWT additionally carries the RFC 7523
  claims `iss`, `sub`, `aud`, `exp`, `iat`, and `jti`, which have no
  ASN.1 counterpart in the X.509 profile.  A PKI helper MAY translate
  between the two for issuance, verification, or audit;
* PrincipalAuthorization: the ASN.1 extension and the PA JWT carry the
  same grants, constraints, and delegation policy;
* issuance: a server-side helper MAY accept an X.509 AIC credential
  bundle and issue the equivalent AIC-JWT (Mode B), so that the same
  authorization semantics can be enforced at the transport layer
  (mTLS) and at the application layer (Bearer).

Interoperability between the two profiles is a deployment mechanism,
not a new token format; both profiles share the data model defined by
[AIC].

---

# 11. Validation Pipeline

The verifier/gateway MUST execute the following steps in order after
receiving the AIC-JWT and bundle:

1. **Header checks**: validate `typ == "aic+jwt"`, `alg` in the
   deployment allowlist, and reject `none` and symmetric algorithms
   (RFC 8725).  The verifier MUST NOT select a cryptographic
   verification method based on an algorithm value outside the
   allowlist.
2. **JWS verification**: resolve the issuer's verification key from
   `kid` (JWKS or `x5c`) and verify the outer JWS signature per RFC
   7515 using the confirmed algorithm.  When `x5c` is present, the
   certificate chain MUST be validated against the verifier's
   configured trust policy and the resulting public key MUST
   correspond to the expected AIC issuer; a certificate carried in
   `x5c` does not by itself establish trust.
3. **Time checks**: `nbf <= now <= exp` (with deployment-configured
   clock skew); `exp - iat <= requested_lifetime` and
   `requested_lifetime <= 86400`.  The outer AIC-JWT MAY have a
   shorter effective lifetime than the DA.
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
7. **Delegation depth check**: verify `chain_depth <= max_depth`
   and, for multi-level chains (Section 8.3), that depth increases by
   exactly one per hop and that each hop's delegated capabilities are
   a subset of the delegator's effective capabilities:
   `C_n <= C_(n-1) <= ... <= P_grants`.  No hop may expand authority.
8. **Constraint evaluation**: the effective constraint set is the
   conjunction of all applicable `aic.constraints` and, in
   `representative` mode, PA constraints; a request MUST satisfy
   every applicable constraint.  Constraint evaluation precedes
   capability evaluation for fast rejection.
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

Verification MUST NOT expand any authorization property.  In
particular: effective capabilities are a subset of the principal
grants (and of each delegator's capabilities in a chain); effective
expiry does not exceed the DA `exp` or the deployment's maximum
lifetime; `chain_depth` does not exceed `max_depth`; and every
applicable constraint is satisfied.

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
  "jti": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
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
  "jti": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
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
  "nonce": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
}
```

---

# 13. Security Considerations

## 13.1. Algorithm Confusion

Follow [RFC8725]: validate the `alg` allowlist, resolve `kid` to the
expected key, reject `none` and symmetric algorithms, and reject
unexpected `typ` values.  AIC-JWT MUST always be asymmetric.

## 13.2. Token Theft and Replay

AIC-JWT is not inherently sender-constrained: in a deployment that
does not enforce proof of possession, a party in possession of the
token can use it as a bearer credential until expiry.  Deployments
MUST use TLS.  The token MUST carry `cnf` binding it to the Agent
key, and deployments SHOULD additionally use DPoP [RFC9449] (or an
equivalent proof-of-possession mechanism) to prevent token theft and
replay.  Where higher assurance is required, the AS MAY challenge the principal with step-up authentication [RFC9470] before issuing or refreshing tokens.  Where mTLS is deployed, the verifier MAY cross-check the mTLS
client certificate key against `cnf` (Section 3.3).  Replay is
additionally bounded by the DA `nonce`/`jti` uniqueness check at
issuance and by the short lifetime.  The nonce is a signed input of the
DA JWT, not a plaintext parameter.

## 13.3. Audience Confusion

The `aud` claim MUST be validated per [RFC7519] and the deployment's
audience policy.  Issuers MUST use distinct issuer identifiers per
trust domain (RFC 9207) so that a token issued by one AS cannot be
accepted by another.

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
  attacker still cannot forge a principal-signed DA JWT.  A
  compromised issuer could re-issue an outer token with a different
  `cnf` key; DA-level Agent key binding (a future DA claim-set
  revision) closes this gap, and deployments that require
  principal-to-key binding MUST constrain issuance policy accordingly
  until that binding is available.

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
| members of the DA JWT payload | AIC delegation fields plus the RFC 7523 claims `iss`, `sub`, `aud`, `exp`, `iat`, `jti` |
| members of the PA JWT payload | PrincipalAuthorization fields |

Members of the DA and PA JWT payloads are namespaced member names
carried inside those JWTs; they are not registered as standalone
top-level JWT claims.

## 15.3. OAuth Token Type URN

This document does not request registration of an OAuth token type
URN.

## 15.4. OAuth Authorization Server Metadata

This document does not request any OAuth Authorization Server
Metadata entries.

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
Extension", draft-wei-aic-identity-cert-01, August 2026.

---

# 17. Informative References

[DAAP] Kumar, S., "Delegated Agent Authorization Protocol (DAAP)",
draft-mishra-oauth-agent-grants-01, March 2026.

[OBO] Dissanayaka, A., "OAuth 2.0 Extension: On-Behalf-Of User
Authorization for AI Agents", draft-oauth-ai-agents-on-behalf-of-
user-02, August 2025.

[ATN] Somoza, J., "ATN Agent Trust Negotiation",
draft-somoza-atn-agent-trust-negotiation-01, May 2026.

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
* the AIC-JWT `iss` is the issuer identifier per [RFC7519] (in OAuth
  AS deployments, the OAuth issuer URL); JWT-SVID
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
  RSA-PSS coverage with feature detection.  Test suites pass: the
  TypeScript unit suite (node --test ts/aicjwt.test.ts), the demo
  scenario suite (npm test), and tsc --noEmit for the TypeScript
  sources; the Go suites also pass under go test -race.

The Go core is maintained in github.com/varwof/types (package
types/aicjwt); the wrapper, OAuth protocol-layer simulation, and the
TypeScript/WebCrypto implementation are in
https://github.com/varwof/aic-jwt/.  Findings verified by these
implementations are incorporated in Sections 6.2, 9.4, 10.5, 10.6,
11, and 13.8.

Release state (2026-09-06): the RFC 7523 claims/role model defined by
this revision (DA ver=2) is implemented in the types release v0.5.2
(https://github.com/varwof/types/tree/v0.5.2) and the aic-jwt
repository
(https://github.com/varwof/aic-jwt/).
Earlier revisions of this draft pinned the types v0.3.1 release.

---

# Acknowledgements

The author thanks the IETF community for ongoing discussion of agent
identity and accountability frameworks.

# Change Log

draft-wei-aic-jwt-01 (2026-09-05; revised 2026-09-08):

* The DA JWT carries the RFC 7523 claims `iss`, `sub`, `aud`,
  `exp` and `jti` (jti = nonce; exp = ts + requested_lifetime),
  making the Section 10.2 jwt-bearer presentation interoperable
  (resolves review by I. Schrock, OAuth WG, 2026-09-04).
* Role placement is mode-dependent: representative mode places the
  resource owner / principal in `sub` and the agent in `act` (RFC
  8693 actor / OAuth client); authorized mode places the agent in
  `sub` as the authorized accessor (RFC 7523 Section 3, item 2A).
  The X.509 convention that the certificate subject is the agent is
  retained in authorized mode only and stated as such (resolves
  review by J. Lombardo, OAuth WG, 2026-09-04).
* A deployment whose accountable operator differs from the resource
  owner MUST represent the operator separately; recorded as future
  work.
* DA `ver` bumped to 2 for the -01 claim set; `ver=1` is the -00
  shape and is rejected, making the schema break explicit.
* Positioning tightened (2026-09-08): AIC-JWT is the JWT carrier of
  the AIC semantic model; the document does not define an RFC 9068
  access-token profile, does not modify RFC 8693, and does not
  redefine AIC semantics.  The DA JWT is carried as the value of the
  top-level `da` claim (Section 5.1.3).
* OAuth scope trimmed (2026-09-08): RFC 7523 authorization-grant
  presentation is the only normative OAuth consumption profile;
  RFC 8693, DPoP, Token Status Lists, RFC 9068 and related
  mechanisms are deployment-specific; client-assertion presentation
  was removed; OAuth token type URN and Authorization Server
  Metadata registrations are no longer requested; the token-exchange
  section is informative; error handling at the token endpoint
  follows RFC 7523 Section 3.1 (`invalid_grant`).
* PA signing decided (2026-09-08): in pure-JSON/OAuth deployments
  the PA JWT is signed by the issuer that attests the principal
  identity; in PKI deployments the PrincipalAuthorization is carried
  in the principal's X.509 certificate.
* Validation and constraints tightened (2026-09-08): header checks
  precede JWS verification; unknown constraint types MUST be
  rejected; capability subset semantics are scheme-defined;
  multi-level delegation requires an explicit delegation authority;
  the DA nonce is the unpadded base64url encoding of exactly 32
  octets; examples corrected accordingly.
* Wording alignment (2026-09-08): clarified that AIC-JWT is not
  inherently sender-constrained and requires an enforced
  proof-of-possession mechanism for sender binding (Section 13.2);
  constraint types in Section 7 are described as the initial defined
  set rather than examples; "self-contained credential" is qualified
  to distinguish token-carried authorization claims from offline
  self-contained verification (Sections 3.2 and 9.3).

* Reference implementations (Go and TypeScript/WebCrypto) updated
  with regression tests for the claims and role model above.

draft-wei-aic-jwt-00 (2026-08-24):

* Initial individual submission.  Established AIC-JWT as the JWT
  application-layer representation of the AIC X.509 model: an
  issuer-signed outer token carrying a principal-signed DA JWT,
  capability and constraint containers, RFC 7523 authorization-grant
  presentation, DA nonce replay controls, deployment architectures,
  and projections to SPIFFE JWT-SVID and RFC 9068 views (including
  the SPIFFE-aligned algorithm allowlist and `typ` projection rules).
