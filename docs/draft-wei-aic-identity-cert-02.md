---
title: AI Agent Identity Certificate (AIC) Extension for X.509 v3
abbrev: AIC Certificate
docname: draft-wei-aic-identity-cert-02
category: exp
submissiontype: independent
stream: independent
ipr: trust200902
keyword:
  - AI Agent
  - X.509
  - Certificate
  - Identity
  - PKI
  - Accountability
  - Delegation
workgroup: Network Working Group

author:
  -
    ins: J. Wei
    name: Jijie Wei
    organization: Individual
    email: pki@varwof.com
    uri: https://varwof.com

normative:
  RFC5280:
  RFC2119:
  RFC8174:
  RFC4648:
  RFC5912:
  RFC6960:
  RFC7633:

informative:
  RFC6749:
  RFC7942:
  RFC9846:
  RFC3820:
  RFC5755:
  SPIFFE:
    title: SPIFFE Standard
    author:
      -
        ins: SPIFFE Community
        name: SPIFFE Community
    date: 2022-05
    target: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md
  AGTP:
    title: AGTP Agent Certificate Extension
    author:
      -
        ins: C. Hood
        name: C. Hood
        org: Nomotic, Inc.
    date: 2026-06-28
    target: https://datatracker.ietf.org/doc/draft-hood-agtp-agent-cert/
  APKI:
    title: "Agent Public Key Infrastructure (APKI): Certificate-Based Identity and Trust for Autonomous AI Agents"
    author:
      -
        ins: R. Sharif
        name: R. Sharif
        org: CyberSecAI Ltd
    date: 2026-04-10
    target: https://datatracker.ietf.org/doc/draft-sharif-apki-agent-pki/
  AgentIdentity:
    title: X.509 Certificate Profile for Autonomous AI Agent Identity
    author:
      -
        ins: R. Sharif
        name: R. Sharif
        org: CyberSecAI Ltd
    date: 2026-07-31
    target: https://datatracker.ietf.org/doc/draft-sharif-x509-agent-identity-profile/
  DAAP:
    title: Delegated Agent Authorization Protocol (DAAP)
    author:
      -
        ins: S. Kumar
        name: S. Kumar
        org: Grantex
    date: 2026-03-02
    target: https://datatracker.ietf.org/doc/draft-mishra-oauth-agent-grants/
  AIP:
    title: "Agent Identity Protocol (AIP): Decentralized Identity and Delegation for AI Agents"
    author:
      -
        ins: P. Singla
        name: P. Singla
        org: Independent
    date: 2026-06-10
    target: https://datatracker.ietf.org/doc/draft-singla-agent-identity-protocol/
  OpenA2A-AIP:
    title: "OpenA2A Agent Identity Protocol"
    author:
      -
        ins: A. Fane
        name: A. Fane
        org: OpenA2A
    date: 2026-08-06
    target: https://datatracker.ietf.org/doc/draft-fane-opena2a-aip/
  CapabilityBound:
    title: "Governing Dynamic Capabilities: Cryptographic Binding and Reproducibility Verification for AI Agent Tool Use"
    author:
      -
        ins: Z. Zhou
        name: Ziling Zhou
    date: 2026-03-19
    target: https://arxiv.org/abs/2603.14332
  AIC-JWT:
    title: "AI Agent Identity Certificate (AIC) JSON Web Token Profile"
    author:
      -
        ins: J. Wei
        name: Jijie Wei
    date: 2026-09
    target: https://datatracker.ietf.org/doc/draft-wei-aic-jwt/
  CLC:
    title: Capability Language Core
    author:
      -
        ins: J. Wei
        name: Jijie Wei
    date: 2026-09
    target: https://datatracker.ietf.org/doc/draft-wei-capability-language-core/

--- abstract

This document defines the AI Agent Identity Certificate (AIC) Extension
for X.509 v3 certificates. The AIC extension enables binding of an AI
Agent's cryptographic identity to a natural person (principal),
providing cryptographic evidence that can support attribution of
AI-autonomous actions to a principal. This
specification intentionally separates cryptographic delegation from
authorization semantics: AIC defines the cryptographic binding between
agent and principal, while all capability and policy semantics are
defined externally by vendors, industries, or regulators. The extension
is identified by the IANA Private Enterprise Number 66257
assigned to the document author's organization.

The AIC extension carries agent identity fields (agentId,
delegationMode), a principal identifier (principalUid) linking the
agent to the authorizing principal, a container-based
capability declaration, authorization boundary constraints, and
delegation authorization evidence with replay protection. A companion
PrincipalAuthorization extension anchors Principal-side grant
declarations and delegation policies. An authorizationConstraints
container provides offline-verifiable execution boundaries (IP range,
window). An extensibility framework allows vendor-specific and
user-specific metadata.

This document specifies the ASN.1 module, OID registration, field
semantics, delegation model, and extensibility framework. Security
considerations for deployment in regulated enterprise environments
are discussed.

--- middle

# Introduction

## Problem Statement

Existing X.509 public key certificates, as profiled in [RFC5280],
primarily authenticate identity through a cryptographically signed
binding between a distinguished name and a public key. Authorization
is intentionally left outside the certificate: relying parties
perform access control via external IAM policies, OAuth scopes, RBAC
databases, or policy engines evaluated after TLS connection
establishment.

Autonomous AI agents introduce a new requirement that existing
certificate profiles do not address. When an agent acts on behalf
of a principal, the relying party needs answers to additional
questions:

* Who delegated this authority?
* What operations are authorized?
* Under what constraints may the agent operate?
* How long is the authorization valid?
* Who remains accountable for the actions performed?

These questions cannot be answered by identity alone. They require a
standardized mechanism to express delegation relationships, capability
constraints, authorization boundaries, and accountability chains
within the certificate itself.

This document defines an X.509 certificate extension that addresses
this gap. The AI Agent Identity Certificate (AIC) extension encodes
agent identity, principal binding, capability declarations, delegation
modality, authorization boundary constraints, and cryptographic
delegation authorization within a single certificate. A companion
PrincipalAuthorization extension anchors principal-side grant
declarations, authorization constraints, and delegation policies.

AIC is designed to complement existing identity infrastructure:

* **SPIFFE/WIMSE** identifies workloads via SAN URIs. AIC adds
  capability containers, principal binding, and session control on
  top of workload identity.
* **OAuth 2.0 and JWT-based authorization** ([RFC6749]) provides
  online token exchange. AIC enables offline authorization decisions
  during the TLS handshake, without external identity provider
  lookups.
* **Standard X.509 extensions** (Certificate Policies, Extended Key
  Usage) express intended use but not delegation relationships or
  fine-grained capability constraints.

AIC is intended for deployments where:

* AIC is intended to support deployments that reuse existing PKI
  infrastructure (enterprise CAs, HSMs, smart cards);
* Emerging regulatory frameworks require cryptographic traceability
  of autonomous actions to accountable principals;
* Offline or air-gapped environments require self-contained
  certificate authorization without external database lookups;
* Short-lived workload identities need to be augmented with legal
  accountability metadata.

This document specifies the data model, certificate profile, and
validation requirements for AIC. Deployment-specific policy,
implementation details, and performance characteristics are outside
the scope of this specification.

## Scope

This document is organized into three categories:

**Normative (Core):** The following sections are normative: Delegation
Model, Certificate Profile (Data Model), AIC Extension Definition,
Validation Procedure, and PrincipalAuthorization Extension, including
their ASN.1 definitions. Implementations MUST conform to these
sections to claim AIC compliance.

**Informative (Profile):** The Deployment Models section describes
recommended deployment patterns and gateway behavior. These are not
required for AIC compliance but represent best practices.

**Informative (Reference):** The Implementation Status section
describes a reference implementation. These are provided as
implementation guidance and interoperability examples.

The core normative content intentionally separates cryptographic
delegation from authorization semantics: AIC defines the cryptographic
binding between agent and principal, while capability and policy
semantics are defined externally.

~~~text
                     AIC Architecture

   +----------------+      +------------------+
   |   Principal    |      |      Agent       |
   | (User/Org)     |      | (AI Agent)       |
   | PrincipalAuth  |      | AIC Certificate  |
   | Certificate    |      | Identity +       |
   |                |      | Capabilities +   |
   +-------+--------+      | Delegation Mode  |
           |               +--------+---------+
           | Authorization           |
           | signature               |
           +-------+-----------------+
                   |
                   v
         +---------------------+
         |    Gateway (PEP)    |
         |  1. Verify Chain    |
         |  2. Parse AIC       |
         |  3. Verify DA       |
         |  4. Check PA constr |
         |  5. Check AIC constr|
         |  6. Check Caps      |
         |  7. Apply Policy    |
         |  8. Decision        |
         +---------+-----------+
                   |
         +---------v-----------+
         |     Target          |
         |   Resource / API    |
         +---------------------+
~~~

## Design Principles

This specification is guided by seven orthogonal concerns, each
addressed by a distinct layer:

| Concern | Layer | Question |
|---------|-------|----------|
| Identity | AgentIdentity | "Who are you?" |
| Authorization | PrincipalAuthorization | "Who authorizes you?" |
| Capability | Capability (Container) | "What are you allowed to do?" |
| Delegation | DelegationPolicy | "How are you allowed to act?" |
| Constraints | authorizationConstraints | "Under what boundaries?" |
| Enforcement | Gateway | "Is this request allowed now?" |
| Trust | X.509 (PKI) | "Is this certificate trustworthy?" |
| Transport | TLS | "Is this channel secure?" |

AIC does not redefine trust, transport, or cryptography. It
complements X.509 by introducing three orthogonal concepts: Agent
Identity, Principal Authorization, and Capability Container. Trust
remains in PKI, transport remains in TLS, and enforcement remains in
the Gateway.

AIC defines the representation and cryptographic binding of
authorization-related information (agent identity, principal binding,
capability container, constraint container, and delegation evidence).
It does not define a universal authorization language: whether an
operation is permitted is decided by the capability scheme and the
deployment policy, not by the AIC extension itself.  The Capability
Language Core [CLC] is one such external language: AIC carries the
containers and the principal binding; CLC defines a deterministic
evaluation over them.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 <xref target="RFC2119"/> <xref target="RFC8174"/> when, and
only when, they appear in all
capitals, as shown here.

The following terms are used throughout this document:

AIC:
: AI Agent Identity Certificate Extension -- the X.509 v3 extension
  defined in this document.

Agent:
: For the purpose of this document, an AI Agent is a software or
  hardware entity capable of performing actions on behalf of a
  principal with varying degrees of autonomy.

Principal:
: The natural person or organizational entity that authorizes an
  Agent to act on its behalf. Whether a Principal is legally
  responsible for actions performed by an Agent is determined by
  applicable law and deployment policy and is outside the scope of
  this specification.

Delegation Mode:
: The protocol-defined relationship between an Agent and its
  Principal for attribution and authorization purposes. The
  interpretation of these modes under applicable law is outside the
  scope of this specification.
  In authorized mode, the Agent acts under its own identity with
  principal consent. In representative mode, the Agent acts on behalf
  of the Principal within the delegated permission scope.

Capability:
: A container for protocol-level operations that an Agent is
  authorized to perform, defined by a scheme identifier and a
  capability identifier within that scheme.

Capability Scheme:
: A system identified by a scheme identifier (schemeId) that defines
  the semantics of capabilities. Gateways route capability evaluation
  to scheme-specific plugins by schemeId.

Credential Bundle:
: The certificates presented by an Agent during the TLS handshake,
  including the agent certificate chain and the principal's
  certificate.

DelegationAuthorization:
: Cryptographic evidence, carried within the AIC extension, that the
  principal has authorized the Agent. Contains a digital signature
  over a DelegationAuthTBS structure.

DelegationAuthTBS:
: The To-Be-Signed structure whose DER encoding is signed by the
  principal's private key to produce the DelegationAuthorization.

PrincipalAuthorization:
: A companion X.509 extension (OID 1.3.6.1.4.1.66257.1.2) carried in
  the Principal's certificate, declaring grants, authorization
  constraints, and delegation policies.

authorizationConstraints:
: An OPTIONAL container within AIC and PrincipalAuthorization that
  defines authorization boundary conditions (IP ranges, concurrency
  limits, time windows). Constraints are evaluated offline during
  TLS handshake.

OID:
: Object Identifier -- a globally unique sequence of integers used
  to identify objects in the X.509 standard.

PEN:
: Private Enterprise Number -- a globally unique identifier assigned
  by IANA to organizations for private use in OID space.

SPKI:
: Subject Public Key Info -- the ASN.1 structure defined in [RFC5280]
  Section 4.1.2.7 containing the public key algorithm and subject
  public key.

## Related Work

Several proposals address agent identity and authorization, either in
X.509 certificate extensions or in application-layer protocols.

[AGTP] (draft-hood-agtp-agent-cert) defines an X.509 certificate
extension that binds an agent identifier and a principal identifier
and includes an authority-scope commitment over a set of scope
tokens. The scope tokens are carried as a flat list of strings.

[APKI] (draft-sharif-apki-agent-pki) defines five separate X.509
extensions for agent capabilities, delegation, trust scoring,
provenance, and behavioral attestation. Each extension is encoded
independently.

[AgentIdentity] (draft-sharif-x509-agent-identity-profile) defines a
single X.509 extension combining a trust level, a list of capability
names, a maximum delegation depth, and a kill-switch URI.

[RFC3820] defines proxy certificates for grid computing. A proxy
certificate extends the certificate chain so that the proxy acts on
behalf of the issuer; it does not carry agent-specific identity or
authorization data.

[RFC5755] defines attribute certificates as a separate authorization
mechanism bound to an identity certificate. Attribute certificates
carry attribute/value pairs and are issued by an attribute authority.

[CapabilityBound] (arXiv:2603.14332) embeds a hash of a skills
manifest in an X.509 extension. Any change to the manifest requires
issuing a new certificate.

[DAAP] (draft-mishra-oauth-agent-grants) extends OAuth 2.0 with agent
grants, using DID-based identifiers and JSON Web Tokens carried at the
application layer. It supports multi-level delegation and cascading
revocation, and depends on DID resolution.

[AIP] (draft-singla-agent-identity-protocol) defines a
decentralized identity, delegation, and authorization framework for
autonomous agents: agent identifiers derived from public keys
(did:aip), capability manifests, delegation chains, and an online
registry for resolution and revocation.

[OpenA2A-AIP] (draft-fane-opena2a-aip) defines the OpenA2A Agent
Identity Protocol using did:opena2a identifiers and ATX credentials
issued by registries; authorization is addressed in a companion
protocol rather than in the identity layer.

WIMSE and SPIFFE define workload identities using SAN URIs
([SPIFFE]); they identify workloads and do not carry authorization
information.

The authorization language itself is outside this document.  A
companion draft, the Capability Language Core [CLC], defines a
carrier-neutral language for capability identifiers, entailment,
intersection, and delegation containment.  AIC's containers can be
evaluated by that language, but this specification does not require
it.

This specification follows the X.509 extension approach used by
AGTP, APKI, AgentIdentity, and CapabilityBound. It differs in three
respects: (1) the authorization data is signed by the principal and
the resulting signature is covered by the certificate authority's
signature; (2) capabilities use a structured container with a scheme
identifier and a capability identifier, so that evaluation can be
routed to scheme-specific plugins; and (3) an authorization constraint
container carries offline-verifiable boundary conditions. The design
goal is to make the authorization decision fully verifiable offline
from the certificate and its credential bundle.

# Delegation Model

## Delegation Modes

Two delegation modes are defined:

**Authorized mode (default):** The Agent acts under its own identity.
The agent certificate's agentId is recorded as the actor in audit logs,
while the principalUid identifies the authorizing principal. The CA
evaluates the agent's declared capabilities against the principal's
PrincipalAuthorization.grants at issuance time, and the resulting
capability set is locked into the certificate. Gateway runtime does
not perform a further P_grants superset check for authorized mode.
Authorized mode therefore provides snapshot authorization semantics:
principal grant changes after issuance do not affect the capability
set of an already issued certificate.

**Representative mode:** The Agent acts on behalf of the Principal
within the delegated permission scope. The principalUid is recorded
as the actor in audit logs, with the agentId recorded as the executor.
Representative mode is the exception to the minimal credential
bundle model: it requires the principal's certificate and its
PrincipalAuthorization extension to be present in the credential
bundle presented during the TLS handshake. Deployments that cannot
provide the complete bundle MUST use authorized mode.
The agent's declared capabilities MUST be a subset of the principal's
grants at both issuance time (CA verification) and runtime (gateway
verification), as the principal's permissions may change during the
agent certificate's lifetime.

### Security Envelope Model

This specification uses a security-envelope heuristic: reducing
either the delegated permission scope or the credential lifetime
reduces the potential exposure of a compromised credential.

Authorized mode selects **narrow scope x longer validity** -- the
principal selects capabilities at issuance, the capability set is
locked into the certificate, and the certificate lifetime is up to
24 hours with automatic renewal. Renewal of an authorized-mode
certificate likewise requires a new principal-signed
DelegationAuthorization (Section 4.5.6); the CA MUST NOT auto-renew by
reusing a prior DelegationAuthorization.

Representative mode selects **broad scope x shorter validity** -- the
agent may exercise the full extent of the principal's permissions
(P_grants), but the certificate is short-lived and subject to runtime
per-operation P_grants intersection verification.

## Permission Intersection

The effective permission for any agent operation is governed by the
intersection of three sets:

The authorization model is the intersection of the principal's grants
and the agent's capabilities:

~~~
P_effective = P_grants (AND) C_agent
~~~

where P_grants is the principal's declared capability grants (in
PrincipalAuthorization.grants) and C_agent is the agent's declared
capability set (in AIC.capabilities). An operation is authorized only
if it belongs to both sets.  The meaning of "belongs to", including
grant coverage and parameter or constraint merging, is defined by the
governing authorization language; the Capability Language Core [CLC]
is one language that defines it (entailment and intersection, with
delegation containment as a separate per-hop relation).

In authorized mode, C_agent alone serves as the effective capability
set (P_grants intersection was already verified by the CA at issuance
time and locked into the certificate). In representative mode, the
intersection is computed at runtime for each operation.

Gateway-local runtime policy (T_policy) -- rate limits, timeouts,
routing, and other deployment-side controls -- is an additional
enforcement layer applied by the relying party. It is NOT part of the
authorization model defined by this specification and MUST NOT be
confused with the P (AND) C authorization intersection.

## Multi-Level Delegation

Single-level delegation (Principal -> Agent, chainDepth = 0) is the
default and recommended deployment mode. A delegation chain of depth 1
(Principal -> Agent -> sub-Agent, chainDepth = 1) MAY be supported
when a deployment requires it, in which case the delegating agent
signs a DelegationAuthorization for the sub-agent:

* **chainDepth = 0 (default)**: direct delegation from the principal
  to the agent (Principal -> Agent).
* **chainDepth = 1 (optional)**: one additional level (Principal ->
  Agent ->
  sub-Agent), in which the delegating agent signs a
  DelegationAuthorization for the sub-agent.

Each level of the chain produces an independent
DelegationAuthorization signed by the delegator's private key, and
capabilities are recursively intersected along the chain.  The per-hop
requirement that a child grant stay within its parent is a containment
check, not an intersection; the Capability Language Core [CLC] defines
that relation and a fused chain check over it. Chain depth
is carried in a DelegationDepthControl extension with chainDepth and
maxDepth fields. In any chain, chainDepth MUST NOT exceed maxDepth.

Chains deeper than 1 are not prohibited by this specification, but they
are not recommended, and this revision does not define their semantics.
For the strongest accountability, deployments SHOULD keep delegation to
a single hop from the principal to the acting agent (chainDepth = 0):
authority and responsibility then rest with one named party at a known
depth.  A deployment that requires an intermediate delegator MAY use
chainDepth > 1 (see the guardrails below), accepting one specific
consequence: **responsibility boundaries blur as the chain grows**.
Each intermediate agent acts under authority it received and then
passes it on, so the legal status of the intermediate agents and the
audit actor semantics become ambiguous; every additional level also
expands the attack surface and grows the credential bundle.  A larger
numeric depth limit (for example, the 255-level maximum in
[AgentIdentity] or the depth-10 chains in [AIP]) is not treated as a
feature.  Conformance targets the default profile (chainDepth = 0) and
the depth-1 option.  Deeper chains are outside the scope of this
revision; a future revision MAY define them only under the guardrails
below.  The accountability model of this specification is anchored to
the natural person at the top of the chain and is best preserved by a
shallow chain.

### Guardrails for Future Multi-Level Chains

A future revision that defines multi-level delegation (chainDepth
> 1) MUST satisfy all of the following properties at every hop:

* **Signed authorization per hop.**  Each hop MUST carry an
  independent DelegationAuthorization signed by the delegating
  entity's private key.  An entity MAY delegate further only to the
  extent its own DelegationAuthorization (including any delegation
  policy it carries) permits further delegation, and only within the
  scope it received; a hop MUST NOT expand scope or assert authority
  that its delegator never held.
* **Monotonic intersection.**  The capability set of each hop MUST
  be a subset of the effective capabilities of the preceding hop
  (C_eff = P_grants (AND) C_1 (AND) ... (AND) C_n).  The CA MUST
  verify the subset relation at each issuance.
* **Bounded depth and loop prevention.**  chainDepth MUST increase
  monotonically and MUST NOT exceed maxDepth.  The CA MUST refuse to
  issue a hop whose delegator already appears earlier in the same
  chain, and deployments SHOULD enforce a limit on credential-bundle
  size (the reference implementation defaults to a maximum chain
  length of 8).
* **Attribution to the root principal.**  Each hop MUST preserve the
  root principalUid and the immediate delegator so that every
  operation remains attributable to the natural or legal person at
  the top of the chain; an intermediate agent is an executor for
  the hops it did not itself authorize.
* **Legal basis at each hop.**  Delegation by or through autonomous
  agents may raise questions of authority under applicable law.
  Each hop SHOULD be traceable to a consenting responsible party;
  deployments that cannot establish such a basis for every hop MUST
  NOT use chains deeper than 1.

Until a future revision defines multi-level delegation under these
guardrails, deployments MUST NOT rely on semantics for chainDepth
> 1 that are not specified in this document, and conformance is
limited to the chainDepth = 0 profile and the chainDepth = 1 option.
The reference implementation exercises whole-chain recursive
verification, intersection, and depth/loop limits in its test suite;
interop test vectors for multi-level chains are planned together
with the future revision.

# Certificate Profile (Data Model)

A certificate carrying the AIC extension encodes the following abstract
data model:

| Component | Description | Cardinality |
|-----------|-------------|-------------|
| Agent Identity | Identifier of the agent | Mandatory |
| Principal Binding | Link to the accountable principal | Mandatory |
| Delegation Mode | Authorized or representative | Mandatory |
| Capability Set | Declared operational capabilities | Optional |
| Authorization Constraints | Offline-verifiable boundary conditions | Optional |
| Delegation Authorization | Cryptographic evidence of principal consent | Mandatory |
| Extensions | Vendor-specific or future extensions | Optional |

This data model is encoded as a set of X.509v3 certificate extensions,
defined in the following section.

# AIC Extension Definition

## OID Tree

~~~
1.3.6.1.4.1.66257 (IANA PEN -- Varwof PKI)
+-- 1 Identity & Authorization Core
|   +-- 1 AIC (Agent Identity Certificate Extension)
|   |   +-- 1 AgentIdentity (agentId, principalUid, delegationMode)
|   |   +-- 2 DelegationAuthorization (reason, requestedLifetime,
|   |   |     timestamp, nonce, signatureAlgorithm, signatureValue)
|   |   +-- 4 DelegationDepthControl (chainDepth, maxDepth)
|   |   |   +-- 1 chainDepth
|   |   |   +-- 2 maxDepth
|   +-- 2 PrincipalAuthorization (grants, authorizationConstraints,
|   |     delegationPolicy)
|   |   +-- 4 DelegationPolicy
+-- 3 National/Industry Certification
|   +-- 1 MarketAccessId
~~~

## Capability Glob Matching Syntax

Capability matching uses the following matching rules:

| Pattern | Meaning | Example |
|---------|---------|---------|
| `scheme:method:path` | Exact match | `http:GET:/api/v1/users` |
| `scheme:method:path/*` | Single-segment wildcard (no "/") | `http:GET:/api/v1/*` |
| `scheme:method:path/**` | Multi-segment wildcard (crosses "/") | `http:GET:/api/v1/**` |
| `scheme:*:path` | Method wildcard | `http:*:/api/v1/*` |
| `scheme:*` | Scheme-wide wildcard | `http:*` |

Matching priority (highest to lowest):
1. Exact match
2. Single-segment wildcard
3. Multi-segment wildcard
4. Method wildcard
5. Scheme-wide wildcard

When multiple rules match, the highest priority rule applies.
If no rule matches, the capability MUST be treated as Deny.

Unqualified wildcards (bare `*` without a preceding namespace and colon
separator) are NOT permitted. All wildcards MUST be scoped within a
schemeId namespace.

## ASN.1 Module

This section defines the ASN.1 module for the AIC extension, using
the conventions specified in [RFC5912].

Encoding tag conventions:

* Mandatory fields use universal tags (INTEGER, UTF8String, OCTET
  STRING, SEQUENCE); no context-specific tags are applied.
* All OPTIONAL fields use context-specific explicit tags
  (`[n] EXPLICIT`), numbered from 0 in field order within each
  structure. Tag numbers are unique within a structure and MAY be
  reused across structures.
* Standard external types (AlgorithmIdentifier) follow RFC 5280
  encoding conventions.
* DEFAULT fields MAY be omitted from DER encodings when equal to the
  default value; implementations MUST accept both forms.

The AIC and PrincipalAuthorization extensions MUST be non-critical so
that systems unaware of these extensions can safely ignore them.

~~~
VARWOF-AIC DEFINITIONS
    { iso(1) identified-organization(3) dod(6) internet(1)
      private(4) enterprise(1) varwof(66257) modules(2)
      id-mod-varwof-aic(1) }
DEFINITIONS ::= BEGIN

-- All SEQUENCEs SHALL use DER encoding (ordered, no indefinite-length).
-- See RFC 5912 Sec. 3 for DER encoding rules.
-- Implementations MUST reject BER indefinite-length encodings.

IMPORTS
    EXTENSION
        FROM PKIX-CommonTypes-2009
        { iso(1) identified-organization(3) dod(6) internet(1)
          security(5) mechanisms(5) pkix(7) id-mod(0)
          id-mod-pkixCommonTypes-02(57) },
    AlgorithmIdentifier
        FROM PKIXAlgs-2009
        { iso(1) identified-organization(3) dod(6) internet(1)
          security(5) mechanisms(5) pkix(7) id-mod(0)
          id-mod-pkix1-algorithms2008-02(56) } ;

-- OID Assignments

id-varwof        OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 66257 }
id-aic           OBJECT IDENTIFIER ::= { id-varwof 1 1 }

-- AIC Extension

aicExt EXTENSION ::= {
    SYNTAX         AIC
    IDENTIFIED BY  id-aic
    CRITICAL       FALSE
}

AIC ::= SEQUENCE {
    version                  INTEGER DEFAULT 1,
    agentId                  UTF8String (SIZE(1..256)),
    principalUid             PrincipalUid,
    capabilities             SEQUENCE SIZE(1..MAX) OF Capability,
    delegationMode           DelegationMode DEFAULT authorized,
    authorizationConstraints [0] EXPLICIT SEQUENCE
        SIZE(0..32) OF Capability OPTIONAL,
    delegationAuthorization  DelegationAuthorization,
    extensions               [1] EXPLICIT AICExtensions OPTIONAL
}

DelegationMode ::= INTEGER {
    authorized     (0),
    representative (1)
} (0..1)

PrincipalUid ::= SEQUENCE {
    version     INTEGER (0..255) DEFAULT 1,
    realm       UTF8String (SIZE(1..128)),
    identifier  UTF8String (SIZE(1..256)),
    keyHash     OCTET STRING (SIZE(1..64)),
    hashAlgo    [0] EXPLICIT AlgorithmIdentifier OPTIONAL
}
-- hashAlgo omitted defaults to SHA-256 (OID 2.16.840.1.101.3.4.2.1);
-- keyHash = hashAlgo(SPKI). Only hash algorithms with output length
-- not exceeding 64 bytes are supported (SHA-2/SHA-3 family, SM3,
-- BLAKE2/BLAKE3). keyHash length is determined by the algorithm.

Capability ::= SEQUENCE {
    schemeId        UTF8String (SIZE(1..128)),
    capabilityId    UTF8String (SIZE(1..256)),
    parameters      [0] EXPLICIT OCTET STRING (SIZE(0..4096)) OPTIONAL
}

-- Reason for delegation authorization (mandatory in
-- DelegationAuthorization / DelegationAuthTBS; not present in
-- PrincipalAuthorization)

Reason ::= SEQUENCE {
    reasonCode  UTF8String (SIZE(1..64)),
        -- controlled vocabulary, e.g., SCHEDULED_MAINTENANCE
    description UTF8String (SIZE(1..512))
        -- human-readable description
}

DelegationAuthorization ::= SEQUENCE {
    reason              Reason,
    requestedLifetime   INTEGER (1..86400),  -- SHOULD 3600-86400
    timestamp           GeneralizedTime,     -- MUST be UTC (Z form)
    nonce               OCTET STRING (SIZE(32)),
    signatureAlgorithm  AlgorithmIdentifier,
    signatureValue      OCTET STRING
}

-- DelegationAuthTBS (To-Be-Signed structure)
-- The principal's private key signs the DER encoding of this structure.

DelegationAuthTBS ::= SEQUENCE {
    version                  INTEGER { v1(1), v2(2) } DEFAULT v1,
    agentId                  UTF8String (SIZE(1..256)),
    principalUid             PrincipalUid,
    reason                   Reason,
    capabilities             SEQUENCE SIZE(1..MAX) OF Capability,
    delegationMode           DelegationMode,
    authorizationConstraints [0] EXPLICIT SEQUENCE
        SIZE(0..32) OF Capability OPTIONAL,
    requestedLifetime        INTEGER (1..86400),  -- SHOULD 3600-86400
    timestamp                GeneralizedTime,     -- MUST be UTC (Z)
    nonce                    OCTET STRING (SIZE(32)),
    agentKeyBinding          [1] EXPLICIT AgentKeyBinding OPTIONAL
}

-- Version/validation matrix (normative):
--   version = 1 (legacy): agentKeyBinding MUST be absent;
--   version = 2 (current): agentKeyBinding MUST be present and valid;
--   any other version value: rejected.
-- Newly issued DAs MUST be version 2.

AgentKeyBinding ::= SEQUENCE {
    keyHash  OCTET STRING (SIZE(1..64)),
    hashAlgo [0] EXPLICIT AlgorithmIdentifier OPTIONAL
}
-- Binds the DA to the agent's public key: keyHash = hashAlgo(SPKI DER),
-- hashAlgo omitted defaults to SHA-256 (OID 2.16.840.1.101.3.4.2.1).
-- Only hash algorithms whose output does not exceed 64 octets are
-- supported (SHA-2/SHA-3 family, SM3, BLAKE2/BLAKE3); keyHash length
-- MUST equal the declared algorithm's output length. An unknown or
-- unsupported hashAlgo MUST be rejected (no silent fallback); SHA-1
-- MUST NOT be used.

-- PrincipalAuthorization Extension (OID: 1.3.6.1.4.1.66257.1.2)
-- Carried in the Principal's certificate.

paExt EXTENSION ::= {
    SYNTAX         PrincipalAuthorization
    IDENTIFIED BY  id-principal-auth
    CRITICAL       FALSE
}
id-principal-auth OBJECT IDENTIFIER ::= { id-varwof 1 2 }

PrincipalAuthorization ::= SEQUENCE {
    version                  INTEGER DEFAULT 1,
    grants                   SEQUENCE SIZE(1..MAX) OF Capability,
    authorizationConstraints [0] EXPLICIT SEQUENCE
        SIZE(0..32) OF Capability OPTIONAL,
    delegationPolicy         [1] EXPLICIT DelegationPolicy OPTIONAL,
    extensions               [2] EXPLICIT AICExtensions OPTIONAL
}

DelegationPolicy ::= SEQUENCE {
    version             INTEGER DEFAULT 1,
    maxAgents           INTEGER DEFAULT 1,
    allowedMode         DelegationModeEnum DEFAULT authorizedOnly,
    maxSessionHours     [0] EXPLICIT INTEGER OPTIONAL
}

DelegationModeEnum ::= INTEGER {
    authorizedOnly        (0),
    representativeAllowed (1)
} (0..1)

-- Extensibility Framework

AICExtensions ::= SEQUENCE SIZE (1..MAX) OF ExtField

ExtField ::= SEQUENCE {
    extnID      OBJECT IDENTIFIER,
    critical    BOOLEAN DEFAULT FALSE,
    extnValue   OCTET STRING
}

-- DelegationDepthControl carries the delegation chain depth.
-- Placed in AIC extensions slot, OID 1.3.6.1.4.1.66257.1.1.4.
-- chainDepth MUST NOT exceed maxDepth.
-- This revision defines semantics for chainDepth = 0 and chainDepth = 1
-- only.  Deeper chains are not refused, but they are outside the scope
-- of this specification; a deployment that uses them does so under its
-- own policy and cannot claim conformance for them.

id-ddc OBJECT IDENTIFIER ::= { id-aic 4 }
DelegationDepthControl ::= SEQUENCE {
    chainDepth  INTEGER (0..255),  -- OID .1.1.4.1
    maxDepth    INTEGER (0..255)   -- OID .1.1.4.2
}

END
~~~

## Example AIC Extension Encoding

The following example illustrates the AIC extension for an agent with
agentId "agent-1", a principal identified as "zhangsan" in the
"corp.com" realm, and a single HTTP capability:

~~~
AIC ::= {
    agentId         "agent-1",
    principalUid    {
        realm       "corp.com",
        identifier  "zhangsan",
        keyHash     <32-byte hash of the principal's SPKI>
    },
    capabilities    {
        { schemeId "http", capabilityId "GET:/api/v1/users" }
    },
    delegationAuthorization {
        reason      {
            reasonCode  "SCHEDULED_MAINTENANCE",
            description "temporary maintenance window"
        },
        requestedLifetime 3600,
        timestamp   "2026-08-18T00:00:00Z",
        nonce       <32-byte CSPRNG value>,
        signatureAlgorithm ecdsa-with-SHA256,
        signatureValue <DER-encoded signature over DelegationAuthTBS>
    }
}
~~~

In the DER encoding of this example, the DEFAULT fields (version,
delegationMode) are omitted as permitted by the ASN.1 module, and the
OPTIONAL fields (authorizationConstraints, extensions) are absent.
Each field is encoded in the order given in the ASN.1 module using DER
rules [RFC5280] [RFC5912]. The signatureValue is produced by the
principal's private key over the DER encoding of the corresponding
DelegationAuthTBS structure and varies per authorization.

## Field Definitions

### agentId

The `agentId` field contains a globally unique identifier for the AI
Agent instance. The identifier SHOULD be stable across certificate
renewals for the same agent instance. Implementations MAY use UUIDs,
URN-based identifiers, or DNS-anchored names.

### delegationMode

The `delegationMode` field defines the protocol-defined relationship
between the Agent and its Principal for attribution and authorization
purposes:

authorized (0):
: The Agent acts under its own cryptographic identity with explicit
  principal authorization. The audit trail records the agentId as the
  actor. This is the default mode.

representative (1):
: The Agent fully represents the Principal. Actions are attributed to
  the Principal (principalUid) in the audit trail. This mode MUST
  only be permitted when the Principal's certificate explicitly allows
  representative delegation (allowedMode=representativeAllowed in
  PrincipalAuthorization.delegationPolicy).

### principalUid

The `principalUid` field identifies the natural person or
organizational entity that authorizes the Agent's actions. It is
encoded as an ASN.1 SEQUENCE:

~~~
PrincipalUid ::= SEQUENCE {
    version     INTEGER (0..255) DEFAULT 1,
    realm       UTF8String (SIZE(1..128)),
    identifier  UTF8String (SIZE(1..256)),
    keyHash     OCTET STRING (SIZE(1..64)),
    hashAlgo    [0] EXPLICIT AlgorithmIdentifier OPTIONAL
}
~~~

Where:

* `realm` is a globally unique namespace (e.g., an organization domain),
  limited to 128 characters;
* `identifier` is a unique identifier within the realm, limited to 256
  characters;
* `keyHash` is the hash of the SubjectPublicKeyInfo (SPKI) of the
  principal's certificate computed with `hashAlgo`: `keyHash =
  hashAlgo(SPKI)`. The length is determined by the hash algorithm and
  MUST NOT exceed 64 bytes (SHA-256 = 32 bytes, SHA-384 = 48 bytes,
  SHA-512/SHA3-512 = 64 bytes, SM3 = 32 bytes). Using the SPKI hash
  rather than a certificate fingerprint allows principal certificate
  renewal without invalidating existing agent authorizations, provided
  the same key pair is used.
* `hashAlgo` identifies the hash algorithm used for `keyHash`; when
  omitted, SHA-256 (OID 2.16.840.1.101.3.4.2.1) is assumed. Only hash
  algorithms with output length not exceeding 64 bytes are supported.

The human-readable form `{realm}:{identifier}:{keyFingerprint}`
(where keyFingerprint is the base64url encoding of keyHash per
[RFC4648] Section 5, without padding) is RECOMMENDED for display
and logging purposes only. Machine-level comparison MUST use ASN.1
structural comparison, not string parsing.

keyHash MAY be used as a management index (e.g., for cascading
revocation, audit, or certificate lookup by principal). Such lookups
are for management association only; authorization binding and
revocation decisions remain based on keyHash and certificate chain
validation.

### capabilities

The `capabilities` field is a pure container -- this specification
defines only the encoding of capabilities, not their semantics.
Capability semantics are entirely defined by the capability scheme
identified by `schemeId`. AIC implementations MUST NOT assign semantics
to unknown schemes.  The Capability Language Core [CLC] is one external
language for those semantics; it does not change the rule that an
unknown scheme is refused. Each capability entry is identified by a `schemeId`
that indicates the governing scheme, a `capabilityId` within that
scheme, and OPTIONAL parameters.

The `capabilityId` field supports wildcard characters for glob-based
matching: `*` matches a single path segment (no colon), `**` matches
across path segments (any depth).

Gateways route capability evaluation by looking up registered plugins
by `schemeId`. When the capability required by the current request
references an unknown scheme or an unknown capability, the request
MUST be treated as Deny (fail-closed). Capabilities carried in the
certificate that are not relevant to the current request do not affect
the decision.

### authorizationConstraints

The `authorizationConstraints` field (OPTIONAL) defines
authorization boundary conditions for the Agent. Each constraint
reuses the Capability container. The `schemeId` MUST be one of
`"varwof/constraint-v1"`; any other `schemeId` MUST be rejected.
`capabilityId` distinguishes the constraint type. The following
constraint types are defined as examples; additional constraint types
are registered through the capability scheme registry (Section IANA
Considerations) and do not require a change to the ASN.1 module:

| capabilityId | parameters Format | Description |
|-------------|-------------------|-------------|
| `allowed-cidr` | `["10.0.0.0/8", "192.168.0.0/16"]` | Allowed IP ranges |
| `max-concurrent` | `{"max": 5}` | Maximum concurrent Agent instances |
| `time-window` | `{"start": "22:00", "end": "06:00"}` | Allowed execution time window (UTC) |

Constraint semantics MUST define the reference clock, time scale,
timezone interpretation, boundary conditions, and behavior under clock
uncertainty (e.g., for time-window).

Constraints are evaluated with AND logic: all constraints MUST be
satisfied for the connection to be accepted. The maximum number of
constraints is 32, with a single constraint's parameters field limited
to 512 bytes. Unknown constraint types are logged as audit warnings
and ignored by default (forward-compatible); strict rejection behavior
may be configured by the deployment.

Design principle: authorizationConstraints carry boundary conditions
determined by the authorizing party, varying per-principal, and changing
infrequently. Runtime policies (timeouts, retries, rate limits, routing)
are NOT carried in authorizationConstraints and remain in gateway-local
policy configuration.

The boundary between authorizationConstraints and gateway runtime
policy is fixed:

* authorizationConstraints carry authorization boundary conditions
  set by the authorizing party (IP ranges, concurrency limits, time
  windows) that are verifiable offline.
* Gateway runtime policy (timeouts, retries, rate limits, routing,
  logging levels) is deployment-specific and MUST NOT be carried in
  authorizationConstraints.

Constraint types registered with the same capabilityId and parameters
MUST be interpreted consistently by gateways that implement them.
Gateways that do not implement a constraint type treat it as unknown
and follow the unknown-constraint handling described above.

The constraints within AIC.authorizationConstraints are independent of
constraints within PrincipalAuthorization.authorizationConstraints --
PA constraints limit the authorization behavior, AIC constraints limit
the execution behavior. Both are checked independently during
validation.

### delegationAuthorization

The `delegationAuthorization` field provides cryptographic evidence
that the principal has authorized this Agent. It contains:

~~~
DelegationAuthorization ::= SEQUENCE {
    reason              Reason,
    requestedLifetime   INTEGER (1..86400),
    timestamp           GeneralizedTime,
    nonce               OCTET STRING (SIZE(32)),
    signatureAlgorithm  AlgorithmIdentifier,
    signatureValue      OCTET STRING
}
~~~

The signature algorithm and signature value are kept as two flat
fields -- `signatureAlgorithm` preceding `signatureValue` -- following
the X.509 certificate convention (RFC 5280 Section 4.1), where
`signatureAlgorithm` precedes `signatureValue` in the Certificate
structure, enabling parsers to determine the algorithm before reading
the signature bytes. They MUST NOT be merged into a nested SEQUENCE.

* `reason` (mandatory): The reason for this delegation, carried
  both here and in DelegationAuthTBS (where it is covered by the
  principal's signature). `reasonCode` is a controlled vocabulary value
  in SCREAMING_SNAKE style (e.g., `SCHEDULED_MAINTENANCE`,
  `AUTO_RENEWAL`); `description` is a human-readable explanation. Both
  fields MUST be present and non-empty. `reason` does not appear in
  PrincipalAuthorization.

* `requestedLifetime`: The principal-requested certificate lifetime in
  seconds. The wire value MUST be in the range 1-86400 (SHOULD
  3600-86400). The CA determines the actual NotAfter as
  min(requestedLifetime, local policy maximum).

* `timestamp`: The time at which the authorization was granted. MUST be
  UTC encoded as GeneralizedTime in Z form.

* `nonce`: 32-byte CSPRNG-generated random value for replay protection.
  The CA verifies nonce uniqueness at issuance time and persists it
  to prevent reuse. Certificate renewal or re-issuance MUST be backed
  by a new DelegationAuthorization carrying a fresh nonce; a CA MUST
  NOT renew or re-issue an agent certificate by reusing a prior
  DelegationAuthorization.

* `signatureAlgorithm`: The algorithm identifier for the principal's
  signature (e.g., ecdsa-with-SHA256).

* `signatureValue`: The DER-encoded signature value produced by the
  principal's private key over the DER encoding of DelegationAuthTBS.

The principal's private key signs the DER encoding of the following
DelegationAuthTBS structure:

~~~
DelegationAuthTBS ::= SEQUENCE {
    version                  INTEGER { v1(1), v2(2) } DEFAULT v1,
    agentId                  UTF8String (SIZE(1..256)),
    principalUid             PrincipalUid,
    reason                   Reason,
    capabilities             SEQUENCE SIZE(1..MAX) OF Capability,
    delegationMode           DelegationMode,
    authorizationConstraints [0] EXPLICIT SEQUENCE
        SIZE(0..32) OF Capability OPTIONAL,
    requestedLifetime        INTEGER (1..86400),
    timestamp                GeneralizedTime,
    nonce                    OCTET STRING (SIZE(32)),
    agentKeyBinding          [1] EXPLICIT AgentKeyBinding OPTIONAL
}

AgentKeyBinding ::= SEQUENCE {
    keyHash  OCTET STRING (SIZE(1..64)),
    hashAlgo [0] EXPLICIT AlgorithmIdentifier OPTIONAL
}
~~~

All fields except the two OPTIONAL containers
(`authorizationConstraints`, `agentKeyBinding`) MUST be present in the
DER encoding of DelegationAuthTBS. The `authorizationConstraints` field
uses context-specific tag \[0\] EXPLICIT encoding; its OPTIONAL nature
does not break backward compatibility with certificates that do not
carry constraints.

The `agentKeyBinding` field (context-specific tag \[1\] EXPLICIT) is
version-dependent, and the version/validation matrix is normative:

* `version = 1` (legacy): `agentKeyBinding` MUST be absent; a
  version-1 TBS carrying the binding is malformed and MUST be
  rejected;
* `version = 2` (current): `agentKeyBinding` MUST be present and valid;
  newly issued DelegationAuthorizations MUST be version 2;
* any other `version` value MUST be rejected.

A binding is *valid* when `keyHash` is 1-64 octets and its length
equals the output length of the declared `hashAlgo` (SHA-256 when
`[0]` is omitted); an unknown or unsupported `hashAlgo` MUST be
rejected with no silent fallback, and SHA-1 MUST NOT be used. The
binding ties the authorization to the agent's public key (SPKI hash),
so a valid DelegationAuthorization cannot be transplanted onto a
different agent key; version-1 authorizations lack this binding and
are accepted for verification only under the substitution mitigations
described in the Security Considerations.

The JWT counterpart in [AIC-JWT] numbers the DA claim set with a
historical offset: X.509 AIC DA v1 corresponds to AIC-JWT
`da.ver=2`, and X.509 AIC DA v2 (with `agentKeyBinding`) corresponds
to AIC-JWT `da.ver=3`.  A JWT `da.ver=3` MUST carry the equivalent
`agent_key_binding` and MUST NOT be accepted without it; a JWT
`da.ver=2` MUST NOT carry that binding.

### Extensions and Extensibility

The `extensions` field in AIC provides an extensibility mechanism for
vendor-specific and user-specific metadata, analogous to X.509 v3
extensions but scoped to the AIC context. Each extension entry is
identified by a globally unique OID.

* Vendor-specific extensions SHOULD use OIDs under the vendor's own
  IANA Private Enterprise Number.
* Unknown extensions with `critical = TRUE` MUST cause certificate
  rejection.
* Unknown extensions with `critical = FALSE` (default) MAY be silently
  ignored.

### Certificate Size Constraints

Certificates MUST observe the following size limits:

* Full-protocol safety limit: 12 KB recommended, 16 KB hard limit.
  This is the DER-encoded certificate size compatible with TCP/HTTP/
  DTLS/QUIC gateways. 16 KB corresponds to the QUIC
  `CRYPTO_BUFFER_EXCEEDED` limit of the QUIC stacks used by the
  reference implementation; exceeding it fails the handshake.

* Handshake certificate (AIC lightweight): 8 KB recommended, 16 KB
  hard limit. Used for mTLS/DTLS/QUIC handshake. In dual-certificate
  deployments it contains agentId + principalUid + delegationMode
  + DelegationAuthorization, plus at least one capability entry (the
  AIC capability set MUST NOT be empty; see Section 4.5.4). The
  dual-certificate deployment model is an optional deployment profile
  and does not define a new TLS certificate type.

* Full authorization certificate: 64 KB recommended, 128 KB hard
  limit. Carries all capabilities, authorizationConstraints, and
  extensions; transmitted at the application layer after the handshake.
  Certificates exceeding 128 KB MUST be rejected.
  Unlike QUIC, TCP/TLS transports do not impose the 16 KB handshake
  limit: certificate messages are segmented by the TLS record layer,
  so larger certificates can be carried in practice up to the hard
  limit.

The number of entries in the `extensions` field SHOULD NOT exceed 32.
The ASN.1 module bounds the `capabilities` sequence with SIZE(1..MAX)
and does not fix a numeric limit on the wire format. Certificates
whose capability entries exceed 256 MUST be rejected to prevent DoS
attacks; typical deployments carry far fewer entries, and deployments
SHOULD keep the capability set as small as practical.

### Capability Parameters Intersection

When matching capabilities across P_grants and C_agent, parameter
intersection follows these rules:

* If C_agent.parameters exceed the boundary defined in
  P_grants.parameters, the capability entry is invalid (filtered
  or rejected).
* Otherwise, C_agent.parameters are used in full (agent-specified
  values within principal-defined boundaries).

Examples:

| P_grants | C_agent | Result |
|----------|---------|--------|
| `max_rows=1000` | `max_rows=100` | Accept, use `max_rows=100` |
| `max_rows=1000` | `max_rows=5000` | Reject (exceeds boundary) |

# Validation Procedure

This section defines the validation procedure that a gateway or
relying party MUST perform when processing an AIC-bearing certificate.

## Validation Pipeline

The gateway performs the following validation steps in order after
TLS handshake completion:

1. **Certificate Chain** ([RFC5280]): Verify the certificate chain
   up to a trusted root, including signature validation, validity
   periods, and basic constraints.

2. **Revocation Status**: Verify that neither the end-entity
   certificate nor any intermediate certificate in the chain has been
   revoked. Implementations MAY use CRLs ([RFC5280]), OCSP
   ([RFC6960]), or OCSP Must-Staple ([RFC7633]). In offline
   deployments, a locally cached CRL or a short validity window MAY
   serve as an alternative revocation mechanism.

3. **AIC Extension Parsing**: Parse the AIC SEQUENCE. If the
   extension is marked critical and cannot be parsed, the certificate
   MUST be rejected.

4. **DelegationAuthorization Verification**: Verify the principal's
   signature in `delegationAuthorization.signatureValue`:
   * Reconstruct the DER encoding of DelegationAuthTBS (including
     reason and authorizationConstraints if present). The TBS is
     DER-encoded in the field order defined in the ASN.1 module;
     DEFAULT fields MAY be omitted and are interpreted with their
     default values.
   * Use the principal's public key (identified by
     principalUid.keyHash) to verify `signatureValue`.
   * Cross-verify that hashAlgo(principal_cert.SPKI) equals
     principalUid.keyHash (hashAlgo omitted means SHA-256).
   * Verify the version/validation matrix: `version = 1` requires
     `agentKeyBinding` to be absent (legacy-only, accepted under the
     substitution mitigations); `version = 2` requires a valid
     `agentKeyBinding`; any other version value MUST be rejected. When
     the binding is present, cross-verify that
     hashAlgo(agent_cert.SPKI) equals `agentKeyBinding.keyHash`
     (hashAlgo omitted means SHA-256) and that the keyHash length
     equals the declared algorithm's output length; an unknown or
     unsupported hashAlgo MUST be rejected.
   * Verify that the principal's certificate chain validates to the
     same configured trust anchor as the agent certificate chain;
     chains that terminate at different trust anchors MUST be
     rejected (Fail-Close).
   * Verify that the certificate validity period
     (notAfter - notBefore) does not exceed
     delegationAuthorization.requestedLifetime, and that
     requestedLifetime is at most 86400 seconds (1 day).
   * Verify that `signatureAlgorithm` is one of the permitted
     algorithms: ECDSA with SHA-256 (MUST), ECDSA with SHA-384 or
     SHA-512 (MAY), RSA with SHA-256 (MUST), RSA with SHA-384 or
     SHA-512 (MAY), RSA-PSS with SHA-256, SHA-384, or SHA-512 (MAY),
     or Ed25519 (MAY).
     Any other algorithm MUST be rejected.

5. **PA.authorizationConstraints Check**: If the
   PrincipalAuthorization extension in the principal's certificate
   contains authorizationConstraints, evaluate them. PA constraints
   limit the authorization behavior and are independent of
   AIC.authorizationConstraints.

6. **AIC.authorizationConstraints Check**: If
   AIC.authorizationConstraints is present, evaluate each constraint
   it recognizes with AND logic. All constraints MUST be satisfied.
   Unknown constraint types are logged as audit warnings and ignored
   (forward-compatible). This step is executed before capability
   evaluation for fast rejection of unauthorized connections.

7. **Delegation Mode Check**: If `delegationMode` is representative:
   * Load the principal's certificate and its PrincipalAuthorization
     extension.
   * Verify allowedMode permits representative delegation.
   * Verify that C_agent is a subset of P_grants (P (AND) C (AND) T).

8. **Delegation Depth Check**: If a DelegationDepthControl extension
   is present, verify that chainDepth does not exceed maxDepth. As a
   best practice, deployments SHOULD prefer chains within the
   recommended envelope (chainDepth <= 1). A chain with chainDepth >
   1 is not refused by this specification, but its semantics are
   outside the scope of this revision: a deployment that accepts one
   relies on its own policy for the responsibility boundaries along
   the chain.

9. **Capability Evaluation**: For the capability required by the
   current request, route evaluation to the plugin registered for its
   `schemeId`. If no plugin is registered or the capability is
   unknown, the request MUST be denied. Other capabilities carried in
   the certificate but not relevant to the current request do not
   affect the decision.

10. **Decision**: If all validation steps pass, the relying party
   SHOULD allow the connection. If any step fails, the relying party
   MUST reject the request. Deployments SHOULD record the rejection
   with sufficient diagnostic information for audit purposes.

## Offline Validation

In offline or air-gapped deployments without access to CRL or OCSP
responders, the relying party MUST accept the risk that a revoked
certificate may be accepted until the next cache refresh. Mitigations
include:

* Short certificate validity windows (RECOMMENDED <= 1 hour);
* Locally cached CRL shards with freshness checks;
* authorizationConstraints evaluated entirely offline during TLS
  handshake.

The principal's certificate is obtained from the Credential Bundle
presented by the Agent during TLS handshake (TLS 1.3 allows multiple
CertificateEntry messages). If the principal's certificate is not
present in the chain and no local cache is available, the gateway MUST
reject the connection (Fail-Close). The same-trust-anchor requirement
applies in online and offline deployments alike.
The transport mechanism for the credential bundle is a deployment
detail and is not defined as a new TLS message type by this
specification.

# PrincipalAuthorization Extension

The PrincipalAuthorization extension (OID `1.3.6.1.4.1.66257.1.2`) is a
companion X.509 extension carried in the Principal's certificate. It
declares the Principal's authority boundaries, including grant
declarations, authorization constraints, and delegation policies.

## ASN.1 Definition

~~~
PrincipalAuthorization ::= SEQUENCE {
    version                  INTEGER DEFAULT 1,
    grants                   SEQUENCE SIZE(1..MAX) OF Capability,
    authorizationConstraints [0] EXPLICIT SEQUENCE
        SIZE(0..32) OF Capability OPTIONAL,
    delegationPolicy         [1] EXPLICIT DelegationPolicy OPTIONAL,
    extensions               [2] EXPLICIT AICExtensions OPTIONAL
}

DelegationPolicy ::= SEQUENCE {
    version             INTEGER DEFAULT 1,
    maxAgents           INTEGER DEFAULT 1,
    allowedMode         DelegationModeEnum DEFAULT authorizedOnly,
    maxSessionHours     [0] EXPLICIT INTEGER OPTIONAL
}

DelegationModeEnum ::= INTEGER {
    authorizedOnly        (0),
    representativeAllowed (1)
} (0..1)
~~~

The `grants` field defines the set of capabilities the principal may
grant to agents -- serving as the upper bound (P_grants) in the
permission intersection model.

The `authorizationConstraints` field carries principal-level
authorization boundary constraints, reusing the Capability container
with `schemeId="varwof/constraint-v1"`. PA constraints and AIC
constraints are
evaluated independently -- they operate at different semantic layers
and are not in a subset relationship.

The `delegationPolicy` field defines the Principal's delegation
boundary: how many concurrent agents are permitted (maxAgents),
which delegation modes are allowed (allowedMode), and optionally
the maximum session hours (maxSessionHours).

maxAgents (in DelegationPolicy) and the max-concurrent constraint (in
authorizationConstraints) have distinct semantics: maxAgents limits
how many Agent instances the Principal may delegate to concurrently,
whereas max-concurrent limits how many concurrent connections a single
Agent may establish. They are enforced at different layers (policy
boundary vs execution boundary) and are not interchangeable.

## Principal Key Rotation

When the principal's private key is compromised and a new key pair is
generated, the SPKI hash in `principalUid.keyHash` changes, causing all
existing representative-mode agent certificates to fail authorization
checks. This is an intentional design: when the key pair changes, all
associated agent certificates are automatically invalidated through a
key management operation rather than a revocation broadcast. When the
principal renews their certificate using the same key pair, the SPKI
remains unchanged and existing agent authorizations continue without
requiring re-issuance.

# Deployment Models

## Enterprise/Regulated Model

* The `principalUid` field MUST be populated with a verifiable natural
  person identifier.
* The `delegationAuthorization` field MUST be present and
  cryptographically validated.
* Representative mode MUST only be used with explicit
  PrincipalAuthorization delegation grants.
* The agent certificate chain and the principal certificate chain
  MUST validate to the same configured trust anchor (the agent CA and
  the principal CA MUST belong to the same trust domain).
* Certificate validity SHOULD be short-lived (hours to days).
* authorizationConstraints SHOULD carry IP range, concurrency, and
  time window boundaries.
* All AIC-bearing connections SHOULD be logged.

## Consumer/Individual Model

* The `principalUid` MAY be omitted or contain a pseudonymous
  identifier.
* The `delegationAuthorization` field MAY be omitted for low-risk
  operations.
* Representative mode SHOULD NOT be used.
* Deployments in this model prioritize consumer privacy protections
  over granular identity binding.
* When a DelegationAuthorization is present, the same-trust-anchor
  requirement of Section 5 applies.

# Extensibility Framework

The `extensions` field in AIC provides an extensibility mechanism for
vendor-specific and user-specific metadata, analogous to X.509 v3
extensions but scoped to the AIC context.

Each extension in the `extensions` sequence is identified by a globally
unique OID. The following guidelines apply:

* Vendor-specific extensions SHOULD use OIDs under the vendor's own
  IANA Private Enterprise Number.
* Unknown extensions with `critical = TRUE` MUST cause certificate
  rejection.
* Unknown extensions with `critical = FALSE` (default) MAY be silently
  ignored.

This document specifies the container structure only. Semantics are
defined by the OID assignee.

# Privacy Considerations (GDPR / Right to Erasure)

AIC certificates are static X.509 data objects. Once issued, the
`principalUid` field cannot be modified or deleted from distributed
certificates. Deployments MUST ensure that:

1. The `identifier` field within `principalUid` does not contain raw
   personally identifiable information (PII) such as full names,
   national ID numbers, or email addresses. Internal UUIDs or
   pseudonymous identifiers MUST be used instead.
2. The mapping table between pseudonymous identifiers and natural
   persons is stored in a compliant database that supports deletion
   under GDPR Article 17 or equivalent regulations.
3. Certificate revocation (CRL/OCSP) is the only mechanism available
   to signal that a principal no longer authorizes a given agent;
   revocation does not erase the certificate itself.

4. AIC certificates SHOULD be treated as stateless credentials by
   relying parties: they are parsed and verified during the TLS
   handshake, after which the raw certificate MAY be discarded and
   need not be persistently stored.

5. Audit logs SHOULD be minimized: they need not record the full
   principalUid structure or extension content. A session-bound
   fingerprint, the operation summary, the decision, and the
   pseudonymous identifier are sufficient for accountability.

6. Log retention MUST be configurable by the deployment according to
   applicable jurisdictional requirements. A layered model is
   recommended: long-term archival for high-accountability regimes,
   limited cleanup periods for standard deployments, and an ephemeral
   no-mapping mode for consumer scenarios.

7. Cryptographic evidence and log mappings are independent: the
   DelegationAuthorization signature can be verified on its own
   without relying on audit log mappings, so deleting a pseudonym
   mapping table does not invalidate the cryptographic
   evidence of authorization.

Since certificates are immutable once issued, data-subject rights
(access, rectification, erasure) are realized through certificate
revocation and re-issuance: revoke the certificate carrying the old
identifier, issue a new certificate with a fresh pseudonymous
identifier, and delete the associated mapping entries.

This specification provides privacy-preserving mechanisms only.
Legal compliance (lawful basis, cross-border transfer, breach
notification, and other obligations) is the responsibility of the
deployment acting as data controller or processor.

All data carried in the AIC extension is visible during the TLS
handshake. Implementations MUST NOT place sensitive data in any
certificate extension.

# Security Considerations

The AIC extension is not an authentication requirement by itself:
the X.509 certificate chain already authenticates the agent, and the
AIC extension carries authorization-related information that the
relying party may evaluate. Deployments that require AIC-based
authorization MUST configure the relying party to require and process
the AIC extension.

AIC does not constrain the authority of a CA to issue
PrincipalAuthorization extensions. The trustworthiness of a
PrincipalAuthorization depends on the CA issuance policy and the
trust anchor configuration.

## Threat Model

This specification considers the following adversary models:

**Network Attacker (E):** A network-level adversary capable of
intercepting, modifying, and replaying TLS connections. This adversary
does not have access to any private keys.

**Malicious Agent (M):** An authenticated agent in possession of a
valid AIC certificate that attempts to escalate privileges, impersonate
other agents, or exceed its authorized capabilities.

**Compromised Principal (P):** A principal whose private key has been
leaked. The attacker can sign arbitrary DelegationAuthorization
payloads using the compromised key.

**Compromised CA (C):** An adversary with access to a CA signing key.
This adversary can issue arbitrary certificates and is the most
powerful in the model.

Trust boundary. This specification assumes a trusted-CA model: the CA
issuing the agent certificate correctly binds `agentId` to the subject
public key and faithfully encodes the principal-signed delegation
fields in the AIC extension. Compromise of a CA signing key or of a
configured trust anchor is outside the protection scope of the
mechanisms defined in this document; deployments MUST protect CA
signing keys (e.g., HSM or equivalent isolation) and MUST apply the
same-trust-anchor requirement of Section 5 so that agent and principal
chains share a single trust domain.

## Threat Mitigations

| Threat | Mitigation | Mechanism |
|--------|------------|-----------|
| Agent impersonation | Cryptographic identity binding | X.509 CA-issued certificate, BasicConstraints CA:FALSE |
| Principal denial of authorization | Digital signature on authorization | DelegationAuthorization.signatureValue over DelegationAuthTBS |
| Capability escalation | Permission subset check | P_grants (AND) C_agent (AND) T_policy intersection |
| Cross-CA role spoofing | Trust anchor hash verification | Trust anchor fingerprint comparison in offline plugin parameters |
| Unknown extension bypass | Critical flag enforcement | Reject on unknown critical extension |
| Signature replay | Nonce binding in TBS | 32-byte nonce in DelegationAuthTBS, CA uniqueness check |
| Authorization forgery | Dual-signature nesting | Principal signature prevents forgery of DelegationAuthorization content by non-CA parties; faithful CA encoding of principal-signed fields is required by issuance policy and the same-trust-anchor requirement (Section 5) |

## Offline Validation Risks

In offline deployments, the risk of accepting a revoked certificate
exists until the next cache refresh. Mitigations include short
certificate validity windows and strict authorizationConstraints
that limit the blast radius (IP range, concurrency caps).

## Authorization Constraint Integrity

The authorizationConstraints field is carried inside the AIC
extension, which is covered by the CA signature over the
TBSCertificate; a modification of any constraint therefore fails
certificate signature validation. The effectiveness of constraint
enforcement also depends on the gateway evaluating the constraints it
recognizes and on constraint plugins implementing the declared
semantics. Constraints are boundary conditions that limit the blast
radius of a compromised or malicious agent; they are not a substitute
for gateway-local policy controls such as rate limiting or resource
quotas.

## Principal Key Hash Binding

The principalUid.keyHash field binds the delegation authorization to
the principal's public key through the hash algorithm identified by
hashAlgo. The hash output is limited to 64 bytes by the ASN.1 SIZE
constraint, and a collision in a cryptographically secure hash
function is assumed to be computationally infeasible under the
security assumptions of the selected hash algorithm. In addition,
keyHash is used to locate and bind the
principal's certificate within the credential bundle; signature
verification uses the principal's public key after certificate chain
validation, so a hash collision alone would not enable an attacker to
produce a valid principal signature. keyHash itself does not
establish trust: trust derives from certificate chain validation and
the principal's signature. keyHash is a locator and binding mechanism
only.

## Nonce Replay Protection

The 32-byte nonce in DelegationAuthTBS is signed as part of the DER
encoding, making it a cryptographic input to the principal's signature
-- not a plaintext parameter. The CA verifies nonce uniqueness at
issuance time and persists used nonces. The gateway MAY optionally
maintain a local NonceCache for additional replay detection, but this
is not required: the primary defense is the CA-level uniqueness check.
Replay protection is therefore enforced at the CA issuance layer
(nonce uniqueness at issuance time), not at the gateway runtime; the
gateway's optional cache is a secondary defense only.

# IANA Considerations

## Private Enterprise Number Assignment

This document uses the IANA Private Enterprise Number 66257, assigned
to Varwof PKI (contact: Jijie Wei, pki@varwof.com). The OID prefix is:

~~~
1.3.6.1.4.1.66257
~~~

## OID Registration

The following OIDs are defined in this document:

1.3.6.1.4.1.66257.1.1:
: AIC Extension (Section AIC Extension Definition)

1.3.6.1.4.1.66257.1.2:
: PrincipalAuthorization Extension (Section PrincipalAuthorization)

1.3.6.1.4.1.66257.1.1.4:
: DelegationDepthControl (Section Multi-Level Delegation)

Additional OIDs under branch 3 (National/Industry Certification) are
reserved for future allocation. The full OID tree is defined in
Section OID Tree.

## Capability Scheme Registry

This version of the specification does not request an IANA registry.
Capability scheme identifiers and constraint types are registered
through an external or community registry of scheme identifiers,
which follows the vendor/product naming convention. An IANA registry
may be requested in a future revision if the scheme namespace is
transitioned to IANA administration.

The initial entry in the external registry:

| Scheme Identifier | Description | Reference |
|-------------------|-------------|-----------|
| varwof/constraint-v1 | Authorization boundary constraint (allowed-cidr, max-concurrent, time-window) | This document |

The `http` and `database` scheme identifiers are reserved as examples
of externally defined capability schemes; their semantics are defined
by the capability schemes themselves and not by this document.

# Implementation Status

Per [RFC7942], this specification is supported by a reference
implementation.  The implementation is written in Go (standard
library only, no CGO) and covers certificate issuance with
authorizationConstraints, AIC extension parsing,
DelegationAuthorization signature verification, permission
intersection (P (AND) C (AND) T) decisions, capability plugin
routing, revocation, and fully offline constraint validation.  The
companion AIC-JWT profile [AIC-JWT] is implemented in Go and in
TypeScript/WebCrypto for browser-compatible runtimes, with a
publicly accessible browser demo at https://varwof.org/aicjwt/.

The implementation is publicly available at:

* https://github.com/varwof/types -- shared types, including the AIC
  extension structures and the AIC-JWT core (Apache-2.0),
  release v0.6.0;
* https://github.com/varwof/core -- PKI engine and certificate
  issuance (AGPL-3.0), release v0.4.0;
* https://github.com/varwof/engine -- in-memory PKI data engine
  (AGPL-3.0), release v0.2.0;
* https://github.com/varwof/gateway-core and
  https://github.com/varwof/gateway -- zero-trust gateways
  (Apache-2.0), gateway-core release v0.5.0 and gateway release v0.1.0;
* https://github.com/varwof/aic-jwt -- AIC-JWT implementation
  (Go wrapper and TypeScript/WebCrypto pipeline, Apache-2.0);
* https://github.com/varwof/client -- command-line client
  (Apache-2.0), release v0.3.0.

Language ports of the AIC extension structures and validation
logic are also published: C/OpenSSL (https://github.com/varwof/openaic),
Java (https://github.com/varwof/aic-lib-java), and .NET
(https://github.com/varwof/aic-lib-dotnet), all Apache-2.0.

The capability language that AIC composes with [CLC] is implemented and
published as well, under one shared release tag (`clc-v1.16`):

* https://github.com/varwof/capability -- the language specification and
  its conformance corpora;
* https://github.com/varwof/register -- the Go implementation of the
  decision semantics and the rule toolchain;
* https://github.com/varwof/aic-capability-demo -- Python and TypeScript
  implementations of the same semantics, with a browser demo.

The three implementations are exercised against the shared corpora in
CI, so the language this specification defers to has running code as well
as a document.

Test status (2026-10-02): the Go modules in the reference stack (pkcs7, types, engine, register, core, gateway-core, gateway and client) build and all of their test suites pass (go build ./... and go test -count=1 ./...), including the certificate authority and HTTP serving packages.  The AIC-JWT module's Go tests pass, and its TypeScript tests pass (nine demo cases and twenty-four unit cases, node --test).  The implementation status of the AIC-JWT profile, including its test suites, is documented in [AIC-JWT].

Interoperability: an independent implementation of the AIC mapping
boundary -- the EMILIA crossing profile, which consumes native AIC
verifier results and binds them to one exact action and one
relying-party admission domain -- reproduces the committed results for all twenty cases
(positive, hostile and mapping) against the same pinned sources.  The kit,
including its source lock, is published in the EMILIA protocol repository
at conformance/composition/aic-aeb-crossing-v0.2.


SPIFFE conformance (informative, 2026-09-04): byte-level
conformance of SPIFFE ID construction and of issued-certificate
SANs against the SPIRE reference parser (go-spiffe v2.8.1,
spiffeid package) is covered by the core test suite.  The gateway
enforces trust-domain and exact SPIFFE allowlists and fails closed
when a required SPIFFE ID is absent, malformed, or out of scope.

Performance characteristics (informative; measured 2026-08-27 on an
18-core x86 server, engine mode with MySQL; methodology and raw
results at
https://github.com/varwof/core/docs/bench/en/benchmark-report-2026-08-27.md):

* Enterprise steady state: 833 AIC certificates/s (500,000 agents,
  one certificate per agent per 10 minutes) at p50 = 2.4 ms and
  p99 = 5.0 ms, 0.00% error rate, approximately 7x headroom below
  the measured ceiling;
* Single-machine ceiling: approximately 6,100 AIC certificates/s
  (8,040/s with turbo boost), dominated by ECDSA signing and
  DelegationAuthorization verification;
* Worst-case burst: 500,000 simultaneous issuance requests drain in
  approximately 82 s with no dropped requests when the in-memory
  engine budget is sized accordingly;
* Low-end hardware: a Raspberry Pi 5 (4-core, 2.4 GHz) sustains the
  833/s steady state at p99 = 330 ms with approximately 2.5x
  headroom.

# Interoperability

## Relationship to WIMSE and SPIFFE

WIMSE and SPIFFE identify workloads through SAN URIs ([SPIFFE]);
they do not carry authorization data.  AIC composes with them at
the certificate layer: an AIC-enabled certificate MAY carry a
SPIFFE ID as its URI SAN, and a verifier that enforces AIC
admission MAY use the SPIFFE ID as the identity selector for the
admission decision.

The AIC-specific rules in this composition are limited to the
following:

* **Identifier mapping.**  When a certificate carries a SPIFFE ID,
  the AIC extension's agentId is the agent name, corresponding to
  the final path segment of the SPIFFE ID; the full spiffe:// URI
  appears in the certificate SAN.  New issuance MUST use the
  plain-name form in agentId.  Certificates issued by earlier
  revisions that stored the full URI in agentId MAY be accepted for
  backward compatibility, but a relying party MUST NOT treat the SAN
  URI and agentId as independent identities.

* **Verification semantics by reference.**  This specification does
  not redefine SPIFFE ID syntax or validation.  A verifier that
  enforces a SPIFFE requirement (for example, require-SPIFFE, a
  trust-domain allowlist, or an exact SPIFFE ID allowlist) MUST
  validate the SAN URI according to [SPIFFE] and MUST fail closed
  when the URI is absent, malformed, outside the allowed trust
  domain, or outside the allowlist.

* **Renewal continuity.**  SPIFFE/SPIRE-style workloads commonly
  rotate short-lived SVIDs.  AIC anchors identity to the subject
  public key via principalUid.keyHash rather than to the certificate
  fingerprint (see Principal Key Rotation); a renewed SVID that
  reuses the same key therefore preserves the agent identity and its
  issued authorization without re-issuance or cascading re-signing.
  Authorization breaks on key change, not on certificate renewal.

Workload API delivery, SVID rotation protocols, and cross-trust-
domain federation are outside the scope of this specification; they
belong to the SPIFFE/SPIRE ecosystem.  AIC's role in that ecosystem
is certificate-format and offline-verification compatibility, not
the replacement of workload identity lifecycle mechanisms.

The reference implementation issues certificates carrying
spiffe:// SANs and enforces trust-domain and allowlist checks at the
gateway; byte-level conformance of the SPIFFE ID construction and
issued-certificate SAN against the SPIRE reference parser is
covered by the implementation test suite (see Implementation
Status).


## Relationship to Standard X.509 Extensions

### Key Usage and Extended Key Usage

AIC-enabled certificates SHOULD include the digitalSignature key usage
([RFC5280] Section 4.2.1.3). Extended Key Usage MUST include
id-kp-clientAuth when the certificate is used for TLS client
authentication.

### Basic Constraints

AIC Agent certificates MUST have BasicConstraints CA:FALSE. CA
issuance MUST reject any request where the requester holds an AIC
certificate, preventing Agent-to-Agent chaining in single-level
deployment mode. In a delegation chain of depth 1, the sub-agent's
DelegationAuthorization is anchored to the delegating agent's AIC
certificate; as a best practice, the CA SHOULD NOT issue a certificate
with DelegationDepthControl.maxDepth greater than 1.

## Interoperability Test Matrix

| Scenario | AIC Gateway Behavior | Legacy Client Behavior | Compatibility |
|----------|---------------------|----------------------|---------------|
| Client without AIC extension | Reject if RequireAIC=true; pass-through if false | Normal mTLS | Config-dependent |
| Client with AIC | Full admission pipeline | AIC extension ignored | Yes |
| Multiple capabilities (<=64) | Full parse and evaluate | Ignored | Yes |
| Multiple capabilities (>256) | Reject (DoS protection) | Ignored | Limited |
| Unknown capability scheme | Deny | Ignored | Limited |
| OCSP MUST-Staple missing | Reject | Normal OCSP | No |
| Offline + no CRL cache | Fail-Close (reject) | Fail-Open (allow) | No |

## TLS Integration

### Handshake Requirements

The AIC extension does not introduce a new TLS handshake protocol.
Instead, it leverages the existing X.509 certificate chain presented
during TLS 1.3 handshakes. When a TLS server requires AIC-authenticated
connections, it SHOULD include the AIC OID in the CertificateRequest
message.

### TLS Alert Codes

The following is a recommended mapping from AIC conditions to the
official TLS alert codes defined in the IANA TLS Alert Registry
([RFC9846]); implementations MAY choose appropriate alerts in
accordance with the TLS specification.

| Condition | TLS Alert | Code | Description |
|-----------|----------|------|-------------|
| AIC required but missing | unsupported_extension | 116 | Client MUST include AIC |
| AIC malformed | bad_certificate | 42 | Parsing failure |
| Capability not authorized | certificate_unknown | 46 | Permission denied |
| Impersonation without DA | access_denied | 49 | Missing authorization |
| Certificate expired/revoked | certificate_expired | 45 | Lifecycle check failed |

# Limitations

This specification has the following limitations:

1. **Delegation depth**: This revision defines semantics for two depths
   only: single-level delegation (Principal -> Agent, chainDepth = 0),
   which is the default and the recommended configuration, and one
   additional level (Principal -> Agent -> sub-Agent, chainDepth = 1).
   Chains deeper than 1 are not refused by this specification, but they
   are outside its scope: responsibility boundaries blur as the chain
   grows, and conformance does not cover them.

2. **No distributed state**: Multi-gateway deployments require
   out-of-band state synchronization (nonce cache, concurrency
   tracking).

3. **Static capability evaluation**: The pure container design defers
   all semantic validation to gateway plugins. Dynamic, context-aware
   policy evaluation is not in scope.

4. **UDP/DTLS transport**: AIC for TCP/TLS and QUIC is fully specified.
   Non-TLS UDP/DTLS transport is reserved for a future revision.

5. **Post-quantum readiness**: Algorithm OIDs for hybrid and PQC suites
   are reserved but signature exchange is not yet specified.

6. **Deployment scale**: Enterprise-scale validation with >1M agents
   is not yet published.



# Appendix A. Name Disambiguation

The agent-identity space contains several similar acronyms.  This
appendix distinguishes them to avoid citation and interoperability
confusion.

| Name | This document | Related use |
|---|---|---|
| AIC | AI Agent Identity Certificate (draft-wei-aic-identity-cert): X.509 v3 extension with principal-signed DelegationAuthorization and capability containers; companion JWT profile (draft-wei-aic-jwt) | The acronym used in this document and in its companion drafts |
| AgentIdentity / "AIC" | draft-sharif-x509-agent-identity-profile (CyberSecAI) | A single X.509 extension carrying trust level, flat capability names, delegation depth, and kill-switch URI; owner binding is textual, not a signed delegation |
| AIP | Agent Identity Protocol (draft-singla-agent-identity-protocol) | DID-based (did:aip) identity, capability manifests, and delegation chains resolved through an online registry |
| OpenA2A AIP | OpenA2A Agent Identity Protocol (draft-fane-opena2a-aip) | did:opena2a identifiers and ATX registry credentials; authorization handled in a companion protocol |
| DAAP | Delegated Agent Authorization Protocol (draft-mishra-oauth-agent-grants) | OAuth 2.0 profile for delegated agent authorization |

Readers and authors citing this specification SHOULD use the full
title "AI Agent Identity Certificate (AIC) Extension for X.509 v3" or
the document name draft-wei-aic-identity-cert, and SHOULD NOT use the
bare acronym "AIC" to refer to other proposals.

# Intellectual Property

This document is subject to BCP 79 (RFC 8179). The author has filed
patent applications related to the technologies described in this
document, including Chinese patent applications CN2026112384541 and
CN2026112384607 (filed with the China National Intellectual Property
Administration). The author has filed IPR disclosure 7553 with the
IETF in accordance with BCP 79 requirements. Any applicable IPR
disclosures are available through the IETF IPR disclosure system.

# Acknowledgments

The author thanks the IETF community for ongoing discussions on agent
identity and accountability frameworks.

# Change Log


draft-wei-aic-identity-cert-02 (2026-10-02):

* Added Appendix A (Name Disambiguation): distinguishes this AIC from
  AgentIdentity/CyberSecAI, AIP (Singla), OpenA2A AIP (Fane), and DAAP.
* Corrected and expanded Related Work: the Singla AIP is now cited
  under its own name (previously mislabeled "OpenA2A"); added the
  OpenA2A Agent Identity Protocol (Fane); refreshed descriptions for
  the -03 revisions.
* Clarified the delegation-depth posture: a single hop from the
  principal to the acting agent (chainDepth = 0) is recommended for the
  strongest accountability; multi-level delegation is not refused by
  this specification, but conformance targets chainDepth 0 and 1, and
  deeper chains are outside its scope.  Responsibility boundaries blur
  as the chain grows (the legal status of intermediate agents and the
  audit actor semantics become ambiguous).  Guardrails for a future
  revision are stated: per-hop signed authorization, monotonic
  intersection, bounded depth and loop prevention, root-principal
  attribution, and legal basis at each hop.

* Added Relationship to WIMSE and SPIFFE: SPIFFE IDs are carried in
  SAN URIs with plain-name agentId semantics; SPIFFE syntax and
  validation are incorporated by reference; renewal continuity via
  keyHash is documented; Workload API and SVID lifecycle mechanisms
  are out of scope.
* Added a normative same-trust-anchor requirement: the agent
  certificate chain and the principal certificate chain MUST validate
  to the same configured trust anchor; verifiers MUST reject chains
  that terminate at different trust anchors (Validation Procedure,
  Deployment Models).
* Clarified the trust boundary in Security Considerations: AIC assumes
  a trusted-CA model; CA or trust-anchor compromise is outside the
  protection scope of this specification, and CA signing keys MUST be
  protected accordingly. The authorization-forgery mitigation is
  narrowed to non-CA adversaries.
* Added a renewal rule: certificate renewal or re-issuance MUST be
  backed by a new principal-signed DelegationAuthorization carrying a
  fresh nonce; prior DelegationAuthorizations MUST NOT be reused.
* Added DelegationAuthorization version 2: `agentKeyBinding` binds the
  authorization to the agent public key (`keyHash = hashAlgo(SPKI DER)`,
  default SHA-256, SHA-1 disallowed, unknown algorithms rejected without
  fallback), with a normative version/validation matrix (version 1 legacy
  must omit the binding, version 2 must carry a valid one, newly issued
  DAs must be version 2, other version values rejected) and a verifier
  check that cross-verifies `hashAlgo(agent certificate SPKI)` against the
  binding.
* Documented the version mapping to the AIC-JWT profile: X.509 AIC DA v1
  corresponds to AIC-JWT `da.ver=2`, and X.509 DA v2 to `da.ver=3`; a
  `da.ver=3` token must carry the equivalent `agent_key_binding`.
* Added document-level references to the Capability Language Core [CLC]
  in the authorization-language, intersection, containment and
  capability-scheme sections.
* Refreshed the Implementation Status: current release numbers for the
  reference stack, tests re-run on 2026-10-02, the EMILIA crossing profile
  now reproducing all twenty of its cases, SPIFFE byte-level conformance,
  and the three published implementations of the capability language
  ([CLC]).
draft-wei-aic-identity-cert-01 (2026-08-30):

* Added public reference-implementation repository URLs with pinned
  release snapshots, test status, independent-implementation
  interoperability results, and measured performance characteristics
  (informative) to the Implementation Status section.
* Added informative reference to the AIC-JWT companion profile
  [AIC-JWT].
* Listed additional language ports (C/OpenSSL, Java, .NET).
* Aligned patent application numbers with IPR disclosure 7553
  (CN2026112384541, CN2026112384607).

draft-wei-aic-identity-cert-00 (2026-08-18):
* Initial individual draft.
