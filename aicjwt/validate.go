package aicjwt

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"
)

const (
	TypOuter                  = "aic+jwt"
	TypDA                     = "aic+da+jwt"
	TypPA                     = "aic+pa+jwt"
	ModeAuthorized            = "authorized"
	ModeRepresentative        = "representative"
	ConstraintScheme          = "varwof/constraint-v1"
	MaxLifetime               = 86400
	AllowedModeRepresentative = "representative_allowed"
)

// CapabilityPlugin evaluates a request capability for a scheme.  The
// gateway routes evaluation by schemeId (draft Section 6.1); unknown
// schemes MUST be rejected (fail-closed).
type CapabilityPlugin func(req Capability, ctx RequestContext) error

// StatusChecker validates a Token Status List reference
// (draft-ietf-oauth-status-list).
type StatusChecker func(ref StatusRef) error

// NonceStore records used nonces (DA nonce / jti) for replay
// prevention.
type NonceStore interface {
	CheckAndAdd(nonce string) error
}

// VerifyOptions configures the validation pipeline.
type VerifyOptions struct {
	Now                  time.Time
	ExpectedIssuer       string
	ExpectedAudience     []string
	IssuerKeys           map[string]crypto.PublicKey // kid -> issuer public key
	PrincipalMaterial    *PrincipalKeyMaterial       // optional credential bundle
	PrincipalJWKS        map[string]crypto.PublicKey // kid -> principal public key (online)
	PresenterKey         crypto.PublicKey            // optional, for cnf proof-of-possession
	RequestCapability    *Capability                 // capability required by the current request
	RequestContext       RequestContext
	ConstraintStrict     bool
	CapabilityPlugins    map[string]CapabilityPlugin
	StatusChecker        StatusChecker
	NonceStore           NonceStore
	RejectDepthGT1       bool
	RequireJtiNonceMatch bool
	PA                   *PAClaims // optional PrincipalAuthorization material
}

// Decision is the outcome of the validation pipeline.
type Decision struct {
	Permit       bool
	Actor        string // audit actor (draft Section 8.1)
	Principal    string // audit principal identifier
	Capabilities []Capability
	Notes        []string
}

func (o VerifyOptions) withDefaults() VerifyOptions {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	return o
}

// Validate executes the 11-step pipeline of draft Section 11.
func Validate(token string, opts VerifyOptions) (*Decision, error) {
	opts = opts.withDefaults()

	// ---- Step 1: parse + verify the outer JWS ----------------------
	hb, pb, _, err := ParseCompact(token)
	if err != nil {
		return nil, fmt.Errorf("step1: %w", err)
	}
	var hdr Header
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("step1: outer header malformed: %w", err)
	}
	// ---- Step 2: header checks --------------------------------------
	if err := CheckHeader(hdr, TypOuter); err != nil {
		return nil, fmt.Errorf("step2: %w", err)
	}
	issuerKey, ok := opts.IssuerKeys[hdr.Kid]
	if !ok {
		return nil, fmt.Errorf("step2: unknown issuer kid %q", hdr.Kid)
	}
	if err := VerifyCompact(token, hdr.Alg, issuerKey); err != nil {
		return nil, fmt.Errorf("step1: outer signature invalid: %w", err)
	}
	var outer OuterClaims
	if err := json.Unmarshal(pb, &outer); err != nil {
		return nil, fmt.Errorf("step1: outer payload malformed: %w", err)
	}
	if err := checkOuterRequired(&outer); err != nil {
		return nil, fmt.Errorf("step1: %w", err)
	}

	// ---- Step 3: time checks ----------------------------------------
	if err := checkTime(&outer, opts.Now); err != nil {
		return nil, fmt.Errorf("step3: %w", err)
	}

	// ---- Step 4: DA validation --------------------------------------
	var da *DAClaims
	if outer.Da != "" {
		d, err := validateDA(&outer, opts)
		if err != nil {
			return nil, fmt.Errorf("step4: %w", err)
		}
		da = d
	} else if outer.Aic.DelegationMode == ModeRepresentative {
		return nil, fmt.Errorf("step4: representative mode requires a DA JWT")
	} else if outer.Exp-outer.Iat > MaxLifetime {
		return nil, fmt.Errorf("step3: lightweight profile lifetime %d exceeds max %d", outer.Exp-outer.Iat, MaxLifetime)
	}

	// ---- Step 5: consistency checks ---------------------------------
	if da != nil {
		if err := checkConsistency(&outer, da); err != nil {
			return nil, fmt.Errorf("step5: %w", err)
		}
	}

	// ---- Step 6: PA check (representative) --------------------------
	if outer.Aic.DelegationMode == ModeRepresentative {
		if err := checkPA(&outer, opts); err != nil {
			return nil, fmt.Errorf("step6: %w", err)
		}
	}

	// ---- Step 7: constraint evaluation ------------------------------
	notes, err := EvaluateConstraints(outer.Aic.Constraints, opts.RequestContext, opts.ConstraintStrict)
	if err != nil {
		return nil, fmt.Errorf("step7: aic.constraints: %w", err)
	}

	// ---- Step 8: delegation depth check -----------------------------
	if err := checkDepth(outer.Aic, opts); err != nil {
		return nil, fmt.Errorf("step8: %w", err)
	}

	// ---- Step 9: capability evaluation ------------------------------
	if opts.RequestCapability != nil {
		if !MatchCapabilities(outer.Aic.Capabilities, *opts.RequestCapability) {
			return nil, fmt.Errorf("step9: capability %s:%s not allowed by aic.capabilities",
				opts.RequestCapability.Scheme, opts.RequestCapability.ID)
		}
		plugin, ok := opts.CapabilityPlugins[opts.RequestCapability.Scheme]
		if !ok {
			return nil, fmt.Errorf("step9: unknown capability scheme %q (fail-closed)", opts.RequestCapability.Scheme)
		}
		if err := plugin(*opts.RequestCapability, opts.RequestContext); err != nil {
			return nil, fmt.Errorf("step9: scheme plugin denies %s:%s: %w",
				opts.RequestCapability.Scheme, opts.RequestCapability.ID, err)
		}
	}

	// ---- Step 10: status check --------------------------------------
	if outer.Status != nil {
		if opts.StatusChecker == nil {
			return nil, fmt.Errorf("step10: status claim present but no status checker configured")
		}
		if err := opts.StatusChecker(*outer.Status); err != nil {
			return nil, fmt.Errorf("step10: token status check failed: %w", err)
		}
	}

	// ---- issuer / audience / presenter binding ----------------------
	if opts.ExpectedIssuer != "" && outer.Iss != opts.ExpectedIssuer {
		return nil, fmt.Errorf("iss %q does not match expected issuer %q", outer.Iss, opts.ExpectedIssuer)
	}
	if len(opts.ExpectedAudience) > 0 {
		matched := false
		for _, a := range opts.ExpectedAudience {
			if outer.Aud.Contains(a) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("aud %v does not include any of %v (audience confusion)", outer.Aud, opts.ExpectedAudience)
		}
	}
	if opts.PresenterKey != nil {
		if outer.Cnf == nil || outer.Cnf.Jkt == "" {
			return nil, fmt.Errorf("cnf claim required but missing")
		}
		thumb, err := KeyHashOf(opts.PresenterKey, "jkt")
		if err != nil {
			return nil, fmt.Errorf("cnf: cannot compute presenter thumbprint: %w", err)
		}
		if thumb != outer.Cnf.Jkt {
			return nil, fmt.Errorf("cnf: presenter key does not match token cnf.jkt (token theft)")
		}
	}

	// ---- Decision ----------------------------------------------------
	actor := outer.Sub
	if outer.Aic.DelegationMode == ModeRepresentative {
		actor = outer.Aic.Principal.ID
	}
	return &Decision{
		Permit:       true,
		Actor:        actor,
		Principal:    outer.Aic.Principal.ID,
		Capabilities: outer.Aic.Capabilities,
		Notes:        notes,
	}, nil
}

// CheckHeader validates a JOSE header against the expected typ,
// the algorithm allowlist and the kid requirement (draft Section 11,
// step 2).
func CheckHeader(h Header, expectedTyp string) error {
	if h.Typ != expectedTyp {
		return fmt.Errorf("unexpected typ %q (expected %q)", h.Typ, expectedTyp)
	}
	if h.Alg == "" || h.Alg == "none" {
		return fmt.Errorf("alg missing or none")
	}
	if !AllowedAlgs[h.Alg] {
		return fmt.Errorf("alg %q not in allowlist", h.Alg)
	}
	if h.Kid == "" {
		return fmt.Errorf("kid required")
	}
	for _, c := range h.Crit {
		return fmt.Errorf("unsupported critical header %q", c)
	}
	return nil
}

func checkOuterRequired(o *OuterClaims) error {
	if o.Iss == "" {
		return fmt.Errorf("iss required")
	}
	if o.Sub == "" || len(o.Sub) > 256 {
		return fmt.Errorf("sub (agentId) required, 1..256 chars")
	}
	if len(o.Aud) == 0 {
		return fmt.Errorf("aud required")
	}
	if o.Iat == 0 || o.Exp == 0 || o.Exp <= o.Iat {
		return fmt.Errorf("iat/exp required and exp must be after iat")
	}
	if o.Jti == "" {
		return fmt.Errorf("jti required")
	}
	if o.Cnf == nil || o.Cnf.Jkt == "" {
		return fmt.Errorf("cnf required")
	}
	if o.Aic == nil {
		return fmt.Errorf("aic claim required")
	}
	if o.Aic.Ver != 1 {
		return fmt.Errorf("aic.ver must be 1")
	}
	p := o.Aic.Principal
	if p.Realm == "" || len(p.Realm) > 128 || p.ID == "" || len(p.ID) > 256 || p.KeyHash == "" {
		return fmt.Errorf("aic.principal realm/id/key_hash required within size limits")
	}
	alg := p.HashAlg
	if alg == "" {
		alg = "sha-256"
	}
	if _, ok := SupportedHashAlgs[alg]; !ok {
		return fmt.Errorf("unsupported aic.principal.hash_alg %q", p.HashAlg)
	}
	if o.Aic.DelegationMode != ModeAuthorized && o.Aic.DelegationMode != ModeRepresentative {
		return fmt.Errorf("aic.delegation_mode must be %q or %q", ModeAuthorized, ModeRepresentative)
	}
	if len(o.Aic.Capabilities) < 1 || len(o.Aic.Capabilities) > 256 {
		return fmt.Errorf("aic.capabilities must contain 1..256 entries")
	}
	if len(o.Aic.Constraints) > 32 {
		return fmt.Errorf("aic.constraints must not exceed 32 entries")
	}
	if len(o.Aic.Extensions) > 32 {
		return fmt.Errorf("aic.extensions must not exceed 32 entries")
	}
	return nil
}

func checkTime(o *OuterClaims, now time.Time) error {
	nowUnix := now.Unix()
	if o.Nbf != nil && nowUnix < *o.Nbf {
		return fmt.Errorf("token not yet valid (nbf)")
	}
	if nowUnix > o.Exp {
		return fmt.Errorf("token expired")
	}
	return nil
}

func checkDARequired(d *DAClaims) error {
	if d.Ver != 1 {
		return fmt.Errorf("DA ver must be 1")
	}
	if d.AgentID == "" || len(d.AgentID) > 256 {
		return fmt.Errorf("DA agent_id required, 1..256 chars")
	}
	if d.Principal.Realm == "" || d.Principal.ID == "" || d.Principal.KeyHash == "" {
		return fmt.Errorf("DA principal required")
	}
	if d.Reason.Code == "" || d.Reason.Desc == "" {
		return fmt.Errorf("DA reason.code and reason.desc required")
	}
	if len(d.Capabilities) < 1 || len(d.Capabilities) > 256 {
		return fmt.Errorf("DA capabilities must contain 1..256 entries")
	}
	if d.DelegationMode != ModeAuthorized && d.DelegationMode != ModeRepresentative {
		return fmt.Errorf("DA delegation_mode invalid")
	}
	if len(d.Constraints) > 32 {
		return fmt.Errorf("DA constraints must not exceed 32 entries")
	}
	if d.RequestedLifetime < 1 || d.RequestedLifetime > MaxLifetime {
		return fmt.Errorf("DA requested_lifetime must be in 1..%d", MaxLifetime)
	}
	if d.TS == 0 {
		return fmt.Errorf("DA ts required")
	}
	if d.Nonce == "" {
		return fmt.Errorf("DA nonce required")
	}
	return nil
}

// ValidateDA validates a DA JWT in isolation: header checks, required
// claims, signature, principal binding and nonce.  It is used by the
// validation pipeline and by the authorization server issuance flow.
func ValidateDA(daToken string, opts VerifyOptions) (*DAClaims, error) {
	hb, pb, _, err := ParseCompact(daToken)
	if err != nil {
		return nil, fmt.Errorf("DA parse: %w", err)
	}
	var hdr Header
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("DA header malformed: %w", err)
	}
	if err := CheckHeader(hdr, TypDA); err != nil {
		return nil, err
	}
	var da DAClaims
	if err := json.Unmarshal(pb, &da); err != nil {
		return nil, fmt.Errorf("DA payload malformed: %w", err)
	}
	if err := checkDARequired(&da); err != nil {
		return nil, err
	}
	pub, err := resolvePrincipalKey(da.Principal, hdr.Kid, opts)
	if err != nil {
		return nil, err
	}
	if err := VerifyCompact(daToken, hdr.Alg, pub); err != nil {
		return nil, fmt.Errorf("DA signature invalid: %w", err)
	}
	alg := da.Principal.HashAlg
	if alg == "" {
		alg = "sha-256"
	}
	binding, err := KeyHashOf(pub, alg)
	if err != nil {
		return nil, err
	}
	if binding != da.Principal.KeyHash {
		return nil, fmt.Errorf("DA principal key_hash mismatch")
	}
	nonceBytes, err := b64uDecode(da.Nonce)
	if err != nil || len(nonceBytes) != 32 {
		return nil, fmt.Errorf("DA nonce must be the base64url of 32 bytes")
	}
	if opts.NonceStore != nil {
		if err := opts.NonceStore.CheckAndAdd(da.Nonce); err != nil {
			return nil, fmt.Errorf("DA nonce reuse: %w", err)
		}
	}
	return &da, nil
}

func validateDA(outer *OuterClaims, opts VerifyOptions) (*DAClaims, error) {
	da, err := ValidateDA(outer.Da, opts)
	if err != nil {
		return nil, err
	}
	if opts.RequireJtiNonceMatch && outer.Jti != da.Nonce {
		return nil, fmt.Errorf("outer jti does not match DA nonce")
	}
	if outer.Exp-outer.Iat > int64(da.RequestedLifetime) {
		return nil, fmt.Errorf("token lifetime %d exceeds DA requested_lifetime %d", outer.Exp-outer.Iat, da.RequestedLifetime)
	}
	return da, nil
}

func resolvePrincipalKey(p Principal, kid string, opts VerifyOptions) (crypto.PublicKey, error) {
	if opts.PrincipalMaterial != nil {
		if kid != "" && opts.PrincipalMaterial.JWK != nil {
			if j, ok := opts.PrincipalMaterial.JWK[kid]; ok {
				return JWKToPublic(j)
			}
		}
		if pub, err := opts.PrincipalMaterial.LookupByBinding(p); err == nil {
			return pub, nil
		}
	}
	if opts.PrincipalJWKS != nil && kid != "" {
		if pub, ok := opts.PrincipalJWKS[kid]; ok {
			return pub, nil
		}
	}
	return nil, fmt.Errorf("principal key not resolvable (kid %q)", kid)
}

func checkConsistency(o *OuterClaims, da *DAClaims) error {
	if da.AgentID != o.Sub {
		return fmt.Errorf("DA agent_id %q != outer sub %q", da.AgentID, o.Sub)
	}
	if ok, _ := jsonEqual(da.Principal, o.Aic.Principal); !ok {
		return fmt.Errorf("DA principal != outer aic.principal")
	}
	if da.DelegationMode != o.Aic.DelegationMode {
		return fmt.Errorf("DA delegation_mode != outer aic.delegation_mode")
	}
	if ok, _ := jsonEqual(da.Capabilities, o.Aic.Capabilities); !ok {
		return fmt.Errorf("DA capabilities != outer aic.capabilities")
	}
	if ok, _ := jsonEqual(da.Constraints, o.Aic.Constraints); !ok {
		return fmt.Errorf("DA constraints != outer aic.constraints")
	}
	return nil
}

func checkPA(o *OuterClaims, opts VerifyOptions) error {
	pa := opts.PA
	if pa == nil {
		return fmt.Errorf("representative mode requires PrincipalAuthorization material")
	}
	if pa.Ver != 1 {
		return fmt.Errorf("PA ver must be 1")
	}
	if ok, _ := jsonEqual(pa.Principal, o.Aic.Principal); !ok {
		return fmt.Errorf("PA principal != outer aic.principal")
	}
	if pa.DelegationPolicy == nil || pa.DelegationPolicy.AllowedMode != AllowedModeRepresentative {
		return fmt.Errorf("delegation policy does not allow representative mode")
	}
	for _, c := range o.Aic.Capabilities {
		if !CapabilitySubset(c, pa.Grants) {
			return fmt.Errorf("capability %s:%s not within P_grants", c.Scheme, c.ID)
		}
	}
	if _, err := EvaluateConstraints(pa.Constraints, opts.RequestContext, opts.ConstraintStrict); err != nil {
		return fmt.Errorf("PA constraints: %w", err)
	}
	return nil
}

func checkDepth(a *AICClaims, opts VerifyOptions) error {
	if a.ChainDepth < 0 || a.ChainDepth > 255 {
		return fmt.Errorf("chain_depth out of range")
	}
	if a.MaxDepth < 0 || a.MaxDepth > 255 {
		return fmt.Errorf("max_depth out of range")
	}
	if a.ChainDepth > a.MaxDepth {
		return fmt.Errorf("chain_depth %d exceeds max_depth %d", a.ChainDepth, a.MaxDepth)
	}
	if opts.RejectDepthGT1 && a.MaxDepth > 1 {
		return fmt.Errorf("max_depth %d exceeds recommended limit 1", a.MaxDepth)
	}
	return nil
}
