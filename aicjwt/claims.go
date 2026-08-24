// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	pki "github.com/varwof/types"
	"reflect"
)

// Header is the JOSE protected header shared by all AIC-JWT token
// types (draft Sections 4.2-4.4).
type Header struct {
	Alg  string   `json:"alg"`
	Typ  string   `json:"typ"`
	Kid  string   `json:"kid"`
	Crit []string `json:"crit,omitempty"`
	JWK  *JWK     `json:"jwk,omitempty"` // used by DPoP proofs (RFC 9449)
}

// Audience accepts a JSON string or an array of strings (RFC 9068).
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = []string{s}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return fmt.Errorf("aud must be a string or an array of strings: %w", err)
	}
	*a = l
	return nil
}

// Contains reports whether aud includes v.
func (a Audience) Contains(v string) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}

// Cnf is the RFC 7800 confirmation claim (jkt form).
type Cnf struct {
	Jkt string `json:"jkt"`
}

// StatusRef references a Token Status List entry
// (draft-ietf-oauth-status-list).
type StatusRef struct {
	Idx int    `json:"idx"`
	URI string `json:"uri"`
}

// Principal is the principalUid equivalent (draft Section 5.1.2).
type Principal struct {
	Realm   string `json:"realm"`
	ID      string `json:"id"`
	KeyHash string `json:"key_hash"`
	HashAlg string `json:"hash_alg"`
}

// Capability is the unified container (draft Section 6.1), reused in
// aic.capabilities, aic.constraints and PA grants.
type Capability struct {
	Scheme string          `json:"scheme"`
	ID     string          `json:"id"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Extension mirrors the AICExtensions slot.
type Extension struct {
	Critical bool            `json:"critical"`
	Value    json.RawMessage `json:"value"`
}

// AICClaims is the "aic" claim (draft Section 5.1.2).
type AICClaims struct {
	Ver            int                  `json:"ver"`
	Principal      Principal            `json:"principal"`
	DelegationMode string               `json:"delegation_mode"`
	Capabilities   []Capability         `json:"capabilities"`
	Constraints    []Capability         `json:"constraints,omitempty"`
	ChainDepth     int                  `json:"chain_depth,omitempty"`
	MaxDepth       int                  `json:"max_depth,omitempty"`
	Extensions     map[string]Extension `json:"extensions,omitempty"`
}

// OuterClaims is the outer AIC-JWT payload (draft Section 5.1).
type OuterClaims struct {
	Iss          string          `json:"iss"`
	Sub          string          `json:"sub"`
	Aud          Audience        `json:"aud"`
	Iat          int64           `json:"iat"`
	Exp          int64           `json:"exp"`
	Nbf          *int64          `json:"nbf,omitempty"`
	Jti          string          `json:"jti"`
	Cnf          *Cnf            `json:"cnf"`
	Scope        string          `json:"scope,omitempty"`
	ClientID     string          `json:"client_id,omitempty"`
	Status       *StatusRef      `json:"status,omitempty"`
	Aic          *AICClaims      `json:"aic"`
	Da           string          `json:"da,omitempty"`
	AuthzDetails json.RawMessage `json:"authorization_details,omitempty"`
}

// Reason is the delegation reason (draft Section 5.2).
type Reason struct {
	Code string `json:"code"`
	Desc string `json:"desc"`
}

// DAClaims is the inner DA JWT payload, the JSON equivalent of
// DelegationAuthTBS (draft Section 5.2). All ten members are required.
type DAClaims struct {
	Ver               int          `json:"ver"`
	AgentID           string       `json:"agent_id"`
	Principal         Principal    `json:"principal"`
	Reason            Reason       `json:"reason"`
	Capabilities      []Capability `json:"capabilities"`
	DelegationMode    string       `json:"delegation_mode"`
	Constraints       []Capability `json:"constraints,omitempty"`
	RequestedLifetime int          `json:"requested_lifetime"`
	TS                int64        `json:"ts"`
	Nonce             string       `json:"nonce"`
}

// DelegationPolicy is the JSON equivalent of the ASN.1
// DelegationPolicy (draft Section 5.3).
type DelegationPolicy struct {
	MaxAgents       int    `json:"max_agents"`
	AllowedMode     string `json:"allowed_mode"`
	MaxSessionHours *int   `json:"max_session_hours,omitempty"`
}

// PAClaims is the PA JWT payload (draft Section 5.3).
type PAClaims struct {
	Ver              int                  `json:"ver"`
	Principal        Principal            `json:"principal"`
	Grants           []Capability         `json:"grants"`
	Constraints      []Capability         `json:"constraints,omitempty"`
	DelegationPolicy *DelegationPolicy    `json:"delegation_policy,omitempty"`
	Extensions       map[string]Extension `json:"extensions,omitempty"`
}

// decodeNumber decodes raw JSON with json.Number so that integer
// precision is preserved for comparison.
func decodeNumber(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// JSONRawEqual compares two raw JSON values semantically
// (object member order and whitespace are ignored).
func JSONRawEqual(a, b json.RawMessage) (bool, error) {
	av, err := decodeNumber(a)
	if err != nil {
		return false, err
	}
	bv, err := decodeNumber(b)
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(av, bv), nil
}

// jsonEqual compares two Go values by marshalling and semantic JSON
// comparison.
func jsonEqual(a, b any) (bool, error) {
	ab, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false, err
	}
	return JSONRawEqual(ab, bb)
}

// CapToPKI converts an AIC-JWT capability to the canonical
// github.com/varwof/types Capability (ASN.1-oriented encoding).
func CapToPKI(c Capability) pki.Capability {
	return pki.Capability{
		SchemeId:     c.Scheme,
		CapabilityId: c.ID,
		Parameters:   []byte(c.Params),
	}
}

// PKIToCap converts the canonical types.Capability to the AIC-JWT
// JSON capability (draft Section 6.1).
func PKIToCap(c pki.Capability) Capability {
	cap := Capability{Scheme: c.SchemeId, ID: c.CapabilityId}
	if len(c.Parameters) > 0 {
		cap.Params = json.RawMessage(c.Parameters)
	}
	return cap
}
