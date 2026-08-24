// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// PrincipalAuthorization is the v1.7.1 user authorization structure.
// ASN.1 (dev-docs/aic/01-asn1.md §PrincipalAuthorization):
//
//	SEQUENCE {
//	    version                     INTEGER DEFAULT 1,
//	    grants                      SEQUENCE OF Capability,
//	    authorizationConstraints    [0] EXPLICIT SEQUENCE SIZE(0..8) OF Capability OPTIONAL,
//	    delegationPolicy            [1] EXPLICIT DelegationPolicy OPTIONAL,
//	    extensions                  [2] EXPLICIT Extensions OPTIONAL
//	}
//
// The pre-v1.5 `roles` field was removed by the v1.5 spec.
type PrincipalAuthorization struct {
	Version                  int              `asn1:"default:1"`
	Grants                   []Capability     `asn1:"optional,omitempty"`
	AuthorizationConstraints []Capability     `asn1:"optional,omitempty,contextspecific,explicit,tag:0"`
	DelegationPolicy         DelegationPolicy `asn1:"optional,explicit,tag:1"`
	Extensions               []ExtField       `asn1:"optional,omitempty,contextspecific,explicit,tag:2"`
}

// GrantIds returns all grants as full capability IDs (scheme:capabilityId),
// via Capability.FullID(). Matching/authorization decisions uniformly use the full identifier,
// aligned with the "ca:list" format in authorization policy grants.
func (pa *PrincipalAuthorization) GrantIds() []string {
	if pa == nil {
		return nil
	}
	var ids []string
	for _, g := range pa.Grants {
		ids = append(ids, g.FullID())
	}
	return ids
}

// ValidatePrincipalAuthorization validates PrincipalAuthorization field constraints (v1.7.1).
// Validates: grants count <= 256, per-Capability length constraints, authorizationConstraints
// count <= 8 with schemeId in the constraint whitelist, DelegationPolicy value boundaries.
func ValidatePrincipalAuthorization(pa *PrincipalAuthorization) error {
	if pa == nil {
		return nil
	}
	if len(pa.Grants) > MaxGrantEntries {
		return fmt.Errorf("principal_authorization: grants count %d exceeds max %d", len(pa.Grants), MaxGrantEntries)
	}
	for i, g := range pa.Grants {
		if len(g.SchemeId) < 1 || len(g.SchemeId) > 128 {
			return fmt.Errorf("principal_authorization: grant[%d].schemeId length %d: must be 1-128", i, len(g.SchemeId))
		}
		if len(g.CapabilityId) < 1 || len(g.CapabilityId) > 256 {
			return fmt.Errorf("principal_authorization: grant[%d].capabilityId length %d: must be 1-256", i, len(g.CapabilityId))
		}
		if len(g.Parameters) > MaxCapParams {
			return fmt.Errorf("principal_authorization: grant[%d].parameters length %d: must be 0-%d", i, len(g.Parameters), MaxCapParams)
		}
	}
	if len(pa.AuthorizationConstraints) > MaxAuthorizationConstraints {
		return fmt.Errorf("principal_authorization: authorizationConstraints count %d exceeds max %d", len(pa.AuthorizationConstraints), MaxAuthorizationConstraints)
	}
	for i, c := range pa.AuthorizationConstraints {
		if c.SchemeId != "constraint" && c.SchemeId != "constraint-v1" && c.SchemeId != "varwof/constraint-v1" {
			return fmt.Errorf("principal_authorization: authorizationConstraints[%d].schemeId %q: must be \"constraint\", \"constraint-v1\", or \"varwof/constraint-v1\"", i, c.SchemeId)
		}
		if len(c.CapabilityId) == 0 {
			return fmt.Errorf("principal_authorization: authorizationConstraints[%d].capabilityId: must not be empty", i)
		}
		if len(c.Parameters) > MaxConstraintParams {
			return fmt.Errorf("principal_authorization: authorizationConstraints[%d].parameters length %d: must be 0-%d", i, len(c.Parameters), MaxConstraintParams)
		}
	}
	if pa.DelegationPolicy.AllowedMode < 0 || pa.DelegationPolicy.AllowedMode > 1 {
		return fmt.Errorf("principal_authorization: delegationPolicy.allowedMode %d: must be 0-1", pa.DelegationPolicy.AllowedMode)
	}
	if pa.DelegationPolicy.MaxAgents < 0 || pa.DelegationPolicy.MaxAgents > 255 {
		return fmt.Errorf("principal_authorization: delegationPolicy.maxAgents %d: must be 0-255", pa.DelegationPolicy.MaxAgents)
	}
	return nil
}

// HasRole reports whether the authorization has the specified role.
//
// The v1.5 spec removed the roles field; role membership is now carried in
// the certificate OU. HasRole is kept for backward compatibility and always
// returns false.
func (pa *PrincipalAuthorization) HasRole(role string) bool {
	return false
}

// AllowsRepresentative checks if representative delegation mode is allowed.
func (pa *PrincipalAuthorization) AllowsRepresentative() bool {
	if pa == nil {
		return false
	}
	return pa.DelegationPolicy.AllowedMode == 1
}

// ParseUserPermissionExtension parses the PrincipalAuthorization extension from a certificate.
func ParseUserPermissionExtension(cert *x509.Certificate) (*PrincipalAuthorization, error) {
	if cert == nil {
		return nil, nil
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDPrincipalAuthorization) {
			var pa PrincipalAuthorization
			if _, err := asn1.Unmarshal(ext.Value, &pa); err != nil {
				return nil, fmt.Errorf("principal_authorization: unmarshal failed: %w", err)
			}
			return &pa, nil
		}
	}
	return nil, nil
}

// DelegationPolicy controls delegation behavior (v1.7.1, dev-docs/aic/01-asn1.md):
//
//	SEQUENCE {
//	    version             INTEGER DEFAULT 1,
//	    maxAgents           INTEGER DEFAULT 1,
//	    allowedMode         DelegationModeEnum DEFAULT authorizedOnly,
//	    maxSessionHours     [0] EXPLICIT INTEGER OPTIONAL
//	}
type DelegationPolicy struct {
	Version         int `asn1:"default:1"`
	MaxAgents       int `asn1:"default:1"`
	AllowedMode     int `asn1:"enum,default:0"`                    // 0=authorizedOnly, 1=representativeAllowed
	MaxSessionHours int `asn1:"optional,omitempty,explicit,tag:0"` // 0=absent
}

// ExternalPolicyRef references an external policy system.
type ExternalPolicyRef struct {
	RefType   string `asn1:"utf8"`
	RefUrl    string `asn1:"utf8"`
	RefDigest []byte `asn1:"optional,omitempty"`
}

// PermissionLevel for backward compatibility.
type PermissionLevel int

const (
	PermissionAuto             PermissionLevel = 0
	PermissionRequiresApproval PermissionLevel = 1
)

// PermissionDef for backward compatibility.
type PermissionDef struct {
	PermId      string `asn1:"utf8"`
	Level       int    `asn1:"enum,default:0"`
	Constraints []byte `asn1:"optional,omitempty"`
}

// RoleDef for backward compatibility.
type RoleDef struct {
	RoleId      string          `asn1:"utf8"`
	Permissions []PermissionDef `asn1:"sequence"`
}

// UserPermission is the v1.4 legacy type for backward compatibility.
type UserPermission struct {
	Version         int                     `asn1:"default:1"`
	Roles           []RoleDef               `asn1:"sequence"`
	Scope           ResourceScope           `asn1:"optional,explicit,tag:0"`
	CriticalOps     []asn1.ObjectIdentifier `asn1:"optional,tag:1"`
	AgentDelegation DelegationPolicy        `asn1:"optional,explicit,tag:2"`
	ExternalRef     ExternalPolicyRef       `asn1:"optional,explicit,tag:3"`
	AgentSerialList []*big.Int              `asn1:"optional,omitempty,tag:4"`
}

// ResourceScope for backward compatibility.
type ResourceScope struct {
	OrgUnit   string `asn1:"utf8,optional,omitempty"`
	Namespace string `asn1:"utf8,optional,omitempty"`
	Tag       string `asn1:"utf8,optional,omitempty"`
}

// AllowsImpersonation for backward compatibility.
func (u *UserPermission) AllowsImpersonation() bool {
	if u == nil {
		return false
	}
	return u.AgentDelegation.AllowedMode == 1
}

// PermIds for backward compatibility.
func (u *UserPermission) PermIds() []string {
	if u == nil {
		return nil
	}
	var ids []string
	for _, r := range u.Roles {
		for _, p := range r.Permissions {
			ids = append(ids, p.PermId)
		}
	}
	return ids
}
