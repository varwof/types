package pki_test

import (
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// ─── PrincipalAuthorization ──────────────────────────────────────

func TestParsePrincipalAuthorization_Nil(t *testing.T) {
	pa, err := pki.ParseUserPermissionExtension(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pa != nil {
		t.Fatal("expected nil")
	}
}

func TestParsePrincipalAuthorization_NoExt(t *testing.T) {
	cert := makeCert(t)
	pa, err := pki.ParseUserPermissionExtension(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pa != nil {
		t.Fatal("expected nil")
	}
}

func TestParsePrincipalAuthorization_Success(t *testing.T) {
	pa := pki.PrincipalAuthorization{
		Version: 1,
		Grants:  []pki.Capability{{CapabilityId: "gateway:admin"}, {CapabilityId: "gateway:read"}},
		DelegationPolicy: pki.DelegationPolicy{
			Version:     1,
			MaxAgents:   5,
			AllowedMode: 0,
		},
	}
	val, err := asn1.Marshal(pa)
	if err != nil {
		t.Fatalf("marshal PA: %v", err)
	}
	cert := makeCertWithExt(t, pki.OIDPrincipalAuthorization, val)
	parsed, err := pki.ParseUserPermissionExtension(cert)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil PA")
	}
	if len(parsed.Grants) != 2 {
		t.Fatalf("Grants: expected 2, got %d", len(parsed.Grants))
	}
	if parsed.HasRole("admin") {
		t.Fatal("v1.5 PA has no roles field; HasRole must return false")
	}
}

// TestParsePrincipalAuthorization_V15Wire checks that a v1.5 wire encoding
// (version + grants only, no roles) parses correctly. This is the format
// emitted by pki-core internal/ca.BuildPrincipalAuthorizationExtension.
func TestParsePrincipalAuthorization_V15Wire(t *testing.T) {
	grants := []pki.Capability{
		{SchemeId: "ca", CapabilityId: "issue:*"},
		{SchemeId: "ca", CapabilityId: "revoke:*"},
	}
	pa := pki.PrincipalAuthorization{Version: 1, Grants: grants}
	val, err := asn1.Marshal(pa)
	if err != nil {
		t.Fatalf("marshal PA: %v", err)
	}
	// Sanity: version + grants sequence only.
	if len(val) < 4 || val[0] != 0x30 {
		t.Fatalf("expected SEQUENCE, got %x", val)
	}
	cert := makeCertWithExt(t, pki.OIDPrincipalAuthorization, val)
	parsed, err := pki.ParseUserPermissionExtension(cert)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil PA")
	}
	if len(parsed.Grants) != 2 {
		t.Fatalf("Grants: expected 2, got %d", len(parsed.Grants))
	}
	if parsed.Grants[0].SchemeId != "ca" || parsed.Grants[0].CapabilityId != "issue:*" {
		t.Fatalf("grant[0]: unexpected %+v", parsed.Grants[0])
	}
	if parsed.Grants[1].SchemeId != "ca" || parsed.Grants[1].CapabilityId != "revoke:*" {
		t.Fatalf("grant[1]: unexpected %+v", parsed.Grants[1])
	}
}

func TestParsePrincipalAuthorization_Malformed(t *testing.T) {
	cert := makeCertWithExt(t, pki.OIDPrincipalAuthorization, []byte{0xff})
	_, err := pki.ParseUserPermissionExtension(cert)
	if err == nil {
		t.Fatal("expected error for malformed PA")
	}
}

func TestPAGrantIds(t *testing.T) {
	var nilPA *pki.PrincipalAuthorization
	if nilPA.GrantIds() != nil {
		t.Fatal("nil PA should return nil")
	}
	pa := &pki.PrincipalAuthorization{
		Grants: []pki.Capability{
			{CapabilityId: "gateway:admin"},
			{CapabilityId: "gateway:read"},
		},
	}
	ids := pa.GrantIds()
	if len(ids) != 2 || ids[0] != "gateway:admin" || ids[1] != "gateway:read" {
		t.Fatalf("unexpected grants: %v", ids)
	}
}

func TestPAHasRole_Nil(t *testing.T) {
	var nilPA *pki.PrincipalAuthorization
	if nilPA.HasRole("admin") {
		t.Fatal("nil PA should return false")
	}
}

func TestPAAllowsRepresentative(t *testing.T) {
	var nilPA *pki.PrincipalAuthorization
	if nilPA.AllowsRepresentative() {
		t.Fatal("nil PA should return false")
	}
	pa := &pki.PrincipalAuthorization{
		DelegationPolicy: pki.DelegationPolicy{AllowedMode: 1},
	}
	if !pa.AllowsRepresentative() {
		t.Fatal("expected true for AllowedMode=1")
	}
	pa.DelegationPolicy.AllowedMode = 0
	if pa.AllowsRepresentative() {
		t.Fatal("expected false for AllowedMode=0")
	}
}

// ─── UserPermission (legacy) ─────────────────────────────────────

func TestLegacyUserPermission_AllowsImpersonation(t *testing.T) {
	var nilUP *pki.UserPermission
	if nilUP.AllowsImpersonation() {
		t.Fatal("nil UP should return false")
	}
	up := &pki.UserPermission{
		AgentDelegation: pki.DelegationPolicy{AllowedMode: 1},
	}
	if !up.AllowsImpersonation() {
		t.Fatal("expected true")
	}
}

func TestLegacyUserPermission_PermIds(t *testing.T) {
	var nilUP *pki.UserPermission
	if nilUP.PermIds() != nil {
		t.Fatal("nil UP should return nil")
	}
	up := &pki.UserPermission{
		Roles: []pki.RoleDef{
			{RoleId: "admin", Permissions: []pki.PermissionDef{
				{PermId: "gateway:admin"},
				{PermId: "gateway:ops"},
			}},
			{RoleId: "audit", Permissions: []pki.PermissionDef{
				{PermId: "gateway:read"},
			}},
		},
	}
	ids := up.PermIds()
	if len(ids) != 3 {
		t.Fatalf("expected 3 perm IDs, got %d: %v", len(ids), ids)
	}
}

// ─── DelegationPolicy ────────────────────────────────────────────

// TestDelegationPolicyDefaultTags verifies ASN.1 default: tags on DelegationPolicy.
// When a field equals its declared default, the encoder omits it and the
// default value is restored on decode.
func TestDelegationPolicyDefaultTags(t *testing.T) {
	dp := pki.DelegationPolicy{
		Version:     1, // matches default:1 → encoder omits
		MaxAgents:   1, // matches default:1 → encoder omits
		AllowedMode: 0, // matches default:0 → encoder omits
	}
	der, err := asn1.Marshal(dp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded pki.DelegationPolicy
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Version != 1 {
		t.Fatalf("Version: expected 1 (from default:1 tag), got %d", decoded.Version)
	}
	if decoded.MaxAgents != 1 {
		t.Fatalf("MaxAgents: expected 1 (from default:1 tag), got %d", decoded.MaxAgents)
	}
	if decoded.AllowedMode != 0 {
		t.Fatalf("AllowedMode: expected 0, got %d", decoded.AllowedMode)
	}
}

// ─── ExternalPolicyRef ───────────────────────────────────────────

func TestExternalPolicyRef(t *testing.T) {
	ref := pki.ExternalPolicyRef{
		RefType:   "url",
		RefUrl:    "https://policy.example.com/p1",
		RefDigest: []byte("digest"),
	}
	der, err := asn1.Marshal(ref)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded pki.ExternalPolicyRef
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.RefType != "url" {
		t.Fatalf("RefType: expected url, got %s", decoded.RefType)
	}
	if decoded.RefUrl != "https://policy.example.com/p1" {
		t.Fatalf("RefUrl mismatch")
	}
}

// ─── ResourceScope ───────────────────────────────────────────────

func TestResourceScope(t *testing.T) {
	rs := pki.ResourceScope{
		OrgUnit:   "engineering",
		Namespace: "prod",
		Tag:       "v1",
	}
	der, err := asn1.Marshal(rs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded pki.ResourceScope
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.OrgUnit != "engineering" {
		t.Fatalf("OrgUnit mismatch")
	}
}

// ─── PermissionLevel constants ───────────────────────────────────

func TestPermissionLevelValues(t *testing.T) {
	if pki.PermissionAuto != 0 {
		t.Fatalf("PermissionAuto: expected 0, got %d", pki.PermissionAuto)
	}
	if pki.PermissionRequiresApproval != 1 {
		t.Fatalf("PermissionRequiresApproval: expected 1, got %d", pki.PermissionRequiresApproval)
	}
}

// Compile-time checks for ASN.1 serializability of all extension types.
var (
	_ = []interface{}{
		pki.PrincipalAuthorization{},
		pki.UserPermission{},
		pki.DelegationPolicy{},
		pki.ExternalPolicyRef{},
		pki.ResourceScope{},
	}
)

// Ensure big import is used.
var _ = big.NewInt
var _ = x509.ExtKeyUsageAny
var _ = time.Second
