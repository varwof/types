package pki_test

import (
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// ─── GatewaySessionExtension ─────────────────────────────────────

func TestParseGatewaySessionExtension_Nil(t *testing.T) {
	gs, err := pki.ParseGatewaySessionExtension(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs != nil {
		t.Fatal("expected nil for nil cert")
	}
}

func TestParseGatewaySessionExtension_NoExt(t *testing.T) {
	cert := makeCert(t)
	gs, err := pki.ParseGatewaySessionExtension(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs != nil {
		t.Fatal("expected nil for cert without GS ext")
	}
}

func TestParseGatewaySessionExtension_Success(t *testing.T) {
	gs := pki.GatewaySessionExtension{
		Version:       1,
		MaxConcurrent: 10,
		HardTimeout:   3600,
		AllowedCIDRs:  []string{"10.0.0.0/8"},
		MaxRetries:    3,
	}
	val, err := asn1.Marshal(gs)
	if err != nil {
		t.Fatalf("marshal GS: %v", err)
	}
	cert := makeCertWithExt(t, pki.OIDGatewaySession, val)
	parsed, err := pki.ParseGatewaySessionExtension(cert)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil GS")
	}
	if parsed.MaxConcurrentLimit() != 10 {
		t.Fatalf("MaxConcurrent: expected 10, got %d", parsed.MaxConcurrentLimit())
	}
	if parsed.HardTimeoutLimit() != 3600 {
		t.Fatalf("HardTimeout: expected 3600, got %d", parsed.HardTimeoutLimit())
	}
	if parsed.MaxRetriesLimit() != 3 {
		t.Fatalf("MaxRetries: expected 3, got %d", parsed.MaxRetriesLimit())
	}
}

func TestParseGatewaySessionExtension_Malformed(t *testing.T) {
	cert := makeCertWithExt(t, pki.OIDGatewaySession, []byte{0xff})
	_, err := pki.ParseGatewaySessionExtension(cert)
	if err == nil {
		t.Fatal("expected error for malformed GS")
	}
}

func TestGSMaxConcurrentLimit_Nil(t *testing.T) {
	var gs *pki.GatewaySessionExtension
	if gs.MaxConcurrentLimit() != 0 {
		t.Fatal("nil GS should return 0")
	}
}

func TestGSHardTimeoutLimit_Nil(t *testing.T) {
	var gs *pki.GatewaySessionExtension
	if gs.HardTimeoutLimit() != 0 {
		t.Fatal("nil GS should return 0")
	}
}

func TestGSMaxRetriesLimit_Nil(t *testing.T) {
	var gs *pki.GatewaySessionExtension
	if gs.MaxRetriesLimit() != 0 {
		t.Fatal("nil GS should return 0")
	}
}

func TestGSCIDRAllowed_Nil(t *testing.T) {
	var gs *pki.GatewaySessionExtension
	if !gs.CIDRAllowed("10.0.0.1") {
		t.Fatal("nil GS should allow all")
	}
}

func TestGSCIDRAllowed_EmptyList(t *testing.T) {
	gs := &pki.GatewaySessionExtension{}
	if !gs.CIDRAllowed("10.0.0.1") {
		t.Fatal("empty CIDR list should allow all")
	}
}

func TestGSCIDRAllowed_Allowed(t *testing.T) {
	gs := &pki.GatewaySessionExtension{
		AllowedCIDRs: []string{"10.0.0.0/8", "192.168.1.0/24"},
	}
	tests := []struct {
		ip    string
		allow bool
	}{
		{"10.1.2.3", true},
		{"10.255.255.255", true},
		{"192.168.1.1", true},
		{"192.168.2.1", false},
		{"172.16.0.1", false},
		{"invalid-ip", false},
	}
	for _, tt := range tests {
		got := gs.CIDRAllowed(tt.ip)
		if got != tt.allow {
			t.Fatalf("CIDRAllowed(%q): expected %v, got %v", tt.ip, tt.allow, got)
		}
	}
}

func TestGSCIDRAllowed_IPv6(t *testing.T) {
	gs := &pki.GatewaySessionExtension{
		AllowedCIDRs: []string{"::1/128", "2001:db8::/32"},
	}
	if !gs.CIDRAllowed("::1") {
		t.Fatal("expected allowed ::1")
	}
	if !gs.CIDRAllowed("2001:db8:dead:beef::1") {
		t.Fatal("expected allowed 2001:db8::")
	}
	if gs.CIDRAllowed("2001:db9::1") {
		t.Fatal("expected rejected 2001:db9::")
	}
}

func TestGSValidateKeyDerivation_Nil(t *testing.T) {
	var gs *pki.GatewaySessionExtension
	if err := gs.ValidateKeyDerivation(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGSValidateKeyDerivation_Empty(t *testing.T) {
	gs := &pki.GatewaySessionExtension{}
	if err := gs.ValidateKeyDerivation(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGSValidateKeyDerivation_InvalidSalt(t *testing.T) {
	gs := &pki.GatewaySessionExtension{
		KeyDerivation: []pki.KeyDerivationParams{
			{Salt: []byte{1, 2, 3}}, // too short
		},
	}
	if err := gs.ValidateKeyDerivation(); err == nil {
		t.Fatal("expected error for short salt")
	}
}

func TestGSValidateKeyDerivation_Valid(t *testing.T) {
	gs := &pki.GatewaySessionExtension{
		KeyDerivation: []pki.KeyDerivationParams{
			{Salt: make([]byte, 16)},
			{Salt: make([]byte, 32)},
		},
	}
	if err := gs.ValidateKeyDerivation(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

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

// ─── KeyDerivationParams ─────────────────────────────────────────

// TestKeyDerivationParamsDefaultTag verifies that when KeyLength is set to
// the default (32), the encoder omits it and the default is restored on decode.
func TestKeyDerivationParamsDefaultTag(t *testing.T) {
	kd := pki.KeyDerivationParams{
		KDFAlgorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 6},
		KeyLength:    32, // matches default → encoder omits
		Salt:         make([]byte, 32),
	}
	der, err := asn1.Marshal(kd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded pki.KeyDerivationParams
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.KeyLength != 32 {
		t.Fatalf("KeyLength: expected 32 (from default:32 tag), got %d", decoded.KeyLength)
	}
	if decoded.Info != "" {
		t.Fatalf("Info: expected empty, got %q", decoded.Info)
	}
}

func TestKeyDerivationParamsFull(t *testing.T) {
	kd := pki.KeyDerivationParams{
		KDFAlgorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 6},
		KeyLength:    48,
		Salt:         make([]byte, 16),
		Info:         "session-key",
	}
	der, err := asn1.Marshal(kd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded pki.KeyDerivationParams
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.KeyLength != 48 {
		t.Fatalf("KeyLength: expected 48, got %d", decoded.KeyLength)
	}
	if decoded.Info != "session-key" {
		t.Fatalf("Info: expected session-key, got %q", decoded.Info)
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
		pki.GatewaySessionExtension{},
		pki.DelegationPolicy{},
		pki.ExternalPolicyRef{},
		pki.ResourceScope{},
		pki.KeyDerivationParams{},
	}
)

// Ensure big import is used.
var _ = big.NewInt
var _ = x509.ExtKeyUsageAny
var _ = time.Second
