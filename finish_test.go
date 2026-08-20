package pki_test

import (
	"encoding/asn1"
	"testing"

	pki "github.com/varwof/types"
)

func TestAICIntersectPermissionsWithPA(t *testing.T) {
	var nilAIC *pki.AIC
	var nilPA *pki.PrincipalAuthorization

	if got := nilAIC.IntersectPermissions(nilPA); got != nil {
		t.Fatal("nil AIC should return nil")
	}
	if got := nilAIC.IntersectPermissions(&pki.PrincipalAuthorization{}); got != nil {
		t.Fatal("nil AIC with PA should return nil")
	}

	aic := &pki.AIC{
		Capabilities: []pki.Capability{
			{CapabilityId: "gateway:admin"},
			{CapabilityId: "gateway:read"},
			{CapabilityId: "ca:list"},
		},
	}
	if got := aic.IntersectPermissions(nilPA); got != nil {
		t.Fatal("nil PA should return nil")
	}

	pa := &pki.PrincipalAuthorization{
		Grants: []pki.Capability{
			{CapabilityId: "gateway:*"},
			{CapabilityId: "ca:create"},
		},
	}
	got := aic.IntersectPermissions(pa)
	if len(got) != 2 {
		t.Fatalf("expected [gateway:admin gateway:read], got %v", got)
	}
	for _, id := range got {
		if id != "gateway:admin" && id != "gateway:read" {
			t.Errorf("unexpected intersection id %q", id)
		}
	}

	noMatch := &pki.PrincipalAuthorization{
		Grants: []pki.Capability{{CapabilityId: "mysql:SELECT"}},
	}
	if got := aic.IntersectPermissions(noMatch); len(got) != 0 {
		t.Errorf("expected no intersection, got %v", got)
	}

	empty := &pki.AIC{}
	if got := empty.IntersectPermissions(pa); got != nil {
		t.Errorf("empty AIC should return nil, got %v", got)
	}
}

func TestValidatePrincipalUidKeyHash(t *testing.T) {
	if err := pki.ValidatePrincipalUidKeyHash(pki.PrincipalUid{}); err == nil {
		t.Error("empty keyHash should error")
	}
	// Empty algo (default SHA-256) + 32 bytes → OK.
	if err := pki.ValidatePrincipalUidKeyHash(pki.PrincipalUid{KeyHash: make([]byte, 32)}); err != nil {
		t.Errorf("default SHA-256 32B: %v", err)
	}
	// Explicit SHA-256.
	if err := pki.ValidatePrincipalUidKeyHash(pki.PrincipalUid{
		KeyHash:  make([]byte, 32),
		HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
	}); err != nil {
		t.Errorf("explicit SHA-256: %v", err)
	}
	// Length mismatch.
	if err := pki.ValidatePrincipalUidKeyHash(pki.PrincipalUid{KeyHash: make([]byte, 16)}); err == nil {
		t.Error("16-byte keyHash with SHA-256 should error")
	}
	// Explicit SHA-512 → 64 bytes passes (P1-A-12 algorithm family support).
	if err := pki.ValidatePrincipalUidKeyHash(pki.PrincipalUid{
		KeyHash:  make([]byte, 64),
		HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA512},
	}); err != nil {
		t.Errorf("SHA-512 64B should pass: %v", err)
	}
	// SHA-512 length mismatch (32B) → rejected.
	if err := pki.ValidatePrincipalUidKeyHash(pki.PrincipalUid{
		KeyHash:  make([]byte, 32),
		HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA512},
	}); err == nil {
		t.Error("SHA-512 with 32B keyHash should error")
	}
	// Unknown OID → explicitly unsupported.
	if err := pki.ValidatePrincipalUidKeyHash(pki.PrincipalUid{
		KeyHash:  make([]byte, 32),
		HashAlgo: pki.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{9, 9, 9}},
	}); err == nil {
		t.Error("unknown algo should error as unsupported")
	}
}

func TestHashAlgoOID(t *testing.T) {
	var pu pki.PrincipalUid
	if got := pu.HashAlgoOID(); !got.Equal(pki.OIDSHA256) {
		t.Errorf("empty HashAlgo should default to SHA-256, got %v", got)
	}
	pu = pki.PrincipalUid{HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA384}}
	if got := pu.HashAlgoOID(); !got.Equal(pki.OIDSHA384) {
		t.Errorf("expected SHA-384, got %v", got)
	}
}
