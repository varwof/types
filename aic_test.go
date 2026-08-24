// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

func makeCertWithExt(t *testing.T, oid asn1.ObjectIdentifier, extVal []byte) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oid, Value: extVal},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert creation: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("cert parse: %v", err)
	}
	return cert
}

func makeCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert creation: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("cert parse: %v", err)
	}
	return cert
}

// ─── AIC Marshal / Unmarshal ─────────────────────────────────────

func TestAICMarshalRoundTrip(t *testing.T) {
	aic := pki.AIC{
		Version:        1,
		AgentId:        "agent-001",
		PrincipalUid:   pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com", KeyHash: make([]byte, 32)},
		Capabilities:   []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationMode: pki.DelegationAuthorized,
	}
	der, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatalf("marshal AIC: %v", err)
	}
	var decoded pki.AIC
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal AIC: %v", err)
	}
	if decoded.AgentId != "agent-001" {
		t.Fatalf("AgentId: expected agent-001, got %s", decoded.AgentId)
	}
	if len(decoded.Capabilities) != 1 {
		t.Fatalf("Capabilities: expected 1, got %d", len(decoded.Capabilities))
	}
	if decoded.Capabilities[0].CapabilityId != "gateway:admin" {
		t.Fatalf("CapabilityId: expected gateway:admin, got %s", decoded.Capabilities[0].CapabilityId)
	}
}

func TestAICMarshalWithDA(t *testing.T) {
	aic := pki.AIC{
		Version:      1,
		AgentId:      "agent-002",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com", KeyHash: make([]byte, 32)},
		DelegationAuthorization: pki.DelegationAuthorization{
			RequestedLifetime:  7200,
			Timestamp:          time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{1, 2, 3},
		},
	}
	der, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatalf("marshal AIC with DA: %v", err)
	}
	var decoded pki.AIC
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal AIC with DA: %v", err)
	}
	if decoded.DelegationAuthorization.RequestedLifetime != 7200 {
		t.Fatalf("RequestedLifetime: expected 7200, got %d", decoded.DelegationAuthorization.RequestedLifetime)
	}
	if len(decoded.DelegationAuthorization.Nonce) != 32 {
		t.Fatalf("Nonce: expected 32 bytes, got %d", len(decoded.DelegationAuthorization.Nonce))
	}
	// DA with all fields set should be present
	if !decoded.DelegationAuthorization.IsPresent() {
		t.Fatal("DA should be present")
	}
}

func TestAICMarshalWithExtensions(t *testing.T) {
	aic := pki.AIC{
		Version:      1,
		AgentId:      "agent-ext",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "u", KeyHash: make([]byte, 32)},
		Extensions: []pki.ExtField{
			{ExtnID: asn1.ObjectIdentifier{1, 2, 3}, Critical: false, ExtnValue: []byte("hello")},
		},
	}
	der, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatalf("marshal AIC with ext: %v", err)
	}
	var decoded pki.AIC
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal AIC with ext: %v", err)
	}
	if len(decoded.Extensions) != 1 {
		t.Fatalf("Extensions: expected 1, got %d", len(decoded.Extensions))
	}
}

// ─── DelegationMode ──────────────────────────────────────────────

func TestDelegationModeValues(t *testing.T) {
	if pki.DelegationAuthorized != 0 {
		t.Fatalf("DelegationAuthorized: expected 0, got %d", pki.DelegationAuthorized)
	}
	if pki.DelegationRepresentative != 1 {
		t.Fatalf("DelegationRepresentative: expected 1, got %d", pki.DelegationRepresentative)
	}
}

// ─── DelegationAuthorization.IsPresent ────────────────────────────

func TestDAIsPresent(t *testing.T) {
	var empty pki.DelegationAuthorization
	if empty.IsPresent() {
		t.Fatal("empty DA should not be present")
	}
	withNonce := pki.DelegationAuthorization{Nonce: make([]byte, 32)}
	if !withNonce.IsPresent() {
		t.Fatal("DA with Nonce should be present")
	}
	withSig := pki.DelegationAuthorization{SignatureValue: []byte{1, 2, 3}}
	if !withSig.IsPresent() {
		t.Fatal("DA with SignatureValue should be present")
	}
	withLifetime := pki.DelegationAuthorization{RequestedLifetime: 3600}
	if !withLifetime.IsPresent() {
		t.Fatal("DA with RequestedLifetime should be present")
	}
	withTS := pki.DelegationAuthorization{Timestamp: time.Now()}
	if !withTS.IsPresent() {
		t.Fatal("DA with Timestamp should be present")
	}
}

// ─── AIC.Principal ───────────────────────────────────────────────

func TestAICPrincipal(t *testing.T) {
	var nilAIC *pki.AIC
	if nilAIC.Principal() != "" {
		t.Fatal("nil AIC should return empty principal")
	}
	aic := &pki.AIC{
		PrincipalUid: pki.PrincipalUid{
			Realm: "test", Identifier: "alice",
			KeyHash: make([]byte, 32),
		},
	}
	got := aic.Principal()
	if !strings.HasPrefix(got, "test:alice:") {
		t.Fatalf("Principal: expected test:alice:..., got %s", got)
	}
}

// ─── AIC.HasProtocol ─────────────────────────────────────────────

func TestAICHasProtocol(t *testing.T) {
	var nilAIC *pki.AIC
	if nilAIC.HasProtocol("http") {
		t.Fatal("nil AIC should return false")
	}
	aic := &pki.AIC{
		Capabilities: []pki.Capability{
			{SchemeId: "http", CapabilityId: "gateway:admin"},
			{SchemeId: "quic", CapabilityId: "gateway:read"},
		},
	}
	if !aic.HasProtocol("http") {
		t.Fatal("expected protocol http")
	}
	if !aic.HasProtocol("quic") {
		t.Fatal("expected protocol quic")
	}
	if aic.HasProtocol("dtls") {
		t.Fatal("unexpected protocol dtls")
	}
}

// ─── AIC.CheckPermission ─────────────────────────────────────────

func TestAICCheckPermission(t *testing.T) {
	var nilAIC *pki.AIC
	if nilAIC.CheckPermission("any") {
		t.Fatal("nil AIC should return false")
	}
	aic := &pki.AIC{
		Capabilities: []pki.Capability{
			{CapabilityId: "gateway:admin"},
			{CapabilityId: "gateway:read"},
		},
	}
	if !aic.CheckPermission("gateway:admin") {
		t.Fatal("expected gateway:admin")
	}
	if aic.CheckPermission("ca:create") {
		t.Fatal("unexpected ca:create")
	}
}

func TestAICCheckPermissionGlob(t *testing.T) {
	aic := &pki.AIC{
		Capabilities: []pki.Capability{
			{CapabilityId: "ca:list"},
			{CapabilityId: "ca:create"},
			{CapabilityId: "cert:issue"},
		},
	}
	if !aic.CheckPermission("ca:*") {
		t.Fatal("expected ca:* to match ca:list")
	}
	if !aic.CheckPermission("ca:*") {
		t.Fatal("expected ca:* to match ca:create")
	}
	if aic.CheckPermission("crl:*") {
		t.Fatal("expected no match for crl:*")
	}
	if !aic.CheckPermission("cert:issue") {
		t.Fatal("expected exact match cert:issue")
	}
	if aic.CheckPermission("cert:revoke") {
		t.Fatal("expected no match for cert:revoke")
	}
}

// ─── ParseAIC ────────────────────────────────────────────────────

func TestParseAIC_NilCert(t *testing.T) {
	aic, err := pki.ParseAIC(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aic != nil {
		t.Fatal("expected nil for nil cert")
	}
}

func TestParseAIC_NoExt(t *testing.T) {
	cert := makeCert(t)
	aic, err := pki.ParseAIC(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aic != nil {
		t.Fatal("expected nil for cert without AIC ext")
	}
}

func TestParseAIC_Success(t *testing.T) {
	aic := pki.AIC{
		Version:      1,
		AgentId:      "agent-parse",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "AUTO_RENEWAL", Description: "parse test"},
			Timestamp:          time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{1},
		},
	}
	val, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cert := makeCertWithExt(t, pki.OIDAIC, val)
	parsed, err := pki.ParseAIC(cert)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil AIC")
	}
	if parsed.AgentId != "agent-parse" {
		t.Fatalf("AgentId: expected agent-parse, got %s", parsed.AgentId)
	}
	if parsed.DelegationAuthorization.Reason.ReasonCode != "AUTO_RENEWAL" {
		t.Fatalf("reason: expected AUTO_RENEWAL, got %s", parsed.DelegationAuthorization.Reason.ReasonCode)
	}
}

func TestParseAIC_Malformed(t *testing.T) {
	cert := makeCertWithExt(t, pki.OIDAIC, []byte{0xff, 0xff})
	_, err := pki.ParseAIC(cert)
	if err == nil {
		t.Fatal("expected error for malformed AIC")
	}
}

// ─── ValidateAIC ─────────────────────────────────────────────────

func TestValidateAIC_Nil(t *testing.T) {
	if err := pki.ValidateAIC(nil); err != nil {
		t.Fatalf("nil AIC should pass: %v", err)
	}
}

func TestValidateAIC_TooManyCapabilities(t *testing.T) {
	caps := make([]pki.Capability, 257)
	for i := range caps {
		caps[i] = pki.Capability{SchemeId: "x", CapabilityId: "y"}
	}
	aic := &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{KeyHash: make([]byte, 32)},
		Capabilities: caps,
	}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for 257 capabilities")
	}
}

func TestValidateAIC_CapSizes(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		capID  string
		params int
	}{
		{"empty scheme", "", "valid", 0},
		{"oversize scheme", strings.Repeat("x", 129), "valid", 0},
		{"empty capId", "valid", "", 0},
		{"oversize capId", "valid", strings.Repeat("x", 257), 0},
		{"oversize params", "valid", "valid", 5000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aic := &pki.AIC{
				AgentId:      "test",
				PrincipalUid: pki.PrincipalUid{KeyHash: make([]byte, 32)},
				Capabilities: []pki.Capability{{
					SchemeId:     tt.scheme,
					CapabilityId: tt.capID,
					Parameters:   make([]byte, tt.params),
				}},
			}
			if err := pki.ValidateAIC(aic); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidateAIC_KeyHashSize(t *testing.T) {
	aic := &pki.AIC{
		AgentId: "test",
		PrincipalUid: pki.PrincipalUid{
			KeyHash: []byte{1, 2, 3},
		},
	}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for wrong keyHash size")
	}
}

func TestValidateAIC_NonceSize(t *testing.T) {
	aic := &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{KeyHash: make([]byte, 32)},
		DelegationAuthorization: pki.DelegationAuthorization{
			Nonce:          []byte{1, 2, 3},
			SignatureValue: []byte{1},
		},
	}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for wrong nonce size")
	}
}

func TestValidateAIC_LifetimeBounds(t *testing.T) {
	aic := &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:         pki.Reason{ReasonCode: "OK", Description: "d"},
			Nonce:          make([]byte, 32),
			SignatureValue: []byte{1},
		},
	}
	aic.DelegationAuthorization.RequestedLifetime = 99999
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for lifetime > 86400")
	}
}

func TestValidateAIC_UnknownCriticalExt(t *testing.T) {
	aic := &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{KeyHash: make([]byte, 32)},
		Extensions: []pki.ExtField{
			{ExtnID: asn1.ObjectIdentifier{9, 9, 9}, Critical: true},
		},
	}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for unknown critical ext")
	}
}

func TestValidateAIC_Valid(t *testing.T) {
	aic := &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "alice", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{
			{SchemeId: "http", CapabilityId: "gateway:admin"},
		},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:         pki.Reason{ReasonCode: "SCHEDULED_MAINTENANCE", Description: "valid test"},
			Nonce:          make([]byte, 32),
			Timestamp:      time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC),
			SignatureValue: []byte{1},
		},
	}
	if err := pki.ValidateAIC(aic); err != nil {
		t.Fatalf("valid AIC should pass: %v", err)
	}
}

func TestValidateAIC_MissingDA(t *testing.T) {
	aic := &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
	}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for missing delegationAuthorization")
	}
}

func TestValidateAIC_ReasonMissing(t *testing.T) {
	aic := &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Nonce:          make([]byte, 32),
			SignatureValue: []byte{1},
		},
	}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for missing reason")
	}
}

func TestValidateAIC_ReasonTooLong(t *testing.T) {
	aic := &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:         pki.Reason{ReasonCode: strings.Repeat("X", 65), Description: "desc"},
			Nonce:          make([]byte, 32),
			SignatureValue: []byte{1},
		},
	}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for reasonCode > 64")
	}
	aic.DelegationAuthorization.Reason = pki.Reason{ReasonCode: "OK", Description: strings.Repeat("d", 513)}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for description > 512")
	}
}

func TestValidateAIC_ConstraintWhitelist(t *testing.T) {
	// constraint-v1 accepted
	aic := &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "alice", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:         pki.Reason{ReasonCode: "OK", Description: "d"},
			Nonce:          make([]byte, 32),
			SignatureValue: []byte{1},
		},
		AuthorizationConstraints: []pki.Capability{
			{SchemeId: "varwof/constraint-v1", CapabilityId: "allowed-cidr", Parameters: []byte(`["10.0.0.0/8"]`)},
		},
	}
	if err := pki.ValidateAIC(aic); err != nil {
		t.Fatalf("constraint-v1 should pass: %v", err)
	}
	// non-whitelist scheme rejected
	aic.AuthorizationConstraints = []pki.Capability{
		{SchemeId: "other", CapabilityId: "allowed-cidr"},
	}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for non-whitelist constraint scheme")
	}
	// capabilities must not carry constraint scheme
	aic.AuthorizationConstraints = nil
	aic.Capabilities = []pki.Capability{{SchemeId: "varwof/constraint-v1", CapabilityId: "time-window"}}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for constraint scheme in capabilities")
	}
}

func TestValidateAIC_UnsupportedHashAlgo(t *testing.T) {
	aic := &pki.AIC{
		AgentId: "test",
		PrincipalUid: pki.PrincipalUid{
			KeyHash:  make([]byte, 32),
			HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA384},
		},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:         pki.Reason{ReasonCode: "OK", Description: "d"},
			Nonce:          make([]byte, 32),
			SignatureValue: []byte{1},
		},
	}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for unsupported hashAlgo")
	}
}

func TestValidateAIC_LifetimeUpgrade(t *testing.T) {
	aic := &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "alice", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:         pki.Reason{ReasonCode: "OK", Description: "d"},
			Nonce:          make([]byte, 32),
			SignatureValue: []byte{1},
		},
	}
	// lifetime 0 upgraded to 3600 (valid), 100 is now valid (1..86400)
	aic.DelegationAuthorization.RequestedLifetime = 0
	if err := pki.ValidateAIC(aic); err != nil {
		t.Fatalf("lifetime 0 should be upgraded/pass: %v", err)
	}
	aic.DelegationAuthorization.RequestedLifetime = 100
	if err := pki.ValidateAIC(aic); err != nil {
		t.Fatalf("lifetime 100 should pass (1..86400): %v", err)
	}
	aic.DelegationAuthorization.RequestedLifetime = 86401
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for lifetime > 86400")
	}
}

// ─── IntersectPermissions ────────────────────────────────────────

func TestAICIntersectPermissions(t *testing.T) {
	var nilAIC *pki.AIC
	if got := nilAIC.IntersectPermissionsStr(nil); got != nil {
		t.Fatal("nil AIC should return nil")
	}

	aic := &pki.AIC{
		Capabilities: []pki.Capability{
			{CapabilityId: "gateway:admin"},
			{CapabilityId: "gateway:read"},
			{CapabilityId: "ca:list"},
		},
	}

	got := aic.IntersectPermissionsStr([]string{"gateway:admin", "ca:list"})
	if len(got) != 2 {
		t.Fatalf("expected 2 matches, got %d: %v", len(got), got)
	}

	got = aic.IntersectPermissionsStr([]string{"ca:*"})
	if len(got) != 1 || got[0] != "ca:list" {
		t.Fatalf("expected [ca:list], got %v", got)
	}

	got = aic.IntersectPermissionsStr([]string{"nonexistent"})
	if len(got) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(got))
	}
}

func TestAICIntersectPermissionsStrAny(t *testing.T) {
	aic := &pki.AIC{
		Capabilities: []pki.Capability{
			{CapabilityId: "gateway:admin"},
			{CapabilityId: "gateway:ops"},
		},
	}
	got := aic.IntersectPermissionsStrAny("gateway:admin, ca:list")
	if len(got) != 1 || got[0] != "gateway:admin" {
		t.Fatalf("expected [gateway:admin], got %v", got)
	}
}

// ─── DelegationAuthTBS Marshal ──────────────────────────────────

func TestDelegationAuthTBSMarshal(t *testing.T) {
	tbs := pki.DelegationAuthTBS{
		Version:           1,
		AgentId:           "agent-da",
		PrincipalUid:      pki.PrincipalUid{Version: 1, Realm: "r", Identifier: "u", KeyHash: make([]byte, 32)},
		Capabilities:      []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationMode:    pki.DelegationAuthorized,
		RequestedLifetime: 3600,
		Timestamp:         time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC),
		Nonce:             make([]byte, 32),
	}
	der, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshal DATBS: %v", err)
	}
	var decoded pki.DelegationAuthTBS
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal DATBS: %v", err)
	}
	if decoded.AgentId != "agent-da" {
		t.Fatalf("AgentId mismatch")
	}
}

// ─── SigAlgoToOID ────────────────────────────────────────────────

func TestSigAlgoToOID(t *testing.T) {
	tests := []struct {
		name string
		algo x509.SignatureAlgorithm
		want asn1.ObjectIdentifier
	}{
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, pki.OIDSigECDSAWithSHA256},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, pki.OIDSigECDSAWithSHA384},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, pki.OIDSigECDSAWithSHA512},
		{"SHA256WithRSA", x509.SHA256WithRSA, pki.OIDSigRSAWithSHA256},
		{"SHA384WithRSA", x509.SHA384WithRSA, pki.OIDSigRSAWithSHA384},
		{"SHA512WithRSA", x509.SHA512WithRSA, pki.OIDSigRSAWithSHA512},
		{"PureEd25519", x509.PureEd25519, pki.OIDSigEd25519},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pki.SigAlgoToOID(tt.algo)
			if !got.Algorithm.Equal(tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, got.Algorithm)
			}
		})
	}

	unknown := pki.SigAlgoToOID(x509.UnknownSignatureAlgorithm)
	if unknown.Algorithm != nil {
		t.Fatal("expected nil for unknown algo")
	}
}

// ─── OIDAIC ──────────────────────────────────────────────────────

func TestOIDAIC(t *testing.T) {
	expected := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1}
	if !pki.OIDAIC.Equal(expected) {
		t.Fatalf("OIDAIC: expected %v, got %v", expected, pki.OIDAIC)
	}
}

func TestOIDGatewaySession(t *testing.T) {
	expected := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 5}
	if !pki.OIDGatewaySession.Equal(expected) {
		t.Fatalf("OIDGatewaySession: expected %v, got %v", expected, pki.OIDGatewaySession)
	}
}

// ─── Edge Cases ──────────────────────────────────────────────────

func TestEmptyAIC(t *testing.T) {
	aic := pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "r", Identifier: "u", KeyHash: make([]byte, 32)},
	}
	der, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatalf("marshal empty-ish AIC: %v", err)
	}
	var decoded pki.AIC
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestAICPrincipalEmptyUid(t *testing.T) {
	aic := &pki.AIC{}
	if aic.Principal() != "::" {
		t.Fatalf("expected '::', got %q", aic.Principal())
	}
}

func TestHasProtocolEmpty(t *testing.T) {
	aic := &pki.AIC{}
	if aic.HasProtocol("anything") {
		t.Fatal("empty AIC should not have any protocol")
	}
}

func TestCheckPermissionEmpty(t *testing.T) {
	aic := &pki.AIC{}
	if aic.CheckPermission("anything") {
		t.Fatal("empty AIC should not have permission")
	}
}

func TestExtFieldMashal(t *testing.T) {
	ext := pki.ExtField{
		ExtnID:    asn1.ObjectIdentifier{1, 2, 3, 4},
		Critical:  true,
		ExtnValue: []byte("data"),
	}
	der, err := asn1.Marshal(ext)
	if err != nil {
		t.Fatalf("marshal ExtField: %v", err)
	}
	var decoded pki.ExtField
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal ExtField: %v", err)
	}
	if !decoded.ExtnID.Equal(asn1.ObjectIdentifier{1, 2, 3, 4}) {
		t.Fatal("ExtnID mismatch")
	}
	if !decoded.Critical {
		t.Fatal("Critical should be true")
	}
}

func TestAlgorithmIdentifierMarshal(t *testing.T) {
	ai := pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256}
	der, err := asn1.Marshal(ai)
	if err != nil {
		t.Fatalf("marshal AlgorithmIdentifier: %v", err)
	}
	var decoded pki.AlgorithmIdentifier
	_, err = asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal AlgorithmIdentifier: %v", err)
	}
	if !decoded.Algorithm.Equal(pki.OIDSigECDSAWithSHA256) {
		t.Fatal("Algorithm OID mismatch")
	}
}

func BenchmarkAICMarshal(b *testing.B) {
	aic := pki.AIC{
		Version:      1,
		AgentId:      "bench-agent",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "r", Identifier: "u", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{
			{SchemeId: "http", CapabilityId: "gateway:admin"},
			{SchemeId: "quic", CapabilityId: "gateway:read"},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = asn1.Marshal(aic)
	}
}

func BenchmarkParseAIC(b *testing.B) {
	aic := pki.AIC{
		Version:      1,
		AgentId:      "bench-agent",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "r", Identifier: "u", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
	}
	val, _ := asn1.Marshal(aic)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: pki.OIDAIC, Value: val},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pki.ParseAIC(cert)
	}
}

// Ensure fmt import is used (for error formatting tests)
var _ = fmt.Sprintf

func TestValidateAIC_ExtensionsSlotCap(t *testing.T) {
	aic := &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "r", Identifier: "u", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:         pki.Reason{ReasonCode: "OK", Description: "d"},
			Nonce:          make([]byte, 32),
			SignatureValue: []byte{1},
		},
		Extensions: make([]pki.ExtField, pki.MaxExtensionsSlots),
	}
	if err := pki.ValidateAIC(aic); err != nil {
		t.Fatalf("max slots should pass: %v", err)
	}
	aic.Extensions = make([]pki.ExtField, pki.MaxExtensionsSlots+1)
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for extensions count > MaxExtensionsSlots")
	}
}

func TestValidatePrincipalAuthorization(t *testing.T) {
	valid := &pki.PrincipalAuthorization{
		Grants: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
	}
	if err := pki.ValidatePrincipalAuthorization(valid); err != nil {
		t.Fatalf("valid PA should pass: %v", err)
	}
	// grants > 256
	over := &pki.PrincipalAuthorization{
		Grants: make([]pki.Capability, pki.MaxGrantEntries+1),
	}
	if err := pki.ValidatePrincipalAuthorization(over); err == nil {
		t.Fatal("expected error for grants > MaxGrantEntries")
	}
	// bad grant schemeId
	bad := &pki.PrincipalAuthorization{
		Grants: []pki.Capability{{SchemeId: "", CapabilityId: "x"}},
	}
	if err := pki.ValidatePrincipalAuthorization(bad); err == nil {
		t.Fatal("expected error for empty grant schemeId")
	}
	// constraint scheme in authorizationConstraints must be whitelisted
	badCons := &pki.PrincipalAuthorization{
		AuthorizationConstraints: []pki.Capability{{SchemeId: "other", CapabilityId: "x"}},
	}
	if err := pki.ValidatePrincipalAuthorization(badCons); err == nil {
		t.Fatal("expected error for non-constraint scheme in constraints")
	}
	// constraints > 8
	overCons := &pki.PrincipalAuthorization{
		AuthorizationConstraints: make([]pki.Capability, pki.MaxAuthorizationConstraints+1),
	}
	if err := pki.ValidatePrincipalAuthorization(overCons); err == nil {
		t.Fatal("expected error for constraints > MaxAuthorizationConstraints")
	}
	// delegationPolicy bounds
	badPolicy := &pki.PrincipalAuthorization{DelegationPolicy: pki.DelegationPolicy{AllowedMode: 2}}
	if err := pki.ValidatePrincipalAuthorization(badPolicy); err == nil {
		t.Fatal("expected error for allowedMode > 1")
	}
	// nil passes
	if err := pki.ValidatePrincipalAuthorization(nil); err != nil {
		t.Fatalf("nil PA should pass: %v", err)
	}
}

func TestValidateAIC_MaxSizeConstants(t *testing.T) {
	if pki.MaxRecommendedCertDERSize != 12*1024 {
		t.Fatalf("MaxRecommendedCertDERSize = %d, want 12288", pki.MaxRecommendedCertDERSize)
	}
	if pki.MaxHardCertDERSize != 16*1024 {
		t.Fatalf("MaxHardCertDERSize = %d, want 16384", pki.MaxHardCertDERSize)
	}
	if pki.MaxNonceLen != 32 || pki.MaxRequestedLifetime != 86400 || pki.MaxAuthorizationConstraints != 32 {
		t.Fatal("constant mismatch")
	}
}

func TestValidateSPIFFEID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		domain  string
		wantErr bool
	}{
		{"valid", "spiffe://varwof.com/agent/my-agent", "varwof.com", false},
		{"valid with subpath", "spiffe://example.com/agent/prod-web-server", "example.com", false},
		{"wrong scheme", "http://varwof.com/agent/my-agent", "varwof.com", true},
		{"wrong domain", "spiffe://other.com/agent/my-agent", "varwof.com", true},
		{"empty id", "", "varwof.com", true},
		{"no agents path", "spiffe://varwof.com/users/my-user", "varwof.com", true},
		{"empty domain", "spiffe:///agent/my-agent", "varwof.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pki.ValidateSPIFFEID(tt.id, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSPIFFEID(%q, %q) error = %v, wantErr %v", tt.id, tt.domain, err, tt.wantErr)
			}
		})
	}
}

func TestBuildSPIFFEID(t *testing.T) {
	id := pki.BuildSPIFFEID("varwof.com", "my-agent")
	if id != "spiffe://varwof.com/agent/my-agent" {
		t.Errorf("BuildSPIFFEID = %q, want spiffe://varwof.com/agent/my-agent", id)
	}
}

func TestIsSPIFFEAgentID(t *testing.T) {
	if !pki.IsSPIFFEAgentID("spiffe://varwof.com/agent/test") {
		t.Error("expected true for SPIFFE ID")
	}
	if pki.IsSPIFFEAgentID("test") {
		t.Error("expected false for plain agent ID")
	}
	// IsSPIFFEAgentID only checks the prefix, not the path
	if !pki.IsSPIFFEAgentID("spiffe://varwof.com/users/test") {
		t.Error("expected true for any spiffe:// prefix")
	}
}

func TestExtractSPIFFEIDFromCert(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	// No SPIFFE URI
	if got := pki.ExtractSPIFFEIDFromCert(cert); got != "" {
		t.Errorf("expected empty, got %q", got)
	}

	// With SPIFFE URI
	cert.URIs = append(cert.URIs, &url.URL{
		Scheme: "spiffe",
		Host:   "varwof.com",
		Path:   "/agent/test",
	})
	got := pki.ExtractSPIFFEIDFromCert(cert)
	if got != "spiffe://varwof.com/agent/test" {
		t.Errorf("ExtractSPIFFEIDFromCert = %q, want spiffe://varwof.com/agent/test", got)
	}
}

func TestAddSPIFFESANToCert(t *testing.T) {
	tmpl := &x509.Certificate{}
	err := pki.AddSPIFFESANToCert(tmpl, "spiffe://varwof.com/agent/test")
	if err != nil {
		t.Fatalf("AddSPIFFESANToCert: %v", err)
	}
	if len(tmpl.URIs) != 1 {
		t.Fatalf("expected 1 URI, got %d", len(tmpl.URIs))
	}
	if tmpl.URIs[0].String() != "spiffe://varwof.com/agent/test" {
		t.Errorf("URI = %q", tmpl.URIs[0].String())
	}

	// Add another URI - should not duplicate
	err = pki.AddSPIFFESANToCert(tmpl, "spiffe://varwof.com/agent/test")
	if err != nil {
		t.Fatalf("AddSPIFFESANToCert duplicate: %v", err)
	}
	if len(tmpl.URIs) != 1 {
		t.Errorf("expected 1 URI after duplicate, got %d", len(tmpl.URIs))
	}
}

func TestParseSPIFFEAgentName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"spiffe://varwof.com/agent/scheduler-a", "scheduler-a"},
		{"spiffe://varwof.com/agent/agent-01", "agent-01"},
		{"not-spiffe", "not-spiffe"},
		{"spiffe://varwof.com/agent/", ""},
	}
	for _, c := range cases {
		if got := pki.ParseSPIFFEAgentName(c.in); got != c.want {
			t.Errorf("ParseSPIFFEAgentName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseSPIFFEDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"spiffe://varwof.com/agent/scheduler-a", "varwof.com"},
		{"spiffe://example.org/agent/x", "example.org"},
		{"not-spiffe", ""},
		{"spiffe:///agent/x", ""},
	}
	for _, c := range cases {
		if got := pki.ParseSPIFFEDomain(c.in); got != c.want {
			t.Errorf("ParseSPIFFEDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateMaxConcurrentParam(t *testing.T) {
	if err := pki.ValidateMaxConcurrentParam(nil); err != nil {
		t.Errorf("nil should pass, got %v", err)
	}
	if err := pki.ValidateMaxConcurrentParam([]byte("  ")); err != nil {
		t.Errorf("blank should pass, got %v", err)
	}
	if err := pki.ValidateMaxConcurrentParam([]byte(`{"max":5}`)); err != nil {
		t.Errorf("valid max should pass, got %v", err)
	}
	if err := pki.ValidateMaxConcurrentParam([]byte(`{"max":0}`)); err == nil {
		t.Error("max below MinConcurrentMin should fail")
	}
	if err := pki.ValidateMaxConcurrentParam([]byte(`{"max":2000}`)); err == nil {
		t.Error("max above MaxConcurrentMax should fail")
	}
	if err := pki.ValidateMaxConcurrentParam([]byte(`not-json`)); err == nil {
		t.Error("invalid JSON should fail")
	}
	if err := pki.ValidateMaxConcurrentParam([]byte(`{"max":1}`)); err != nil {
		t.Errorf("lower bound max should pass, got %v", err)
	}
	if err := pki.ValidateMaxConcurrentParam([]byte(`{"max":1024}`)); err != nil {
		t.Errorf("upper bound max should pass, got %v", err)
	}
}
