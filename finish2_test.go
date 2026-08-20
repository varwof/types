package pki_test

import (
	"encoding/asn1"
	"fmt"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

func validAICBase() *pki.AIC {
	return &pki.AIC{
		AgentId:      "test",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "alice", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:            pki.Reason{ReasonCode: "OK", Description: "d"},
			Timestamp:         time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC),
			RequestedLifetime: 3600,
			Nonce:             make([]byte, 32),
			SignatureValue:    []byte{1},
		},
	}
}

func TestValidateAIC_AgentIdLength(t *testing.T) {
	for _, agentId := range []string{"", strings.Repeat("x", 257)} {
		aic := validAICBase()
		aic.AgentId = agentId
		if err := pki.ValidateAIC(aic); err == nil {
			t.Fatalf("expected error for agentId length %d", len(agentId))
		}
	}
}

func TestValidateAIC_IdentifierLength(t *testing.T) {
	aic := validAICBase()
	aic.PrincipalUid.Identifier = ""
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for empty identifier")
	}
}

func TestValidateAIC_KeyHashBadFullBase(t *testing.T) {
	aic := validAICBase()
	aic.PrincipalUid.KeyHash = make([]byte, 16)
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for bad keyHash length")
	}
}

func TestValidateAIC_DAMissingFullBase(t *testing.T) {
	aic := validAICBase()
	aic.DelegationAuthorization = pki.DelegationAuthorization{}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for missing DA")
	}
}

func TestValidateAIC_ReasonCodeEmptyFullBase(t *testing.T) {
	aic := validAICBase()
	aic.DelegationAuthorization.Reason = pki.Reason{Description: "d"}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for empty reasonCode")
	}
}

func TestValidateAIC_ReasonDescriptionEmptyFullBase(t *testing.T) {
	aic := validAICBase()
	aic.DelegationAuthorization.Reason = pki.Reason{ReasonCode: "OK"}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for empty reason description")
	}
}

func TestValidateAIC_ReasonLengthsFullBase(t *testing.T) {
	aic := validAICBase()
	aic.DelegationAuthorization.Reason = pki.Reason{ReasonCode: strings.Repeat("X", 65), Description: "d"}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for reasonCode > 64")
	}
	aic = validAICBase()
	aic.DelegationAuthorization.Reason = pki.Reason{ReasonCode: "OK", Description: strings.Repeat("d", 513)}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for description > 512")
	}
}

func TestValidateAIC_NonceSizeFullBase(t *testing.T) {
	aic := validAICBase()
	aic.DelegationAuthorization.Nonce = []byte{1, 2, 3}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for nonce < 32")
	}
}

func TestValidateAIC_ConstraintsTooMany(t *testing.T) {
	aic := validAICBase()
	for i := 0; i < pki.MaxAuthorizationConstraints+1; i++ {
		aic.AuthorizationConstraints = append(aic.AuthorizationConstraints, pki.Capability{
			SchemeId: "varwof/constraint-v1", CapabilityId: "c",
		})
	}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for constraints > MaxAuthorizationConstraints")
	}
}

func TestValidateAIC_ConstraintCapIdEmpty(t *testing.T) {
	aic := validAICBase()
	aic.AuthorizationConstraints = []pki.Capability{{SchemeId: "varwof/constraint-v1"}}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for empty constraint capabilityId")
	}
}

func TestValidateAIC_ConstraintParamsTooLong(t *testing.T) {
	aic := validAICBase()
	aic.AuthorizationConstraints = []pki.Capability{{
		SchemeId: "varwof/constraint-v1", CapabilityId: "c", Parameters: make([]byte, 513),
	}}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for constraint params > 512")
	}
}

func TestValidateAIC_ConstraintParamsInvalidJSON(t *testing.T) {
	aic := validAICBase()
	aic.AuthorizationConstraints = []pki.Capability{{
		SchemeId: "varwof/constraint-v1", CapabilityId: "c", Parameters: []byte("not-json"),
	}}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("expected error for invalid JSON constraint params")
	}
}

func TestValidateAIC_MaxConcurrentParams(t *testing.T) {
	// Valid {"max":10} → pass.
	aic := validAICBase()
	aic.AuthorizationConstraints = []pki.Capability{{
		SchemeId: "varwof/constraint-v1", CapabilityId: pki.ConstraintConcurrentKey, Parameters: []byte(`{"max": 10}`),
	}}
	if err := pki.ValidateAIC(aic); err != nil {
		t.Fatalf("valid max-concurrent rejected: %v", err)
	}
	// Boundary values 1 and 1024 → pass.
	for _, m := range []int{1, 1024} {
		aic.AuthorizationConstraints = []pki.Capability{{
			SchemeId: "varwof/constraint-v1", CapabilityId: pki.ConstraintConcurrentKey,
			Parameters: []byte(fmt.Sprintf(`{"max": %d}`, m)),
		}}
		if err := pki.ValidateAIC(aic); err != nil {
			t.Fatalf("boundary max=%d rejected: %v", m, err)
		}
	}
	// 0 and 1025 → rejected.
	for _, m := range []int{0, 1025} {
		aic.AuthorizationConstraints = []pki.Capability{{
			SchemeId: "varwof/constraint-v1", CapabilityId: pki.ConstraintConcurrentKey,
			Parameters: []byte(fmt.Sprintf(`{"max": %d}`, m)),
		}}
		if err := pki.ValidateAIC(aic); err == nil {
			t.Fatalf("max=%d should be rejected", m)
		}
	}
	// Non-JSON → rejected.
	aic.AuthorizationConstraints = []pki.Capability{{
		SchemeId: "varwof/constraint-v1", CapabilityId: pki.ConstraintConcurrentKey, Parameters: []byte(`{"max": "ten"}`),
	}}
	if err := pki.ValidateAIC(aic); err == nil {
		t.Fatal("invalid max-concurrent JSON should be rejected")
	}
	// Empty parameters → pass (not configured).
	aic.AuthorizationConstraints = []pki.Capability{{
		SchemeId: "varwof/constraint-v1", CapabilityId: pki.ConstraintConcurrentKey,
	}}
	if err := pki.ValidateAIC(aic); err != nil {
		t.Fatalf("empty max-concurrent params rejected: %v", err)
	}
}

func TestValidateAIC_KnownCriticalExtAndNonCriticalUnknown(t *testing.T) {
	aic := validAICBase()
	aic.Extensions = []pki.ExtField{
		{ExtnID: pki.OIDPrincipalAuthorization, Critical: true},
		{ExtnID: asn1.ObjectIdentifier{9, 9, 9}, Critical: false},
	}
	if err := pki.ValidateAIC(aic); err != nil {
		t.Fatalf("known-critical + non-critical unknown ext should pass: %v", err)
	}
}

func TestParseAIC_MissingDA(t *testing.T) {
	aic := pki.AIC{
		Version:      1,
		AgentId:      "agent-noda",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
	}
	val, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cert := makeCertWithExt(t, pki.OIDAIC, val)
	parsed, err := pki.ParseAIC(cert)
	if err == nil {
		t.Fatal("expected error for AIC without DA")
	}
	if parsed != nil {
		t.Fatal("expected nil AIC on error")
	}
}

func TestIntersectPermissionsStrAnyEdgeCases(t *testing.T) {
	var nilAIC *pki.AIC
	if got := nilAIC.IntersectPermissionsStrAny("gateway:admin"); got != nil {
		t.Fatal("nil AIC should return nil")
	}
	aic := &pki.AIC{Capabilities: []pki.Capability{{CapabilityId: "gateway:admin"}}}
	if got := aic.IntersectPermissionsStrAny(""); got != nil {
		t.Fatal("empty perms should return nil")
	}
	got := aic.IntersectPermissionsStrAny("gateway:admin,, ca:list, ,x")
	if len(got) != 1 || got[0] != "gateway:admin" {
		t.Fatalf("expected [gateway:admin], got %v", got)
	}
}

func TestMatchCapabilityDoubleStarErrors(t *testing.T) {
	if pki.MatchCapability("z/y", "a/**") {
		t.Fatal("prefix mismatch should not match")
	}
	if pki.MatchCapability("a/z", "**/b") {
		t.Fatal("suffix mismatch should not match")
	}
	if pki.MatchCapability("a/../x/b", "a/**/b") {
		t.Fatal(".. segment should not match")
	}
	if pki.MatchCapability("a//x/b", "a/**/b") {
		t.Fatal("empty segment should not match")
	}
}

func TestGSCIDRAllowed_InvalidCIDRInList(t *testing.T) {
	gs := &pki.GatewaySessionExtension{AllowedCIDRs: []string{"not-a-cidr", "10.0.0.0/8"}}
	if !gs.CIDRAllowed("10.1.1.1") {
		t.Fatal("valid CIDR after invalid entry should match")
	}
	gs2 := &pki.GatewaySessionExtension{AllowedCIDRs: []string{"not-a-cidr"}}
	if gs2.CIDRAllowed("10.1.1.1") {
		t.Fatal("only-invalid CIDR list should not match")
	}
}
