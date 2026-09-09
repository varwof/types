package pki_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// v1GoldenDER is the byte-for-byte DER of DelegationAuthTBS before the
// AgentKeyBinding field was introduced (DA version 1). Captured with the
// pre-change type: no AgentKeyBinding, Version omitted-as-1. It MUST stay
// stable — old da/client/signer DER and certificates must remain parseable
// and verifiable.
const v1GoldenDER = "3081e30201010c076167656e742d3730410201010c0461636d650c05616c69636504200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20a00d300b060960864801650304020130170c036f70730c1072656c6561736520706970656c696e65301d301b0c0263610c056973737565a00e040c7b2274706c223a226369227d020100a020301e301c0c0a636f6e73747261696e740c03637431a00904077b2278223a317d02020e10180f32303236303330343035303630375a04203031323334353637383930313233343536373839303132333435363738393031"

func fixedKeyHash() []byte {
	kh := make([]byte, 32)
	for i := range kh {
		kh[i] = byte(i + 1)
	}
	return kh
}

func v1GoldenTBS() pki.DelegationAuthTBS {
	return pki.DelegationAuthTBS{
		Version:                  1,
		AgentId:                  "agent-7",
		PrincipalUid:             pki.PrincipalUid{Version: 1, Realm: "acme", Identifier: "alice", KeyHash: fixedKeyHash(), HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256}},
		Reason:                   pki.Reason{ReasonCode: "ops", Description: "release pipeline"},
		Capabilities:             []pki.Capability{{SchemeId: "ca", CapabilityId: "issue", Parameters: []byte(`{"tpl":"ci"}`)}},
		DelegationMode:           pki.DelegationAuthorized,
		AuthorizationConstraints: []pki.Capability{{SchemeId: "constraint", CapabilityId: "ct1", Parameters: []byte(`{"x":1}`)}},
		RequestedLifetime:        3600,
		Timestamp:                time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		Nonce:                    []byte("01234567890123456789012345678901"),
	}
}

// TestDelegationAuthTBSV1Golden asserts the legacy v1 DER is byte-identical
// after the AgentKeyBinding field was added (the zero value marshals nothing),
// and that a version=0 TBS (default omitted) is accepted but produces a
// distinct DER (INTEGER 0 vs INTEGER 1).
func TestDelegationAuthTBSV1Golden(t *testing.T) {
	der, err := asn1.Marshal(v1GoldenTBS())
	if err != nil {
		t.Fatalf("marshal v1 TBS: %v", err)
	}
	want, err := hex.DecodeString(v1GoldenDER)
	if err != nil {
		t.Fatalf("golden hex: %v", err)
	}
	if string(der) != string(want) {
		t.Fatalf("v1 DER drift:\n got %x\nwant %x", der, want)
	}

	// Version omitted (0) must accept as version 1 via ValidateDelegationAuthTBSVersion.
	v0 := v1GoldenTBS()
	v0.Version = 0
	if err := pki.ValidateDelegationAuthTBSVersion(&v0); err != nil {
		t.Fatalf("version 0 must pass validation: %v", err)
	}
	// The raw DER differs — version 0 encodes INTEGER 0, not INTEGER 1.
	v0der, err := asn1.Marshal(v0)
	if err != nil {
		t.Fatalf("marshal v1(version 0) TBS: %v", err)
	}
	if string(v0der) == string(want) {
		t.Fatal("version-omitted DER must not equal v1 golden (different INTEGER encoding)")
	}
}

// TestDelegationAuthTBSV2RoundTrip covers marshal→unmarshal fidelity for
// DA version 2 with an agent key binding, plus the [1] EXPLICIT wrapper.
func TestDelegationAuthTBSV2RoundTrip(t *testing.T) {
	spki := []byte("agent-spki-der-000infinity")
	sum := sha256.Sum256(spki)
	binding := pki.AgentKeyBinding{
		KeyHash:  sum[:],
		HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
	}
	tbs := v1GoldenTBS()
	tbs.Version = pki.DAVersion2
	tbs.AgentKeyBinding = binding
	der, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshal v2 TBS: %v", err)
	}

	var decoded pki.DelegationAuthTBS
	rest, err := asn1.Unmarshal(der, &decoded)
	if err != nil {
		t.Fatalf("unmarshal v2 TBS: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unmarshal left %d trailing bytes", len(rest))
	}
	if decoded.Version != pki.DAVersion2 {
		t.Fatalf("version: got %d want %d", decoded.Version, pki.DAVersion2)
	}
	if !decoded.AgentKeyBinding.HashAlgo.Algorithm.Equal(binding.HashAlgo.Algorithm) {
		t.Fatalf("hashAlgo: got %v want %v", decoded.AgentKeyBinding.HashAlgo.Algorithm, binding.HashAlgo.Algorithm)
	}
	if string(decoded.AgentKeyBinding.KeyHash) != string(binding.KeyHash) {
		t.Fatalf("keyHash mismatch: got %x want %x", decoded.AgentKeyBinding.KeyHash, binding.KeyHash)
	}
	if err := pki.ValidateDelegationAuthTBSVersion(&decoded); err != nil {
		t.Fatalf("round-tripped v2 must validate: %v", err)
	}

	// DER must contain a trailing [1] EXPLICIT wrapper (0xa1 tag byte) wrapping
	// the AgentKeyBinding sequence — scan backwards for it.
	foundWrapper := false
	for i := len(der) - 1; i >= 0; i-- {
		if der[i] == 0xa1 {
			// Must not be the very last byte (nothing would follow).
			if i < len(der)-1 {
				foundWrapper = true
			}
			break
		}
	}
	if !foundWrapper {
		t.Fatalf("DER lacks [1] EXPLICIT AgentKeyBinding tag: %x", der[len(der)-40:])
	}
	// A v1 DER must NOT contain a trailing a1 tag after Nonce.
	v1der, _ := asn1.Marshal(v1GoldenTBS())
	foundV1Wrapper := false
	for i := len(v1der) - 1; i >= 0; i-- {
		if v1der[i] == 0xa1 && i < len(v1der)-1 {
			foundV1Wrapper = true
			break
		}
	}
	if foundV1Wrapper {
		t.Fatal("v1 DER unexpectedly contains trailing [1] EXPLICIT wrapper")
	}

	// hashAlgo default: a binding with empty HashAlgo must round-trip the same.
	noAlgo := tbs
	noAlgo.AgentKeyBinding.HashAlgo = pki.AlgorithmIdentifier{}
	nader, err := asn1.Marshal(noAlgo)
	if err != nil {
		t.Fatalf("marshal no-hashAlgo v2 TBS: %v", err)
	}
	var nd pki.DelegationAuthTBS
	if _, err := asn1.Unmarshal(nader, &nd); err != nil {
		t.Fatalf("unmarshal no-hashAlgo v2 TBS: %v", err)
	}
	if got := nd.AgentKeyBinding.HashAlgoOID(); !got.Equal(pki.OIDSHA256) {
		t.Fatalf("default hashAlgo: got %v want sha256", got)
	}
}

// TestMakeAgentKeyBinding checks the factory: empty algo → SHA-256 default,
// unsupported algorithm → explicit error.
func TestMakeAgentKeyBinding(t *testing.T) {
	spki := []byte("some-agent-spki")
	made, err := pki.MakeAgentKeyBinding(nil, spki)
	if err != nil {
		t.Fatalf("make default binding: %v", err)
	}
	sum := sha256.Sum256(spki)
	if string(made.KeyHash) != string(sum[:]) {
		t.Fatalf("default keyHash mismatch")
	}
	if !made.HashAlgo.Algorithm.Equal(pki.OIDSHA256) {
		t.Fatalf("default algo: got %v", made.HashAlgo.Algorithm)
	}
	if _, err := pki.MakeAgentKeyBinding(nil, nil); err == nil {
		t.Fatal("empty SPKI must error")
	}
	if _, err := pki.MakeAgentKeyBinding(asn1.ObjectIdentifier{1, 2, 3, 4}, spki); err == nil {
		t.Fatal("unsupported hashAlgo must error")
	}
}

// TestValidateDelegationAuthTBSVersion enforces the version matrix.
func TestValidateDelegationAuthTBSVersion(t *testing.T) {
	// v1 without binding → ok
	if err := pki.ValidateDelegationAuthTBSVersion(&pki.DelegationAuthTBS{Version: pki.DAVersion1}); err != nil {
		t.Fatalf("v1 no binding: %v", err)
	}
	// version omitted/nil → treated as v1
	if err := pki.ValidateDelegationAuthTBSVersion(&pki.DelegationAuthTBS{}); err != nil {
		t.Fatalf("v0: %v", err)
	}
	// version 3 → reject
	if err := pki.ValidateDelegationAuthTBSVersion(&pki.DelegationAuthTBS{Version: 3}); err == nil {
		t.Fatal("version 3 must be rejected")
	}
}

// TestValidateAgentKeyBinding negative matrix.
func TestValidateAgentKeyBinding(t *testing.T) {
	spki := []byte("agent-spki-0000")
	sum := sha256.Sum256(spki)
	sha384Sum := sha384Of(spki)

	cases := []struct {
		name string
		b    pki.AgentKeyBinding
		ok   bool
	}{
		{"sha256-32-len", pki.AgentKeyBinding{KeyHash: sum[:], HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256}}, true},
		{"sha384-48-len", pki.AgentKeyBinding{KeyHash: sha384Sum, HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA384}}, true},
		{"empty-keyhash", pki.AgentKeyBinding{}, false},
		// A v2 binding with the wrong output length for the declared hashAlgo.
		{"sha256-with-48-byte", pki.AgentKeyBinding{KeyHash: sha384Sum, HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256}}, false},
		{"sha384-with-32-byte", pki.AgentKeyBinding{KeyHash: sum[:], HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA384}}, false},
		{"65-byte-keyhash", pki.AgentKeyBinding{KeyHash: make([]byte, 65)}, false},
		{"unsupported-algo", pki.AgentKeyBinding{KeyHash: make([]byte, 32), HashAlgo: pki.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}}, false},
	}
	for _, c := range cases {
		err := pki.ValidateAgentKeyBinding(c.b)
		if c.ok && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

// TestAgentKeyBindingInDAVersionMatrix ties the version rules together.
func TestAgentKeyBindingInDAVersionMatrix(t *testing.T) {
	tbs := v1GoldenTBS()
	spki := []byte("agent-spki-0000")
	sum := sha256.Sum256(spki)
	binding := pki.AgentKeyBinding{KeyHash: sum[:], HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256}}

	// v2 must carry the binding.
	v2 := tbs
	v2.Version = pki.DAVersion2
	v2.AgentKeyBinding = binding
	if err := pki.ValidateDelegationAuthTBSVersion(&v2); err != nil {
		t.Fatalf("valid v2 rejected: %v", err)
	}
	// v2 missing the binding → reject.
	broken := tbs
	broken.Version = pki.DAVersion2
	if err := pki.ValidateDelegationAuthTBSVersion(&broken); err == nil {
		t.Fatal("v2 without binding must be rejected")
	}
	// v1 carrying a binding → reject (an attacker must not smuggle an agent
	// binding into a legacy v1 signature over which it was never signed).
	v1 := tbs
	v1.AgentKeyBinding = binding
	if err := pki.ValidateDelegationAuthTBSVersion(&v1); err == nil {
		t.Fatal("v1 with binding must be rejected")
	}
}

func sha384Of(b []byte) []byte {
	h := sha512.Sum384(b)
	return h[:]
}
