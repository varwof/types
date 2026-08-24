// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

func TestHashAlgoOIDs(t *testing.T) {
	expected := map[string]asn1.ObjectIdentifier{
		"sha256":   pki.OIDSHA256,
		"sha384":   pki.OIDSHA384,
		"sha512":   pki.OIDSHA512,
		"sha3-256": {2, 16, 840, 1, 101, 3, 4, 2, 8},
		"sha3-384": {2, 16, 840, 1, 101, 3, 4, 2, 9},
		"sha3-512": {2, 16, 840, 1, 101, 3, 4, 2, 10},
	}
	if len(pki.HashAlgoOIDs) != len(expected) {
		t.Fatalf("HashAlgoOIDs: expected %d entries, got %d", len(expected), len(pki.HashAlgoOIDs))
	}
	for name, want := range expected {
		got, ok := pki.HashAlgoOIDs[name]
		if !ok {
			t.Fatalf("HashAlgoOIDs missing entry: %s", name)
		}
		if !got.Equal(want) {
			t.Fatalf("HashAlgoOIDs[%s]: expected %v, got %v", name, want, got)
		}
	}
}

func TestParseHashAlgo_Empty(t *testing.T) {
	oid, err := pki.ParseHashAlgo("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if oid != nil {
		t.Fatal("expected nil for empty string")
	}
}

func TestParseHashAlgo_SHA256(t *testing.T) {
	oid, err := pki.ParseHashAlgo("sha256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !oid.Equal(pki.OIDSHA256) {
		t.Fatalf("expected SHA-256 OID, got %v", oid)
	}
}

func TestParseHashAlgo_CaseInsensitive(t *testing.T) {
	oid, err := pki.ParseHashAlgo("SHA256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !oid.Equal(pki.OIDSHA256) {
		t.Fatalf("expected SHA-256 OID for uppercase input")
	}
}

func TestParseHashAlgo_AllSupported(t *testing.T) {
	names := []string{"sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"}
	for _, name := range names {
		oid, err := pki.ParseHashAlgo(name)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", name, err)
		}
		if oid == nil {
			t.Fatalf("nil OID for %s", name)
		}
	}
}

func TestParseHashAlgo_Unsupported(t *testing.T) {
	_, err := pki.ParseHashAlgo("md5")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestDefaultHashAlgo(t *testing.T) {
	oid := pki.DefaultHashAlgo()
	if !oid.Equal(pki.OIDSHA256) {
		t.Fatalf("default hash algo: expected SHA-256 OID, got %v", oid)
	}
}

func TestOIDSHAConstants(t *testing.T) {
	// Verify the OID constants are well-formed
	if !pki.OIDSHA256.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}) {
		t.Fatal("OIDSHA256 incorrect")
	}
	if !pki.OIDSHA384.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}) {
		t.Fatal("OIDSHA384 incorrect")
	}
	if !pki.OIDSHA512.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}) {
		t.Fatal("OIDSHA512 incorrect")
	}
}

func TestKeyHashFromSPKI_AlgoFamily(t *testing.T) {
	spki := []byte("test-public-key-der-bytes")
	cases := []struct {
		algo string
		want int
	}{
		{"sha256", 32},
		{"sha384", 48},
		{"sha512", 64},
		{"sha3-256", 32},
		{"sha3-384", 48},
		{"sha3-512", 64},
	}
	for _, c := range cases {
		oid, err := pki.ParseHashAlgo(c.algo)
		if err != nil {
			t.Fatalf("parse %s: %v", c.algo, err)
		}
		got, err := pki.KeyHashFromSPKI(oid, spki)
		if err != nil {
			t.Fatalf("KeyHashFromSPKI(%s): %v", c.algo, err)
		}
		if len(got) != c.want {
			t.Fatalf("KeyHashFromSPKI(%s) length = %d, want %d", c.algo, len(got), c.want)
		}
	}
	// Each algorithm should produce different output.
	h256, _ := pki.KeyHashFromSPKI(pki.OIDSHA256, spki)
	h384, _ := pki.KeyHashFromSPKI(pki.OIDSHA384, spki)
	if string(h256) == string(h384[:32]) {
		t.Fatal("sha256 and sha384(truncated) should differ")
	}
}

func TestKeyHashFromSPKI_ExternalDepAlgos(t *testing.T) {
	spki := []byte("test-public-key-der-bytes")
	// Unknown OID → explicit error.
	unknown := asn1.ObjectIdentifier{9, 9, 9}
	if _, err := pki.KeyHashFromSPKI(unknown, spki); err == nil {
		t.Fatal("unknown OID should error")
	}
}

func TestKeyHashFromCertSPKI_ValidateRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key gen: %v", err)
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

	uid, err := pki.MakePrincipalUidFromCertWithAlgo("corp.com", "zhangsan", cert, pki.OIDSHA384)
	if err != nil {
		t.Fatalf("MakePrincipalUidFromCertWithAlgo: %v", err)
	}
	if len(uid.KeyHash) != 48 {
		t.Fatalf("SHA-384 keyHash length = %d, want 48", len(uid.KeyHash))
	}
	if err := pki.ValidatePrincipalUidKeyHash(uid); err != nil {
		t.Fatalf("ValidatePrincipalUidKeyHash: %v", err)
	}
	// Default SHA-256 for backward compatibility with old signatures.
	uid256 := pki.MakePrincipalUidFromCert("corp.com", "zhangsan", cert)
	if len(uid256.KeyHash) != 32 {
		t.Fatalf("default SHA-256 keyHash length = %d, want 32", len(uid256.KeyHash))
	}
	if err := pki.ValidatePrincipalUidKeyHash(uid256); err != nil {
		t.Fatalf("default validate: %v", err)
	}
}

func TestSupportedHashAlgos(t *testing.T) {
	algos := pki.SupportedHashAlgos()
	if len(algos) != len(pki.HashAlgoOIDs) {
		t.Fatalf("SupportedHashAlgos() length = %d, HashAlgoOIDs = %d", len(algos), len(pki.HashAlgoOIDs))
	}
	for _, a := range algos {
		if _, ok := pki.HashAlgoOIDs[a]; !ok {
			t.Errorf("SupportedHashAlgos contains %q not in HashAlgoOIDs", a)
		}
	}
	for name := range pki.HashAlgoOIDs {
		found := false
		for _, a := range algos {
			if a == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("HashAlgoOIDs key %q missing from SupportedHashAlgos", name)
		}
	}
}

func TestHashOIDName(t *testing.T) {
	for name, oid := range pki.HashAlgoOIDs {
		if got := pki.HashOIDName(oid); got != name {
			t.Errorf("HashOIDName(%v) = %q, want %q", oid, got, name)
		}
	}
	if got := pki.HashOIDName(asn1.ObjectIdentifier{1, 2, 3, 4}); got != "" {
		t.Errorf("HashOIDName(unknown) = %q, want empty", got)
	}
}
