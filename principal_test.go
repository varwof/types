package pki_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

func TestPrincipalUidString(t *testing.T) {
	keyHash := sha256.Sum256([]byte("test-key"))
	uid := pki.PrincipalUid{
		Version:    1,
		Realm:      "varwof",
		Identifier: "alice",
		KeyHash:    keyHash[:],
	}
	s := uid.String()
	expectedPrefix := "varwof:alice:"
	if !strings.HasPrefix(s, expectedPrefix) {
		t.Fatalf("expected prefix %q, got %q", expectedPrefix, s)
	}
	// Verify the fingerprint part is valid base64url
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(decoded))
	}
}

func TestPrincipalUidStringEmpty(t *testing.T) {
	uid := pki.PrincipalUid{}
	s := uid.String()
	if s != "::" {
		t.Fatalf("expected '::', got %q", s)
	}
}

func TestParsePrincipalUid(t *testing.T) {
	keyHash := sha256.Sum256([]byte("key"))
	fp := base64.RawURLEncoding.EncodeToString(keyHash[:])
	input := "varwof:alice:" + fp
	uid, err := pki.ParsePrincipalUid(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid.Version != 1 {
		t.Fatalf("Version: expected 1, got %d", uid.Version)
	}
	if uid.Realm != "varwof" {
		t.Fatalf("Realm: expected varwof, got %s", uid.Realm)
	}
	if uid.Identifier != "alice" {
		t.Fatalf("Identifier: expected alice, got %s", uid.Identifier)
	}
	if len(uid.KeyHash) != 32 {
		t.Fatalf("KeyHash: expected 32 bytes, got %d", len(uid.KeyHash))
	}
}

func TestParsePrincipalUid_InvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"too few parts", "varwof:alice"},
		{"too many parts", "a:b:c:d"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pki.ParsePrincipalUid(tt.input)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParsePrincipalUid_InvalidBase64(t *testing.T) {
	_, err := pki.ParsePrincipalUid("varwof:alice:!!!invalid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParsePrincipalUid_WrongKeyHashSize(t *testing.T) {
	fp := base64.RawURLEncoding.EncodeToString(make([]byte, 65))
	_, err := pki.ParsePrincipalUid("varwof:alice:" + fp)
	if err == nil {
		t.Fatal("expected error for wrong key hash size")
	}
}

func TestParsePrincipalUid_KeyHashSizeInRange(t *testing.T) {
	// v1.7.1 allows 1..64 bytes (algo-dependent); 3 bytes is valid at parse level.
	fp := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
	uid, err := pki.ParsePrincipalUid("varwof:alice:" + fp)
	if err != nil {
		t.Fatalf("unexpected error for 3-byte keyHash: %v", err)
	}
	if len(uid.KeyHash) != 3 {
		t.Fatalf("KeyHash: expected 3 bytes, got %d", len(uid.KeyHash))
	}
}

func TestParsePrincipalUid_RealmIdentifierBounds(t *testing.T) {
	fp := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		name  string
		input string
	}{
		{"empty realm", ":alice:" + fp},
		{"realm too long", strings.Repeat("r", 129) + ":alice:" + fp},
		{"empty identifier", "varwof::" + fp},
		{"identifier too long", "varwof:" + strings.Repeat("i", 257) + ":" + fp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pki.ParsePrincipalUid(tt.input)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParsePrincipalUid_ColonInParts(t *testing.T) {
	// realm contains colon
	_, err := pki.ParsePrincipalUid("var:wof:alice:AAAA")
	if err == nil {
		t.Fatal("expected error for colon in realm")
	}
}

// ParsePrincipalUid round-trip.
func TestPrincipalUidRoundTrip(t *testing.T) {
	keyHash := sha256.Sum256([]byte("roundtrip"))
	original := pki.PrincipalUid{
		Version:    1,
		Realm:      "prod",
		Identifier: "bot-42",
		KeyHash:    keyHash[:],
		HashAlgo:   pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
	}
	s := original.String()
	parsed, err := pki.ParsePrincipalUid(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Realm != original.Realm {
		t.Fatalf("Realm mismatch: %s vs %s", parsed.Realm, original.Realm)
	}
	if parsed.Identifier != original.Identifier {
		t.Fatalf("Identifier mismatch: %s vs %s", parsed.Identifier, original.Identifier)
	}
}

func TestMakePrincipalUidFromCert(t *testing.T) {
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

	uid := pki.MakePrincipalUidFromCert("prod", "agent-1", cert)
	if uid.Version != 1 {
		t.Fatalf("Version: expected 1, got %d", uid.Version)
	}
	if uid.Realm != "prod" {
		t.Fatalf("Realm: expected prod, got %s", uid.Realm)
	}
	if uid.Identifier != "agent-1" {
		t.Fatalf("Identifier: expected agent-1, got %s", uid.Identifier)
	}
	if len(uid.KeyHash) != 32 {
		t.Fatalf("KeyHash: expected 32 bytes, got %d", len(uid.KeyHash))
	}
	// Verify KeyHash is SPKI hash (not cert DER hash)
	pubBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	expectedHash := sha256.Sum256(pubBytes)
	for i := range uid.KeyHash {
		if uid.KeyHash[i] != expectedHash[i] {
			t.Fatalf("KeyHash mismatch at byte %d: expected %02x, got %02x", i, expectedHash[i], uid.KeyHash[i])
		}
	}
}

func TestMakePrincipalUidFromCert_DifferentKeys(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	makeCert := func(key *rsa.PrivateKey) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "test"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(der)
		return cert
	}

	uid1 := pki.MakePrincipalUidFromCert("r", "a", makeCert(key1))
	uid2 := pki.MakePrincipalUidFromCert("r", "a", makeCert(key2))

	// Different keys should produce different hashes
	equal := true
	for i := range uid1.KeyHash {
		if uid1.KeyHash[i] != uid2.KeyHash[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Fatal("different keys should produce different KeyHash values")
	}
}
