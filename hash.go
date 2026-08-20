package pki

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

// HashAlgoOIDs maps hash algorithm name strings to OIDs.
var HashAlgoOIDs = map[string]asn1.ObjectIdentifier{
	"sha256":   OIDSHA256,
	"sha384":   OIDSHA384,
	"sha512":   OIDSHA512,
	"sha3-256": {2, 16, 840, 1, 101, 3, 4, 2, 8},
	"sha3-384": {2, 16, 840, 1, 101, 3, 4, 2, 9},
	"sha3-512": {2, 16, 840, 1, 101, 3, 4, 2, 10},
}

// HashOutputLen returns the output byte length for each hash algorithm OID (spec P1-A-12).
// Supports SHA-2/SHA-3 (stdlib implementation); BLAKE2/BLAKE3 only register known OID-to-length mappings per zero external dependency policy
// (consistent with keyHash OCTET STRING SIZE(1..64) semantics); actual computation requires
// the corresponding dependencies on the gateway/core side.
var HashOutputLen = map[string]int{
	"sha256":   32,
	"sha384":   48,
	"sha512":   64,
	"sha3-256": 32,
	"sha3-384": 48,
	"sha3-512": 64,
}

// SupportedHashAlgos returns the names of computationally implemented algorithms (SHA-2/SHA-3 family).
func SupportedHashAlgos() []string {
	return []string{"sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"}
}

// HashOIDName returns the canonical name of a hash algorithm OID; returns empty string if unknown.
func HashOIDName(oid asn1.ObjectIdentifier) string {
	for name, o := range HashAlgoOIDs {
		if o.Equal(oid) {
			return name
		}
	}
	return ""
}

// ParseHashAlgo parses a hash algorithm string to an OID. Returns nil if empty.
func ParseHashAlgo(s string) (asn1.ObjectIdentifier, error) {
	if s == "" {
		return nil, nil
	}
	oid, ok := HashAlgoOIDs[strings.ToLower(s)]
	if !ok {
		return nil, fmt.Errorf("hash_algo: unsupported algorithm %q, supported: sha256, sha384, sha512, sha3-256, sha3-384, sha3-512", s)
	}
	return oid, nil
}

// DefaultHashAlgo returns the default SHA-256 OID.
func DefaultHashAlgo() asn1.ObjectIdentifier {
	return OIDSHA256
}

// KeyHashFromSPKI computes the SPKI DER digest (keyHash) of a public key using the specified hash algorithm OID.
// Supports stdlib-implemented SHA-2/SHA-3 family; other algorithms return explicit errors (to prevent silent degradation).
func KeyHashFromSPKI(algo asn1.ObjectIdentifier, spkiDER []byte) ([]byte, error) {
	name := HashOIDName(algo)
	if name == "" {
		if len(algo) > 0 {
			return nil, fmt.Errorf("keyhash: unsupported hashAlgo %v (requires external dependency)", algo)
		}
		name = "sha256"
	}
	var sum []byte
	switch name {
	case "sha256":
		h := sha256.Sum256(spkiDER)
		sum = h[:]
	case "sha384":
		h := sha512.Sum384(spkiDER)
		sum = h[:]
	case "sha512":
		h := sha512.Sum512(spkiDER)
		sum = h[:]
	case "sha3-256":
		h := sha3.Sum256(spkiDER)
		sum = h[:]
	case "sha3-384":
		h := sha3.Sum384(spkiDER)
		sum = h[:]
	case "sha3-512":
		h := sha3.Sum512(spkiDER)
		sum = h[:]
	default:
		return nil, fmt.Errorf("keyhash: unsupported hashAlgo %q", name)
	}
	return sum, nil
}

// KeyHashFromCertSPKI computes keyHash from a certificate's public key using the algorithm OID.
func KeyHashFromCertSPKI(algo asn1.ObjectIdentifier, cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("keyhash: nil certificate")
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keyhash: marshal public key: %w", err)
	}
	return KeyHashFromSPKI(algo, pubBytes)
}
