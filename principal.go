package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"strings"
)

// PrincipalUid is the structured ASN.1 principal identity (spec §PrincipalUid).
// hashAlgo is [0] EXPLICIT AlgorithmIdentifier OPTIONAL; omitted defaults to SHA-256.
type PrincipalUid struct {
	Version    int                 `asn1:"default:1"`
	Realm      string              `asn1:"utf8"`
	Identifier string              `asn1:"utf8"`
	KeyHash    []byte              `asn1:"octet"`
	HashAlgo   AlgorithmIdentifier `asn1:"optional,omitempty,explicit,tag:0"`
}

// HashAlgoOID returns the effective hash algorithm OID (nil/empty defaults to SHA-256).
func (pu PrincipalUid) HashAlgoOID() asn1.ObjectIdentifier {
	if len(pu.HashAlgo.Algorithm) == 0 {
		return OIDSHA256
	}
	return pu.HashAlgo.Algorithm
}

// String returns the communication format {realm}:{identifier}:{keyFingerprint}.
func (pu PrincipalUid) String() string {
	fp := base64.RawURLEncoding.EncodeToString(pu.KeyHash)
	return pu.Realm + ":" + pu.Identifier + ":" + fp
}

// ParsePrincipalUid parses a PrincipalUid from communication format string.
func ParsePrincipalUid(s string) (PrincipalUid, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		return PrincipalUid{}, fmt.Errorf("principal_uid: invalid format, expected {realm}:{identifier}:{keyFingerprint}")
	}
	if len(parts[0]) < 1 || len(parts[0]) > 128 {
		return PrincipalUid{}, fmt.Errorf("principal_uid: realm length %d: must be 1-128", len(parts[0]))
	}
	if len(parts[1]) < 1 || len(parts[1]) > 256 {
		return PrincipalUid{}, fmt.Errorf("principal_uid: identifier length %d: must be 1-256", len(parts[1]))
	}
	keyHash, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return PrincipalUid{}, fmt.Errorf("principal_uid: invalid keyFingerprint base64url: %w", err)
	}
	if len(keyHash) < 1 || len(keyHash) > 64 {
		return PrincipalUid{}, fmt.Errorf("principal_uid: keyHash length %d: must be 1-64", len(keyHash))
	}
	if strings.Contains(parts[0], ":") || strings.Contains(parts[1], ":") {
		return PrincipalUid{}, fmt.Errorf("principal_uid: realm and identifier must not contain ':'")
	}
	return PrincipalUid{
		Version:    1,
		Realm:      parts[0],
		Identifier: parts[1],
		KeyHash:    keyHash,
		HashAlgo:   AlgorithmIdentifier{Algorithm: OIDSHA256},
	}, nil
}

// MakePrincipalUidFromCert constructs a PrincipalUid from a certificate (KeyHash = SPKI SHA-256).
// Returns a PrincipalUid with empty KeyHash when certificate or key encoding fails (preserves old signature compatibility).
func MakePrincipalUidFromCert(realm, identifier string, cert *x509.Certificate) PrincipalUid {
	uid, _ := MakePrincipalUidFromCertWithAlgo(realm, identifier, cert, nil)
	return uid
}

// MakePrincipalUidFromCertWithAlgo constructs a PrincipalUid from a certificate, computing
// SPKI keyHash using the specified hash algorithm OID. When algo is nil/empty, defaults to SHA-256;
// unsupported algorithms (BLAKE2/BLAKE3) return an error (no silent degradation).
// SM3 is provided by pki-types built-in pure Go implementation (C1).
func MakePrincipalUidFromCertWithAlgo(realm, identifier string, cert *x509.Certificate, algo asn1.ObjectIdentifier) (PrincipalUid, error) {
	if cert == nil {
		return PrincipalUid{}, fmt.Errorf("principal_uid: nil certificate")
	}
	oid := algo
	if len(oid) == 0 {
		oid = OIDSHA256
	}
	h, err := KeyHashFromCertSPKI(oid, cert)
	if err != nil {
		return PrincipalUid{}, err
	}
	return PrincipalUid{
		Version:    1,
		Realm:      realm,
		Identifier: identifier,
		KeyHash:    h,
		HashAlgo:   AlgorithmIdentifier{Algorithm: oid},
	}, nil
}
