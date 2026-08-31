// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package aicjwt

// X.509 certificate → JWK / JWKS interop. AIC-JWT lives in OAuth/JOSE land
// but must interoperate with the X.509 AIC profile where the same CA keys are
// carried as certificates: verifying an AIC-JWT issued by a CA requires
// turning that CA's certificate into a JWK the same way Verifiers and
// Authorization Servers publish JWKS document.
//
// kid convention: base64url(SHA-256 of the certificate's
// SubjectPublicKeyInfo), matching the draft's key_hash semantics so a JWKS
// key can be traced to the exact certificate the X.509 chain is rooted at.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// CertToJWK converts an X.509 certificate into a JWK carrying the CF identity
// binding: kid = SPKI hash, x5c = the certificate, x5t = SHA-256 thumbprint.
func CertToJWK(cert *x509.Certificate) (JWK, error) {
	if cert == nil {
		return JWK{}, fmt.Errorf("cert = nil for CertToJWK")
	}
	if cert.PublicKey == nil {
		return JWK{}, fmt.Errorf("cert public key is nil")
	}
	base, err := PublicKeyToJWK(cert.PublicKey)
	if err != nil {
		return JWK{}, fmt.Errorf("PublicKeyToJWK: %w", err)
	}
	kid, err := SPKIHash(cert, "sha-256")
	if err != nil {
		return JWK{}, fmt.Errorf("SPKIHash: %w", err)
	}
	j := base
	j.Kid = kid
	j.Use = "sig"
	if len(cert.Raw) > 0 {
		j.X5c = []string{base64.StdEncoding.EncodeToString(cert.Raw)}
		der := sha256.Sum256(cert.Raw)
		j.X5t = base64.RawURLEncoding.EncodeToString(der[:])
	}
	return j, nil
}

// JWKS is a JWK Key Set (RFC 7517 §5).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// BuildJWKS builds a JWKS from certificates; keys are deduplicated by kid.
func BuildJWKS(certs []*x509.Certificate) (JWKS, error) {
	if len(certs) == 0 {
		return JWKS{Keys: []JWK{}}, nil
	}
	keys := make([]JWK, 0, len(certs))
	seen := make(map[string]struct{}, len(certs))
	for _, c := range certs {
		if c == nil {
			continue
		}
		j, err := CertToJWK(c)
		if err != nil {
			return JWKS{}, fmt.Errorf("CertToJWK: %w", err)
		}
		if _, dup := seen[j.Kid]; dup {
			continue
		}
		seen[j.Kid] = struct{}{}
		keys = append(keys, j)
	}
	return JWKS{Keys: keys}, nil
}

// BuildJWKSJSON returns the marshaled JWKS for a certificate set.
func BuildJWKSJSON(certs []*x509.Certificate) ([]byte, error) {
	ks, err := BuildJWKS(certs)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(&ks)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// AlgForPublicKey derives the JOSE algorithm implied by a public key.
func AlgForPublicKey(pub any) (string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "ES256", nil
		case elliptic.P384():
			return "ES384", nil
		case elliptic.P521():
			return "ES512", nil
		}
		return "", fmt.Errorf("unsupported EC curve")
	case *rsa.PublicKey:
		if k.Size() >= 3072 {
			return "PS256", nil
		}
		return "RS256", nil
	case ed25519.PublicKey:
		return "EdDSA", nil
	default:
		return "", fmt.Errorf("unsupported public key type %T", pub)
	}
}