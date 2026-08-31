package aicjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	pki "github.com/varwof/types"
	"math/big"
	"strings"
)

// JWK is an RFC 7517 public JWK supporting EC, RSA and OKP (kty/crv/x/y/n/e),
// plus the key-set metadata members kid/use/x5c/x5t used to bind a JWK to an
// X.509 certificate chain (draft Section 5).
type JWK struct {
	Kty string   `json:"kty"`
	Crv string   `json:"crv,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	Kid string   `json:"kid,omitempty"`
	Use string   `json:"use,omitempty"`
	X5c []string `json:"x5c,omitempty"`
	X5t string   `json:"x5t,omitempty"`
}

// SupportedHashAlgs lists the hash_alg values implemented here.
// sha3-* and sm3 require golang.org/x/crypto and are intentionally not
// implemented in this stdlib-only reference implementation.
var SupportedHashAlgs = map[string]int{
	"sha-256": 32,
	"sha-384": 48,
	"sha-512": 64,
	"jkt":     32,
}

// SPKIHash computes hash_alg(SPKI) for an X.509 certificate (draft
// Section 9.2).
func SPKIHash(cert *x509.Certificate, hashAlg string) (string, error) {
	return hashBytes(cert.RawSubjectPublicKeyInfo, hashAlg)
}

// SPKIHashPub computes hash_alg(SPKI) directly from a public key using
// x509.MarshalPKIXPublicKey.
func SPKIHashPub(pub crypto.PublicKey, hashAlg string) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return hashBytes(der, hashAlg)
}

func hashBytes(b []byte, hashAlg string) (string, error) {
	switch hashAlg {
	case "sha-256", "sha-384", "sha-512":
		// Delegate to the canonical github.com/varwof/types hash layer
		// (single source of truth for SPKI digest computation).
		oid, err := pki.ParseHashAlgo(strings.ReplaceAll(hashAlg, "-", ""))
		if err != nil {
			return "", err
		}
		h, err := pki.KeyHashFromSPKI(oid, b)
		if err != nil {
			return "", err
		}
		return b64uEncode(h), nil
	default:
		return "", fmt.Errorf("unsupported SPKI hash algorithm %q", hashAlg)
	}
}

// JWKThumbprint implements RFC 7638 for EC, RSA and OKP keys.
func JWKThumbprint(j JWK) (string, error) {
	var canon string
	switch j.Kty {
	case "EC":
		canon = `{"crv":"` + j.Crv + `","kty":"EC","x":"` + j.X + `","y":"` + j.Y + `"}`
	case "RSA":
		canon = `{"e":"` + j.E + `","kty":"RSA","n":"` + j.N + `"}`
	case "OKP":
		canon = `{"crv":"` + j.Crv + `","kty":"OKP","x":"` + j.X + `"}`
	default:
		return "", fmt.Errorf("unsupported kty %q", j.Kty)
	}
	d := sha256.Sum256([]byte(canon))
	return b64uEncode(d[:]), nil
}

// PublicKeyToJWK converts a public key to a minimal JWK.
func PublicKeyToJWK(pub crypto.PublicKey) (JWK, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		var crv string
		switch k.Curve {
		case elliptic.P256():
			crv = "P-256"
		case elliptic.P384():
			crv = "P-384"
		case elliptic.P521():
			crv = "P-521"
		default:
			return JWK{}, fmt.Errorf("unsupported curve")
		}
		xb := make([]byte, size)
		yb := make([]byte, size)
		k.X.FillBytes(xb)
		k.Y.FillBytes(yb)
		return JWK{Kty: "EC", Crv: crv, X: b64uEncode(xb), Y: b64uEncode(yb)}, nil
	case *rsa.PublicKey:
		return JWK{Kty: "RSA", N: b64uEncode(k.N.Bytes()), E: b64uEncode(big.NewInt(int64(k.E)).Bytes())}, nil
	case ed25519.PublicKey:
		return JWK{Kty: "OKP", Crv: "Ed25519", X: b64uEncode(k)}, nil
	}
	return JWK{}, fmt.Errorf("unsupported public key type %T", pub)
}

// JWKToPublic converts a minimal JWK back to a public key.
func JWKToPublic(j JWK) (crypto.PublicKey, error) {
	switch j.Kty {
	case "EC":
		curves := map[string]elliptic.Curve{
			"P-256": elliptic.P256(),
			"P-384": elliptic.P384(),
			"P-521": elliptic.P521(),
		}
		curve, ok := curves[j.Crv]
		if !ok {
			return nil, fmt.Errorf("unsupported curve %q", j.Crv)
		}
		xb, err := b64uDecode(j.X)
		if err != nil {
			return nil, err
		}
		yb, err := b64uDecode(j.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
	case "RSA":
		nb, err := b64uDecode(j.N)
		if err != nil {
			return nil, err
		}
		eb, err := b64uDecode(j.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}, nil
	case "OKP":
		xb, err := b64uDecode(j.X)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(xb), nil
	}
	return nil, fmt.Errorf("unsupported kty %q", j.Kty)
}

// KeyHashOf computes the binding of a public key for the given
// hash_alg: "jkt" uses the RFC 7638 JWK thumbprint, otherwise the SPKI
// hash is used.
func KeyHashOf(pub crypto.PublicKey, hashAlg string) (string, error) {
	if hashAlg == "jkt" {
		j, err := PublicKeyToJWK(pub)
		if err != nil {
			return "", err
		}
		return JWKThumbprint(j)
	}
	if hashAlg == "" {
		hashAlg = "sha-256"
	}
	return SPKIHashPub(pub, hashAlg)
}

// PrincipalKeyMaterial is the optional credential bundle (draft
// Section 9).  Either X5C (PKI mode) or JWK (pure-JSON mode) is used.
type PrincipalKeyMaterial struct {
	X5C []*x509.Certificate
	JWK map[string]JWK
}

// LookupByBinding finds a principal key whose binding matches the
// principal claim.
func (m *PrincipalKeyMaterial) LookupByBinding(p Principal) (crypto.PublicKey, error) {
	switch p.HashAlg {
	case "jkt":
		for _, j := range m.JWK {
			thumb, err := JWKThumbprint(j)
			if err != nil {
				continue
			}
			if thumb == p.KeyHash {
				return JWKToPublic(j)
			}
		}
		return nil, fmt.Errorf("no JWK matches key_hash %s", p.KeyHash)
	default:
		alg := p.HashAlg
		if alg == "" {
			alg = "sha-256"
		}
		for _, cert := range m.X5C {
			h, err := SPKIHash(cert, alg)
			if err != nil {
				continue
			}
			if h == p.KeyHash {
				return cert.PublicKey, nil
			}
		}
		return nil, fmt.Errorf("no certificate matches key_hash %s", p.KeyHash)
	}
}

// ParseJWK decodes a JWK JSON object.
func ParseJWK(b []byte) (JWK, error) {
	var j JWK
	if err := json.Unmarshal(b, &j); err != nil {
		return JWK{}, err
	}
	return j, nil
}
