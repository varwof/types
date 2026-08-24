// Package aicjson is a reference implementation and conformance
// test target for draft-wei-aic-jwt-00 (AIC-JWT: JSON Web Token
// Profile for AI Agent Identity Certificates).
package aicjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// AllowedAlgs is the full JOSE algorithm allowlist from draft Section
// 4.5.  ES384, ES512, RS384 and RS512 are MAY-level algorithms: a
// conforming implementation MAY reject them, and this reference
// implementation does.
var AllowedAlgs = map[string]bool{
	"ES256": true,
	"ES384": true,
	"ES512": true,
	"RS256": true,
	"RS384": true,
	"RS512": true,
	"PS256": true,
	"PS384": true,
	"PS512": true,
	"EdDSA": true,
}

// ImplementedAlgs are the algorithms actually implemented here.
var ImplementedAlgs = map[string]bool{
	"ES256": true,
	"RS256": true,
	"PS256": true,
	"PS384": true,
	"PS512": true,
	"EdDSA": true,
}

var errMalformedJWS = errors.New("malformed JWS compact serialization")

func b64uEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64uDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// SignCompact creates a JWS compact serialization. header and payload
// are raw JSON bytes; the protected header MUST contain alg and typ.
func SignCompact(header, payload []byte, alg string, key crypto.Signer) (string, error) {
	if !AllowedAlgs[alg] {
		return "", fmt.Errorf("algorithm %q not in AIC-JWT allowlist", alg)
	}
	if !ImplementedAlgs[alg] {
		return "", fmt.Errorf("algorithm %q recognized but not implemented", alg)
	}
	eh := b64uEncode(header)
	ep := b64uEncode(payload)
	signingInput := eh + "." + ep
	sig, err := signBytes(alg, []byte(signingInput), key)
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64uEncode(sig), nil
}

// ParseCompact splits a JWS compact serialization into header, payload
// and signature bytes.
func ParseCompact(token string) ([]byte, []byte, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, errMalformedJWS
	}
	h, err := b64uDecode(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bad header base64url: %w", err)
	}
	p, err := b64uDecode(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bad payload base64url: %w", err)
	}
	s, err := b64uDecode(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bad signature base64url: %w", err)
	}
	return h, p, s, nil
}

// VerifyCompact verifies the JWS signature for alg over the compact
// token.
func VerifyCompact(token, alg string, pub crypto.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errMalformedJWS
	}
	sig, err := b64uDecode(parts[2])
	if err != nil {
		return err
	}
	return verifyBytes(alg, []byte(parts[0]+"."+parts[1]), sig, pub)
}

func signBytes(alg string, input []byte, key crypto.Signer) ([]byte, error) {
	switch alg {
	case "ES256":
		return signES(input, key, elliptic.P256(), crypto.SHA256)
	case "RS256":
		return signRSAPKCS1(input, key, crypto.SHA256)
	case "PS256":
		return signRSAPSS(input, key, crypto.SHA256)
	case "PS384":
		return signRSAPSS(input, key, crypto.SHA384)
	case "PS512":
		return signRSAPSS(input, key, crypto.SHA512)
	case "EdDSA":
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("EdDSA requires ed25519.PrivateKey, got %T", key)
		}
		return ed25519.Sign(priv, input), nil
	}
	return nil, fmt.Errorf("algorithm %q not supported", alg)
}

func signES(input []byte, key crypto.Signer, curve elliptic.Curve, h crypto.Hash) ([]byte, error) {
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ES256 requires *ecdsa.PrivateKey")
	}
	if priv.Curve != curve {
		return nil, fmt.Errorf("ES256 requires a P-256 key")
	}
	digest := hashDigest(h, input)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return nil, err
	}
	size := (curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])
	return out, nil
}

func signRSAPKCS1(input []byte, key crypto.Signer, h crypto.Hash) ([]byte, error) {
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RS256 requires *rsa.PrivateKey")
	}
	digest := hashDigest(h, input)
	return rsa.SignPKCS1v15(rand.Reader, priv, h, digest)
}

func signRSAPSS(input []byte, key crypto.Signer, h crypto.Hash) ([]byte, error) {
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PS256 requires *rsa.PrivateKey")
	}
	digest := hashDigest(h, input)
	return rsa.SignPSS(rand.Reader, priv, h, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
}

func hashDigest(h crypto.Hash, input []byte) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(input)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(input)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(input)
		return d[:]
	}
	hh := h.New()
	hh.Write(input)
	return hh.Sum(nil)
}

func verifyBytes(alg string, input, sig []byte, pub crypto.PublicKey) error {
	switch alg {
	case "ES256":
		return verifyES(input, sig, pub, elliptic.P256(), crypto.SHA256)
	case "RS256":
		return verifyRSAPKCS1(input, sig, pub, crypto.SHA256)
	case "PS256":
		return verifyRSAPSS(input, sig, pub, crypto.SHA256)
	case "PS384":
		return verifyRSAPSS(input, sig, pub, crypto.SHA384)
	case "PS512":
		return verifyRSAPSS(input, sig, pub, crypto.SHA512)
	case "EdDSA":
		pk, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("EdDSA requires ed25519.PublicKey, got %T", pub)
		}
		if !ed25519.Verify(pk, input, sig) {
			return errors.New("EdDSA signature verification failed")
		}
		return nil
	}
	return fmt.Errorf("algorithm %q not supported", alg)
}

func verifyES(input, sig []byte, pub crypto.PublicKey, curve elliptic.Curve, h crypto.Hash) error {
	pk, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("ES256 requires *ecdsa.PublicKey")
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(sig) != 2*size {
		return errors.New("ES256 signature length mismatch")
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	digest := hashDigest(h, input)
	if !ecdsa.Verify(pk, digest, r, s) {
		return errors.New("ECDSA signature verification failed")
	}
	return nil
}

func verifyRSAPKCS1(input, sig []byte, pub crypto.PublicKey, h crypto.Hash) error {
	pk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("RS256 requires *rsa.PublicKey")
	}
	digest := hashDigest(h, input)
	return rsa.VerifyPKCS1v15(pk, h, digest, sig)
}

func verifyRSAPSS(input, sig []byte, pub crypto.PublicKey, h crypto.Hash) error {
	pk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("PS256 requires *rsa.PublicKey")
	}
	digest := hashDigest(h, input)
	return rsa.VerifyPSS(pk, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
}
