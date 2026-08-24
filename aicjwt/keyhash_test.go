package aicjwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"testing"
)

// TestJWKRoundTripEC exercises PublicKeyToJWK / JWKToPublic / ParseJWK /
// JWKThumbprint for the EC family.
func TestJWKRoundTripEC(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		j, err := PublicKeyToJWK(&key.PublicKey)
		if err != nil {
			t.Fatalf("PublicKeyToJWK: %v", err)
		}
		if j.Kty != "EC" {
			t.Fatalf("kty = %q, want EC", j.Kty)
		}
		// JSON round trip through ParseJWK.
		b, err := json.Marshal(j)
		if err != nil {
			t.Fatal(err)
		}
		j2, err := ParseJWK(b)
		if err != nil {
			t.Fatalf("ParseJWK: %v", err)
		}
		pub, err := JWKToPublic(j2)
		if err != nil {
			t.Fatalf("JWKToPublic: %v", err)
		}
		ec := pub.(*ecdsa.PublicKey)
		if !ec.Equal(&key.PublicKey) {
			t.Fatalf("round trip mismatch for %s", curve.Params().Name)
		}
		if _, err := JWKThumbprint(j); err != nil {
			t.Fatalf("JWKThumbprint: %v", err)
		}
	}
}

// TestJWKRoundTripRSA exercises RSA public-key JWK conversion.
func TestJWKRoundTripRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	j, err := PublicKeyToJWK(&key.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToJWK: %v", err)
	}
	if j.Kty != "RSA" {
		t.Fatalf("kty = %q, want RSA", j.Kty)
	}
	pub, err := JWKToPublic(j)
	if err != nil {
		t.Fatalf("JWKToPublic: %v", err)
	}
	r := pub.(*rsa.PublicKey)
	if !r.Equal(&key.PublicKey) {
		t.Fatal("RSA round trip mismatch")
	}
	if _, err := JWKThumbprint(j); err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}
}

// TestJWKRoundTripEd25519 exercises OKP JWK conversion.
func TestJWKRoundTripEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j, err := PublicKeyToJWK(pub)
	if err != nil {
		t.Fatalf("PublicKeyToJWK: %v", err)
	}
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		t.Fatalf("got kty=%q crv=%q, want OKP/Ed25519", j.Kty, j.Crv)
	}
	pub2, err := JWKToPublic(j)
	if err != nil {
		t.Fatalf("JWKToPublic: %v", err)
	}
	if !ed25519.PublicKey(pub2.(ed25519.PublicKey)).Equal(pub) {
		t.Fatal("Ed25519 round trip mismatch")
	}
	if _, err := JWKThumbprint(j); err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}
}

// TestJWKUnsupported verifies error paths for unsupported types/kty.
func TestJWKUnsupported(t *testing.T) {
	if _, err := PublicKeyToJWK(struct{}{}); err == nil {
		t.Error("expected error for unsupported key type")
	}
	if _, err := JWKToPublic(JWK{Kty: "unsupported"}); err == nil {
		t.Error("expected error for unsupported kty")
	}
	if _, err := JWKThumbprint(JWK{Kty: "unsupported"}); err == nil {
		t.Error("expected error for unsupported thumbprint kty")
	}
	if _, err := ParseJWK([]byte("not json")); err == nil {
		t.Error("expected error for invalid JWK JSON")
	}
	if _, err := SPKIHashPub(nil, "sha-256"); err == nil {
		t.Error("expected error for nil public key")
	}
}

// TestSPKIHashPubMatchesCert ensures SPKIHashPub agrees with SPKIHash(cert).
func TestSPKIHashPubMatchesCert(t *testing.T) {
	env := newTestEnv(t)
	fromCert, err := SPKIHash(env.principalCert, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	fromPub, err := SPKIHashPub(&env.principalKey.PublicKey, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	if fromCert != fromPub {
		t.Fatalf("SPKIHash(cert) %q != SPKIHashPub(pub) %q", fromCert, fromPub)
	}
}

// TestLookupByBinding covers both JWK (jkt) and X5C binding lookup paths.
func TestLookupByBinding(t *testing.T) {
	env := newTestEnv(t)

	t.Run("jkt match", func(t *testing.T) {
		jwk, err := PublicKeyToJWK(&env.principalKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		m := &PrincipalKeyMaterial{JWK: map[string]JWK{"principal-1": jwk}}
		binding := principalBinding(t, env.principalKey)
		binding.HashAlg = "jkt"
		binding.KeyHash, _ = KeyHashOf(&env.principalKey.PublicKey, "jkt")
		pub, err := m.LookupByBinding(binding)
		if err != nil {
			t.Fatalf("LookupByBinding jkt: %v", err)
		}
		if !pub.(*ecdsa.PublicKey).Equal(&env.principalKey.PublicKey) {
			t.Fatal("jkt lookup returned wrong key")
		}
	})

	t.Run("jkt no match", func(t *testing.T) {
		m := &PrincipalKeyMaterial{JWK: map[string]JWK{}}
		binding := Principal{HashAlg: "jkt", KeyHash: "nonexistent"}
		if _, err := m.LookupByBinding(binding); err == nil {
			t.Fatal("expected error for no JWK match")
		}
	})

	t.Run("x5c match", func(t *testing.T) {
		m := &PrincipalKeyMaterial{X5C: []*x509.Certificate{env.principalCert}}
		binding := principalBinding(t, env.principalKey)
		pub, err := m.LookupByBinding(binding)
		if err != nil {
			t.Fatalf("LookupByBinding x5c: %v", err)
		}
		if !pub.(*ecdsa.PublicKey).Equal(&env.principalKey.PublicKey) {
			t.Fatal("x5c lookup returned wrong key")
		}
	})

	t.Run("x5c no match", func(t *testing.T) {
		m := &PrincipalKeyMaterial{X5C: []*x509.Certificate{env.principalCert}}
		binding := Principal{HashAlg: "sha-256", KeyHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
		if _, err := m.LookupByBinding(binding); err == nil {
			t.Fatal("expected error for no certificate match")
		}
	})
}
