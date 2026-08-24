// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
)

// TestJWSRoundTrips covers every implemented algorithm (draft Section
// 4.5, aligned with the SPIFFE JWT-SVID algorithm set plus EdDSA).
func TestJWSRoundTrips(t *testing.T) {
	header := func(alg string) []byte {
		h, _ := json.Marshal(map[string]any{"alg": alg, "typ": TypDA, "kid": "k-1"})
		return h
	}
	payload, _ := json.Marshal(map[string]any{"ver": 1, "agent_id": "agent:x"})

	t.Run("ES256", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tok, err := SignCompact(header("ES256"), payload, "ES256", key)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCompact(tok, "ES256", &key.PublicKey); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("RS256", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tok, err := SignCompact(header("RS256"), payload, "RS256", key)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCompact(tok, "RS256", &key.PublicKey); err != nil {
			t.Fatal(err)
		}
	})

	for _, alg := range []string{"PS256", "PS384", "PS512"} {
		t.Run(alg, func(t *testing.T) {
			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			tok, err := SignCompact(header(alg), payload, alg, key)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyCompact(tok, alg, &key.PublicKey); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("EdDSA", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := SignCompact(header("EdDSA"), payload, "EdDSA", priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCompact(tok, "EdDSA", priv.Public()); err != nil {
			t.Fatal(err)
		}
	})
}

// TestJWSAlgConfusion ensures per-alg hash binding cannot be crossed.
func TestJWSAlgConfusion(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	h, _ := json.Marshal(map[string]any{"alg": "PS384", "typ": TypDA, "kid": "k"})
	p, _ := json.Marshal(map[string]any{"ver": 1})
	tok, err := SignCompact(h, p, "PS384", key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCompact(tok, "PS256", &key.PublicKey); err == nil {
		t.Fatal("PS384 token must not verify as PS256")
	}
}

// TestJWSAllowlistRejects verifies that disallowed algorithms are
// refused before any crypto operation.
func TestJWSAllowlistRejects(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, alg := range []string{"none", "HS256", "RS1", "ES256K"} {
		if AllowedAlgs[alg] {
			t.Fatalf("algorithm %q must not be in the allowlist", alg)
		}
		h, _ := json.Marshal(map[string]any{"alg": alg, "typ": TypDA, "kid": "k"})
		p, _ := json.Marshal(map[string]any{})
		if _, err := SignCompact(h, p, alg, key); err == nil {
			t.Fatalf("signing with %q must fail", alg)
		}
	}
}
