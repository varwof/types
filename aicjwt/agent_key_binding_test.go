package aicjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// TestDAVersion3AgentKeyBinding covers the da.ver=3 claim set: the
// version matrix, the agent_key_binding object, and the requirement
// that the key identified by cnf matches the binding (draft -02
// Section 5.2).
func TestDAVersion3AgentKeyBinding(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:*"}}

	bindingOf := func(t *testing.T, key *ecdsa.PrivateKey) *AgentKeyBinding {
		t.Helper()
		h, err := KeyHashOf(&key.PublicKey, "sha-256")
		if err != nil {
			t.Fatal(err)
		}
		return &AgentKeyBinding{HashAlg: "sha-256", KeyHash: h}
	}

	t.Run("ver3_requires_binding", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) { d.Ver = 3 })
		_, err := ValidateDA(tok, defaultOpts(env))
		requireErrContains(t, err, "agent_key_binding")
	})

	t.Run("ver2_rejects_binding", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.AgentKeyBinding = bindingOf(t, env.agentKey)
		})
		_, err := ValidateDA(tok, defaultOpts(env))
		requireErrContains(t, err, "must be 3 to carry agent_key_binding")
	})

	t.Run("ver1_rejected", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) { d.Ver = 1 })
		_, err := ValidateDA(tok, defaultOpts(env))
		requireErrContains(t, err, "DA ver")
	})

	t.Run("unknown_version_rejected", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.Ver = 4
			d.AgentKeyBinding = bindingOf(t, env.agentKey)
		})
		_, err := ValidateDA(tok, defaultOpts(env))
		requireErrContains(t, err, "DA ver")
	})

	t.Run("unsupported_hash_alg", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.Ver = 3
			b := bindingOf(t, env.agentKey)
			b.HashAlg = "sm3" // not implemented by this stdlib-only reference
			d.AgentKeyBinding = b
		})
		_, err := ValidateDA(tok, defaultOpts(env))
		requireErrContains(t, err, "unsupported")
	})

	t.Run("jkt_is_not_a_binding_algorithm", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.Ver = 3
			b := bindingOf(t, env.agentKey)
			b.HashAlg = "jkt"
			d.AgentKeyBinding = b
		})
		_, err := ValidateDA(tok, defaultOpts(env))
		requireErrContains(t, err, "unsupported")
	})

	t.Run("key_hash_length_must_match_algorithm", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.Ver = 3
			d.AgentKeyBinding = &AgentKeyBinding{
				HashAlg: "sha-256",
				KeyHash: b64uEncode(make([]byte, 16)),
			}
		})
		_, err := ValidateDA(tok, defaultOpts(env))
		requireErrContains(t, err, "length")
	})

	t.Run("key_hash_must_be_base64url", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.Ver = 3
			d.AgentKeyBinding = &AgentKeyBinding{HashAlg: "sha-256", KeyHash: "not base64url!"}
		})
		_, err := ValidateDA(tok, defaultOpts(env))
		requireErrContains(t, err, "agent_key_binding")
	})

	t.Run("pipeline_binding_matches_presenter_key", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.Ver = 3
			d.AgentKeyBinding = bindingOf(t, env.agentKey)
		})
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		opts := defaultOpts(env)
		opts.PresenterKey = &env.agentKey.PublicKey
		dec, err := Validate(tok, opts)
		if err != nil {
			t.Fatalf("ver=3 with a matching binding should pass: %v", err)
		}
		if !dec.Permit {
			t.Fatalf("expected permit")
		}
	})

	t.Run("pipeline_binding_mismatch_is_rejected", func(t *testing.T) {
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		daTok, da := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.Ver = 3
			d.AgentKeyBinding = bindingOf(t, otherKey)
		})
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		opts := defaultOpts(env)
		opts.PresenterKey = &env.agentKey.PublicKey
		_, err = Validate(tok, opts)
		requireErrContains(t, err, "does not match the presenter key")
	})

	t.Run("pipeline_without_presenter_key_skips_the_cross_check", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.Ver = 3
			d.AgentKeyBinding = bindingOf(t, env.agentKey)
		})
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		if _, err := Validate(tok, defaultOpts(env)); err != nil {
			t.Fatalf("without a presenter key the binding cannot be cross-checked: %v", err)
		}
	})
}
