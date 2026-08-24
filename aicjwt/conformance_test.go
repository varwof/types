// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// ---- unit: glob matching (draft Section 6.2) -----------------------

func TestUnitMatchPattern(t *testing.T) {
	cases := []struct {
		pattern, target string
		wantMatch       bool
		wantScore       int
	}{
		{"http:GET:/api/v1/users", "http:GET:/api/v1/users", true, 6},
		{"http:GET:/api/v1/users", "http:GET:/api/v1/orders", false, 0},
		{"http:GET:/api/v1/*", "http:GET:/api/v1/users", true, 5},
		{"http:GET:/api/v1/*", "http:GET:/api/v1/users/42", false, 0},
		{"http:GET:/api/v1/**", "http:GET:/api/v1/users/42", true, 4},
		{"http:*:/api/v1/*", "http:POST:/api/v1/users", true, 5},
		{"http:*", "http:GET:/api/v1/users", true, 1},
		{"http:*", "https:GET:/api", false, 0},
		{"database:query:*", "database:query:SELECT", true, 5},
		{"database:query:*", "database:admin:reset", false, 0},
		// 07-capability extensions: alternation and char class.
		{"http:{GET,POST}", "http:POST", true, 3},
		{"http:{GET,POST}", "http:DELETE", false, 0},
		{"http:[A-Z]", "http:G", true, 2},
		{"http:[A-Z]", "http:g", false, 0},
		{"http:user*", "http:username", true, 5},
		{"http:[A-Z]*:/api/*", "http:GET:/api/users", true, 5},
		{"http:{GET,POST}:/api/v1/*", "http:POST:/api/v1/users", true, 5},
	}
	for _, c := range cases {
		gotMatch, gotScore := matchPattern(c.pattern, c.target)
		if gotMatch != c.wantMatch || gotScore != c.wantScore {
			t.Errorf("matchPattern(%q,%q) = (%v,%d), want (%v,%d)",
				c.pattern, c.target, gotMatch, gotScore, c.wantMatch, c.wantScore)
		}
	}
	allowed := []Capability{
		{Scheme: "database", ID: "query:*"},
		{Scheme: "database", ID: "query:SELECT"},
	}
	if !MatchCapabilities(allowed, Capability{Scheme: "database", ID: "query:SELECT"}) {
		t.Fatalf("exact capability should match")
	}
	if !MatchCapabilities(allowed, Capability{Scheme: "database", ID: "query:EXPLAIN"}) {
		t.Fatalf("wildcard should match EXPLAIN")
	}
}

// ---- unit: parameter intersection (draft Section 6.3) ---------------

func TestUnitParamsWithinGrant(t *testing.T) {
	within, err := ParamsWithinGrant(
		json.RawMessage(`{"max_rows":1000}`),
		json.RawMessage(`{"max_rows":100}`))
	if err != nil || !within {
		t.Fatalf("agent param within grant should pass: within=%v err=%v", within, err)
	}
	within, err = ParamsWithinGrant(
		json.RawMessage(`{"max_rows":1000}`),
		json.RawMessage(`{"max_rows":5000}`))
	if err != nil || within {
		t.Fatalf("agent param exceeding grant should fail: within=%v err=%v", within, err)
	}
	within, err = ParamsWithinGrant(
		json.RawMessage(`{"regions":["cn","eu"]}`),
		json.RawMessage(`{"regions":["cn"]}`))
	if err != nil || !within {
		t.Fatalf("subset array should pass")
	}
}

// ---- unit: constraints (draft Section 7) ----------------------------

func TestUnitConstraints(t *testing.T) {
	now := time.Now().UTC()
	ctx := RequestContext{Now: now, SourceIP: netip.MustParseAddr("10.1.2.3"), ConcurrentCount: 1}
	cs := []Capability{
		{Scheme: ConstraintScheme, ID: "allowed-cidr", Params: json.RawMessage(`["10.0.0.0/8"]`)},
		{Scheme: ConstraintScheme, ID: "time-window", Params: json.RawMessage(`{"start":"00:00","end":"23:59"}`)},
		{Scheme: ConstraintScheme, ID: "max-concurrent", Params: json.RawMessage(`{"max":5}`)},
	}
	if _, err := EvaluateConstraints(cs, ctx, false); err != nil {
		t.Fatalf("valid constraints should pass: %v", err)
	}
	cs2 := append([]Capability{{Scheme: ConstraintScheme, ID: "future-type", Params: json.RawMessage(`{}`)}}, cs...)
	notes, err := EvaluateConstraints(cs2, ctx, false)
	if err != nil {
		t.Fatalf("unknown constraint should be ignored by default: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("expected one audit note, got %d", len(notes))
	}
	if _, err := EvaluateConstraints(cs2, ctx, true); err == nil {
		t.Fatalf("strict mode should reject unknown constraint")
	}
	cs3 := []Capability{{Scheme: "evil", ID: "allowed-cidr", Params: json.RawMessage(`["10.0.0.0/8"]`)}}
	if _, err := EvaluateConstraints(cs3, ctx, false); err == nil {
		t.Fatalf("non-varwof constraint scheme must be rejected")
	}
}

// ---- unit: key binding (draft Section 9.2) --------------------------

func TestUnitKeyHash(t *testing.T) {
	env := newTestEnv(t)
	h, err := KeyHashOf(&env.principalKey.PublicKey, "sha-256")
	if err != nil || len(h) != 43 {
		t.Fatalf("bad sha-256 binding: %q err=%v", h, err)
	}
	j, err := KeyHashOf(&env.agentKey.PublicKey, "jkt")
	if err != nil || len(j) != 43 {
		t.Fatalf("bad jkt binding: %q err=%v", j, err)
	}
	certHash, err := SPKIHash(env.principalCert, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	if certHash != h {
		t.Fatalf("cert SPKI hash %q != pub SPKI hash %q", certHash, h)
	}
}

// ---- negative pipeline tests (draft Section 11) ---------------------

func TestValidateNegatives(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}

	freshOpts := func() VerifyOptions {
		o := defaultOpts(env)
		o.NonceStore = NewMemNonceStore()
		return o
	}

	t.Run("tampered_payload", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		baseTok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		if _, err := Validate(baseTok, freshOpts()); err != nil {
			t.Fatalf("baseline should pass: %v", err)
		}
		_, pb, _, err := ParseCompact(baseTok)
		if err != nil {
			t.Fatal(err)
		}
		var o map[string]any
		if err := json.Unmarshal(pb, &o); err != nil {
			t.Fatal(err)
		}
		o["sub"] = "agent:evil"
		mod, _ := json.Marshal(o)
		parts := strings.Split(baseTok, ".")
		tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(mod) + "." + parts[2]
		if _, err := Validate(tampered, freshOpts()); err == nil {
			t.Fatalf("tampered token must fail")
		}
	})

	t.Run("expired", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, func(o *OuterClaims) {
			o.Exp = env.now.Add(-time.Minute).Unix()
		})
		if _, err := Validate(tok, freshOpts()); err == nil {
			t.Fatalf("expired token must fail")
		}
	})

	t.Run("lifetime_exceeds_requested", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, func(o *OuterClaims) {
			o.Exp = o.Iat + 2*3600
		})
		if _, err := Validate(tok, freshOpts()); err == nil {
			t.Fatalf("lifetime > requested_lifetime must fail")
		}
	})

	t.Run("alg_none", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		baseTok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		_, pb, _, _ := ParseCompact(baseTok)
		hb, _ := json.Marshal(map[string]any{"alg": "none", "typ": TypOuter, "kid": "issuer-1"})
		crafted := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb) + "."
		if _, err := Validate(crafted, freshOpts()); err == nil {
			t.Fatalf("alg=none must fail")
		}
	})

	t.Run("alg_confusion_hs256", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		baseTok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		_, pb, _, _ := ParseCompact(baseTok)
		hb, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": TypOuter, "kid": "issuer-1"})
		crafted := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb) + ".c2ln"
		if _, err := Validate(crafted, freshOpts()); err == nil {
			t.Fatalf("HS256 must fail the allowlist")
		}
	})

	t.Run("da_key_hash_mismatch", func(t *testing.T) {
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		badTok, badDa := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			h, _ := KeyHashOf(&otherKey.PublicKey, "sha-256")
			d.Principal.KeyHash = h
		})
		tok, _ := buildOuter(t, env, badTok, badDa, ModeAuthorized, caps, nil)
		if _, err := Validate(tok, freshOpts()); err == nil {
			t.Fatalf("key_hash mismatch must fail")
		}
	})

	t.Run("nonce_reuse", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		opts := freshOpts()
		if _, err := Validate(tok, opts); err != nil {
			t.Fatalf("first validation should pass: %v", err)
		}
		if _, err := Validate(tok, opts); err == nil {
			t.Fatalf("DA nonce reuse must fail")
		}
	})

	t.Run("inconsistent_capabilities", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized,
			[]Capability{{Scheme: "database", ID: "admin:reset"}}, nil)
		if _, err := Validate(tok, freshOpts()); err == nil {
			t.Fatalf("DA/outer capability mismatch must fail")
		}
	})

	t.Run("unknown_scheme_fail_closed", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		opts := freshOpts()
		opts.RequestCapability = &Capability{Scheme: "mystery", ID: "do:thing"}
		if _, err := Validate(tok, opts); err == nil {
			t.Fatalf("unknown scheme must fail closed")
		}
	})

	t.Run("representative_without_pa", func(t *testing.T) {
		repTok, repDa := buildDA(t, env, ModeRepresentative, caps, nil)
		tok, _ := buildOuter(t, env, repTok, repDa, ModeRepresentative, caps, nil)
		opts := freshOpts()
		opts.PA = nil
		if _, err := Validate(tok, opts); err == nil {
			t.Fatalf("representative without PA must fail")
		}
	})

	t.Run("missing_cnf", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, func(o *OuterClaims) {
			o.Cnf = nil
		})
		if _, err := Validate(tok, freshOpts()); err == nil {
			t.Fatalf("missing cnf must fail")
		}
	})

	t.Run("malformed_token", func(t *testing.T) {
		if _, err := Validate("not-a-jws", freshOpts()); err == nil {
			t.Fatalf("malformed token must fail")
		}
	})
}
