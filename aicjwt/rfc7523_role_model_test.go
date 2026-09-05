// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjwt

import (
	"crypto"
	"encoding/json"
	"testing"
)

// Regression tests for the RFC 7523 role/claims model added after OAuth
// WG review of draft-wei-aic-jwt-00 (2026-09-04):
//
// Jeff Lombardo (Amazon): in OAuth the agent is the client/actor, not
// the grant subject; "the DA is issued by the principal with the agent
// as subject" puts the agent in the wrong slot (RFC 6749 has no subject
// role; RFC 8693 splits subject_token from actor_token), and the draft
// used "principal" for both the accountable operator and the resource
// owner.
//
// Iman Schrock (EMILIA): AIC-JWT Section 5.2 defined the DA payload
// (agent_id, principal, requested_lifetime, ts, nonce) without the RFC
// 7523 required claims iss/sub/aud/exp, so the Section 10.2 jwt-bearer
// presentation did not interoperate; the profile must fix the assertion
// first and then define the issued-token subject per mode
// (representative: resource owner/principal is sub, agent is
// act/client_id; authorized: agent may be sub as the authorized
// accessor, RFC 7523 Section 3 item 2A).
func TestDARFC7523RequiredClaims(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daOpts := func() VerifyOptions {
		return VerifyOptions{
			PrincipalJWKS: map[string]crypto.PublicKey{"principal-1": &env.principalKey.PublicKey},
			NonceStore:    NewMemNonceStore(),
		}
	}

	cases := []struct {
		name string
		mut  func(*DAClaims)
		want string
	}{
		{"iss missing", func(d *DAClaims) { d.Iss = "" }, "DA iss required"},
		{"sub missing", func(d *DAClaims) { d.Sub = "" }, "DA sub required"},
		{"aud missing", func(d *DAClaims) { d.Aud = nil }, "DA aud"},
		{"exp missing", func(d *DAClaims) { d.Exp = 0 }, "DA exp required"},
		{"jti missing", func(d *DAClaims) { d.Jti = "" }, "DA jti required"},
		{"jti != nonce", func(d *DAClaims) { d.Jti = "other" }, "DA jti must equal nonce"},
		{"iat != ts", func(d *DAClaims) { d.Iat = d.TS + 1 }, "DA iat must equal ts"},
		{"exp != ts+requested_lifetime", func(d *DAClaims) { d.Exp = d.TS + int64(d.RequestedLifetime) - 1 }, "must equal ts+requested_lifetime"},
		{"expired", func(d *DAClaims) {
			d.TS = env.now.Add(-2 * 3600 * 1e9).Unix()
			d.Iat = d.TS
			d.Exp = d.TS + int64(d.RequestedLifetime)
		}, "expired"},
		{"iss != principal", func(d *DAClaims) { d.Iss = "evil:other" }, "!= principal"},
		{"authorized sub must be agent", func(d *DAClaims) { d.Sub = d.Principal.SubjectID() }, "must be the agent"},
		{"representative sub must be resource owner", func(d *DAClaims) {
			d.DelegationMode = ModeRepresentative
			d.Sub = d.AgentID
		}, "must be the resource owner"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mode := ModeAuthorized
			if c.name == "representative sub must be resource owner" {
				mode = ModeRepresentative
			}
			tok, _ := buildDA(t, env, mode, caps, c.mut)
			_, err := ValidateDA(tok, daOpts())
			requireErrContains(t, err, c.want)
		})
	}
}

// TestModeRoleMappingEndToEnd verifies the outer-token role placement
// adopted in response to the review above: representative mode carries
// the resource owner as subject and the agent as RFC 8693 actor;
// authorized mode carries the agent as subject (RFC 7523 item 2A
// authorized accessor) with no actor claim.
func TestModeRoleMappingEndToEnd(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT", Params: json.RawMessage(`{"max_rows":100}`)}}

	t.Run("authorized: agent is subject, no act", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, outer := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		dec, err := Validate(tok, defaultOpts(env))
		if err != nil {
			t.Fatalf("authorized validate: %v", err)
		}
		if outer.Sub != da.AgentID || outer.Act != nil {
			t.Fatalf("authorized outer roles wrong: sub=%q act=%v", outer.Sub, outer.Act)
		}
		if dec.Actor != da.AgentID {
			t.Fatalf("authorized audit actor = %q, want %q", dec.Actor, da.AgentID)
		}
		if dec.Executor != da.AgentID {
			t.Fatalf("authorized executor = %q, want agent %q", dec.Executor, da.AgentID)
		}
	})

	t.Run("representative: resource owner is subject, agent is act", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeRepresentative, caps, nil)
		tok, outer := buildOuter(t, env, daTok, da, ModeRepresentative, caps, nil)
		dec, err := Validate(tok, defaultOpts(env))
		if err != nil {
			t.Fatalf("representative validate: %v", err)
		}
		if outer.Sub != da.Principal.SubjectID() {
			t.Fatalf("representative outer sub = %q, want resource owner %q", outer.Sub, da.Principal.SubjectID())
		}
		if outer.Act == nil || outer.Act.Sub != da.AgentID {
			t.Fatalf("representative outer act = %v, want agent %q", outer.Act, da.AgentID)
		}
		if dec.Actor != da.Principal.ID {
			t.Fatalf("representative audit actor = %q, want principal %q", dec.Actor, da.Principal.ID)
		}
		if dec.Executor != da.AgentID {
			t.Fatalf("representative executor = %q, want agent %q", dec.Executor, da.AgentID)
		}
	})

	t.Run("old representative shape rejected", func(t *testing.T) {
		// Pre-review tokens carried the agent as subject with no actor.
		daTok, da := buildDA(t, env, ModeRepresentative, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeRepresentative, caps, func(o *OuterClaims) {
			o.Sub = da.AgentID
			o.Act = nil
		})
		_, err := Validate(tok, defaultOpts(env))
		requireErrContains(t, err, "must be the resource owner")
	})

	t.Run("authorized with act rejected", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, func(o *OuterClaims) {
			o.Act = &Actor{Sub: da.AgentID}
		})
		_, err := Validate(tok, defaultOpts(env))
		requireErrContains(t, err, "act must be absent")
	})
}

// TestDAOuterBoundConsistency verifies the RS-side DA/outer checks
// required by Section 11: the DA audience must include the outer
// issuer, and the outer token must not outlive the DA grant.
func TestDAOuterBoundConsistency(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT", Params: json.RawMessage(`{"max_rows":100}`)}}

	t.Run("DA aud must include outer iss", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.Aud = Audience{"https://other.example.com"}
		})
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		_, err := Validate(tok, defaultOpts(env))
		requireErrContains(t, err, "DA aud")
	})

	t.Run("outer exp must not exceed DA exp", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, func(o *OuterClaims) {
			o.Exp = da.Exp + 100
		})
		_, err := Validate(tok, defaultOpts(env))
		requireErrContains(t, err, "exceeds DA exp")
	})
}
