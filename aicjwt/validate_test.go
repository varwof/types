package aicjwt

import (
	"crypto"
	"encoding/json"
	"strings"
	"testing"
)

func TestCheckHeader(t *testing.T) {
	valid := Header{Alg: "ES256", Typ: TypDA, Kid: "principal-1"}
	if err := CheckHeader(valid, TypDA); err != nil {
		t.Fatalf("valid header rejected: %v", err)
	}

	cases := []struct {
		name   string
		header Header
		want   string
	}{
		{"wrong typ", Header{Alg: "ES256", Typ: TypOuter, Kid: "principal-1"}, "unexpected typ"},
		{"empty alg", Header{Typ: TypDA, Kid: "principal-1"}, "alg"},
		{"alg none", Header{Alg: "none", Typ: TypDA, Kid: "principal-1"}, "alg"},
		{"alg not allowed", Header{Alg: "HS256", Typ: TypDA, Kid: "principal-1"}, "not in allowlist"},
		{"empty kid", Header{Alg: "ES256", Typ: TypDA}, "kid"},
		{"crit header", Header{Alg: "ES256", Typ: TypDA, Kid: "principal-1", Crit: []string{"exp"}}, "critical"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckHeader(c.header, TypDA)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
		})
	}
}

func TestValidateDA(t *testing.T) {
	env := newTestEnv(t)
	tok, da := buildDA(t, env, ModeAuthorized, []Capability{
		{Scheme: "database", ID: "query:SELECT"},
	}, nil)
	if da == nil {
		t.Fatal("buildDA returned nil DA")
	}

	opts := VerifyOptions{
		PrincipalJWKS: map[string]crypto.PublicKey{"principal-1": &env.principalKey.PublicKey},
		NonceStore:    NewMemNonceStore(),
	}
	got, err := ValidateDA(tok, opts)
	if err != nil {
		t.Fatalf("ValidateDA: %v", err)
	}
	if got.AgentID != "agent:db-analyst-01" {
		t.Errorf("AgentID = %q", got.AgentID)
	}
	if len(got.Capabilities) != 1 {
		t.Errorf("capabilities = %d, want 1", len(got.Capabilities))
	}
}

func TestValidateDANegatives(t *testing.T) {
	env := newTestEnv(t)
	opts := func() VerifyOptions {
		return VerifyOptions{
			PrincipalJWKS: map[string]crypto.PublicKey{"principal-1": &env.principalKey.PublicKey},
			NonceStore:    NewMemNonceStore(),
		}
	}

	t.Run("wrong typ header", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, []Capability{{Scheme: "database", ID: "query:SELECT"}}, nil)
		hb, pb, _, err := ParseCompact(tok)
		if err != nil {
			t.Fatal(err)
		}
		var hdr map[string]any
		if err := json.Unmarshal(hb, &hdr); err != nil {
			t.Fatal(err)
		}
		hdr["typ"] = TypOuter
		hb2, _ := json.Marshal(hdr)
		bad, err := SignCompact(hb2, pb, "ES256", env.principalKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ValidateDA(bad, opts())
		if err == nil || !strings.Contains(err.Error(), "unexpected typ") {
			t.Fatalf("expected typ error, got %v", err)
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, []Capability{{Scheme: "database", ID: "query:SELECT"}}, nil)
		// Tamper the trailing signature bytes.
		tampered := tok[:len(tok)-2] + "AA"
		_, err := ValidateDA(tampered, opts())
		if err == nil {
			t.Fatal("expected signature error, got nil")
		}
	})

	t.Run("nonce reuse", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, []Capability{{Scheme: "database", ID: "query:SELECT"}}, nil)
		o := opts()
		if _, err := ValidateDA(tok, o); err != nil {
			t.Fatalf("first ValidateDA: %v", err)
		}
		_, err := ValidateDA(tok, o)
		if err == nil || !strings.Contains(err.Error(), "nonce reuse") {
			t.Fatalf("expected nonce reuse error, got %v", err)
		}
	})

	t.Run("no principal key", func(t *testing.T) {
		tok, _ := buildDA(t, env, ModeAuthorized, []Capability{{Scheme: "database", ID: "query:SELECT"}}, nil)
		_, err := ValidateDA(tok, VerifyOptions{})
		if err == nil {
			t.Fatal("expected error for missing principal key, got nil")
		}
	})
}

func TestCheckDARequired(t *testing.T) {
	env := newTestEnv(t)
	valid := func() *DAClaims {
		_, da := buildDA(t, env, ModeAuthorized, []Capability{{Scheme: "database", ID: "query:SELECT"}}, nil)
		return da
	}

	if err := checkDARequired(valid()); err != nil {
		t.Fatalf("valid DA rejected: %v", err)
	}

	// Each mutation must produce a failure.
	cases := []struct {
		name string
		mut  func(*DAClaims)
		want string
	}{
		{"ver", func(d *DAClaims) { d.Ver = 1 }, "DA ver"},
		{"agent_id empty", func(d *DAClaims) { d.AgentID = "" }, "agent_id"},
		{"agent_id too long", func(d *DAClaims) { d.AgentID = strings.Repeat("x", 257) }, "agent_id"},
		{"principal missing", func(d *DAClaims) { d.Principal = Principal{} }, "principal"},
		{"reason missing", func(d *DAClaims) { d.Reason = Reason{} }, "reason"},
		{"capabilities empty", func(d *DAClaims) { d.Capabilities = nil }, "capabilities"},
		{"capabilities too many", func(d *DAClaims) { d.Capabilities = make([]Capability, 257) }, "capabilities"},
		{"delegation_mode invalid", func(d *DAClaims) { d.DelegationMode = "bogus" }, "delegation_mode"},
		{"constraints too many", func(d *DAClaims) { d.Constraints = make([]Capability, 33) }, "constraints"},
		{"requested_lifetime too low", func(d *DAClaims) { d.RequestedLifetime = 0 }, "requested_lifetime"},
		{"requested_lifetime too high", func(d *DAClaims) { d.RequestedLifetime = MaxLifetime + 1 }, "requested_lifetime"},
		{"ts zero", func(d *DAClaims) { d.TS = 0 }, "ts"},
		{"nonce empty", func(d *DAClaims) { d.Nonce = "" }, "nonce"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := valid()
			c.mut(d)
			err := checkDARequired(d)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
		})
	}
}

func TestCheckPA(t *testing.T) {
	env := newTestEnv(t)
	validOuter := func() *OuterClaims {
		return &OuterClaims{
			Aic: &AICClaims{
				Ver:            1,
				Principal:      principalBinding(t, env.principalKey),
				DelegationMode: ModeRepresentative,
				Capabilities:   []Capability{{Scheme: "database", ID: "query:SELECT", Params: json.RawMessage(`{"max_rows":100}`)}},
			},
		}
	}
	opts := func() VerifyOptions {
		paCopy := *env.pa
		o := VerifyOptions{PA: &paCopy}
		o.RequestContext = defaultCtx(env)
		return o
	}

	if err := checkPA(validOuter(), opts()); err != nil {
		t.Fatalf("valid PA rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*OuterClaims, *VerifyOptions)
		want string
	}{
		{"nil PA", func(o *OuterClaims, v *VerifyOptions) { v.PA = nil }, "requires PrincipalAuthorization"},
		{"pa ver wrong", func(o *OuterClaims, v *VerifyOptions) { v.PA.Ver = 2 }, "PA ver"},
		{"principal mismatch", func(o *OuterClaims, v *VerifyOptions) { o.Aic.Principal.ID = "other" }, "principal"},
		{"policy nil", func(o *OuterClaims, v *VerifyOptions) { v.PA.DelegationPolicy = nil }, "delegation policy"},
		{"policy not representative", func(o *OuterClaims, v *VerifyOptions) {
			v.PA.DelegationPolicy = &DelegationPolicy{MaxAgents: 1, AllowedMode: "authorized"}
		}, "delegation policy"},
		{"capability not in grants", func(o *OuterClaims, v *VerifyOptions) {
			o.Aic.Capabilities = []Capability{{Scheme: "http", ID: "GET"}}
		}, "not within P_grants"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := validOuter()
			v := opts()
			c.mut(o, &v)
			err := checkPA(o, v)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
		})
	}
}
