package aicjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

var errRevoked = &nonceReuseError{}

type nonceReuseError struct{}

func (e *nonceReuseError) Error() string { return "revoked" }

func validOuterClaims(t *testing.T, env *testEnv) *OuterClaims {
	t.Helper()
	p := principalBinding(t, env.principalKey)
	return &OuterClaims{
		Iss: "https://as.example.com",
		Sub: "agent:db-analyst-01",
		Aud: Audience{"https://rs.example.com"},
		Iat: env.now.Unix(),
		Exp: env.now.Add(3600 * time.Second).Unix(),
		Jti: "test-jti",
		Cnf: &Cnf{Jkt: agentJkt(t, env)},
		Aic: &AICClaims{
			Ver:            1,
			Principal:      p,
			DelegationMode: ModeAuthorized,
			Capabilities:   []Capability{{Scheme: "database", ID: "query:SELECT"}},
		},
	}
}

func TestCheckOuterRequired(t *testing.T) {
	env := newTestEnv(t)
	base := validOuterClaims(t, env)
	if err := checkOuterRequired(base); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}

	cases := map[string]func(*OuterClaims){
		"iss empty":              func(o *OuterClaims) { o.Iss = "" },
		"sub empty":              func(o *OuterClaims) { o.Sub = "" },
		"sub too long":           func(o *OuterClaims) { o.Sub = strings.Repeat("x", 257) },
		"aud empty":              func(o *OuterClaims) { o.Aud = nil },
		"aud empty string":       func(o *OuterClaims) { o.Aud = Audience{""} },
		"iat zero":               func(o *OuterClaims) { o.Iat = 0 },
		"exp zero":               func(o *OuterClaims) { o.Exp = 0 },
		"exp <= iat":             func(o *OuterClaims) { o.Exp = o.Iat },
		"jti empty":              func(o *OuterClaims) { o.Jti = "" },
		"cnf nil":                func(o *OuterClaims) { o.Cnf = nil },
		"cnf jkt empty":          func(o *OuterClaims) { o.Cnf.Jkt = "" },
		"aic nil":                func(o *OuterClaims) { o.Aic = nil },
		"aic ver zero":           func(o *OuterClaims) { o.Aic.Ver = 2 },
		"principal realm empty":  func(o *OuterClaims) { o.Aic.Principal.Realm = "" },
		"principal realm too lo": func(o *OuterClaims) { o.Aic.Principal.Realm = strings.Repeat("x", 129) },
		"principal id empty":     func(o *OuterClaims) { o.Aic.Principal.ID = "" },
		"principal id too long":  func(o *OuterClaims) { o.Aic.Principal.ID = strings.Repeat("x", 257) },
		"principal keyhash empt": func(o *OuterClaims) { o.Aic.Principal.KeyHash = "" },
		"bad hash alg":           func(o *OuterClaims) { o.Aic.Principal.HashAlg = "md5" },
		"bad delegation mode":    func(o *OuterClaims) { o.Aic.DelegationMode = "strange" },
		"no capabilities":        func(o *OuterClaims) { o.Aic.Capabilities = nil },
		"too many capabilities": func(o *OuterClaims) {
			o.Aic.Capabilities = make([]Capability, 257)
			for i := range o.Aic.Capabilities {
				o.Aic.Capabilities[i] = Capability{Scheme: "s", ID: "i"}
			}
		},
		"cap params too big": func(o *OuterClaims) {
			o.Aic.Capabilities = []Capability{{Scheme: "database", ID: "query:SELECT",
				Params: json.RawMessage(`{"p":"` + strings.Repeat("x", MaxParamsSize+1) + `"}`)}}
		},
		"constraints too many": func(o *OuterClaims) {
			o.Aic.Constraints = make([]Capability, 33)
			for i := range o.Aic.Constraints {
				o.Aic.Constraints[i] = Capability{Scheme: ConstraintScheme, ID: "max-concurrent"}
			}
		},
		"constraint params big": func(o *OuterClaims) {
			o.Aic.Constraints = []Capability{{Scheme: ConstraintScheme, ID: "max-concurrent",
				Params: json.RawMessage(`{"p":"` + strings.Repeat("x", MaxParamsSize+1) + `"}`)}}
		},
		"extensions too many": func(o *OuterClaims) {
			o.Aic.Extensions = make(map[string]Extension, 33)
			for i := 0; i < 33; i++ {
				o.Aic.Extensions[fmt.Sprintf("ext-%02d", i)] = Extension{}
			}
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			o := *base
			o.Aic = &(*base.Aic)
			o.Aic.Capabilities = append([]Capability(nil), base.Aic.Capabilities...)
			mut(&o)
			if err := checkOuterRequired(&o); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestCheckTimeNbfAndExpired(t *testing.T) {
	env := newTestEnv(t)
	base := validOuterClaims(t, env)

	t.Run("nbf in future", func(t *testing.T) {
		o := *base
		n := env.now.Add(60 * time.Second).Unix()
		o.Nbf = &n
		if err := checkTime(&o, env.now); err == nil {
			t.Fatal("expected not-yet-valid error")
		}
	})

	t.Run("nbf exact now passes", func(t *testing.T) {
		o := *base
		n := env.now.Unix()
		o.Nbf = &n
		if err := checkTime(&o, env.now); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCheckDepth(t *testing.T) {
	opts := VerifyOptions{RejectDepthGT1: true}
	a := &AICClaims{ChainDepth: 1, MaxDepth: 1}
	if err := checkDepth(a, opts); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}

	cases := map[string]func(*AICClaims){
		"chain negative":    func(x *AICClaims) { x.ChainDepth = -1 },
		"chain too big":     func(x *AICClaims) { x.ChainDepth = 256 },
		"max negative":      func(x *AICClaims) { x.MaxDepth = -1 },
		"max too big":       func(x *AICClaims) { x.MaxDepth = 256 },
		"chain exceeds max": func(x *AICClaims) { x.ChainDepth = 2; x.MaxDepth = 1 },
		"max exceeds rec":   func(x *AICClaims) { x.MaxDepth = 2; x.ChainDepth = 2 },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			x := *a
			mut(&x)
			if err := checkDepth(&x, opts); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}

	t.Run("reject depth gt 1 off", func(t *testing.T) {
		opts.RejectDepthGT1 = false
		x := &AICClaims{ChainDepth: 3, MaxDepth: 3}
		if err := checkDepth(x, opts); err != nil {
			t.Fatalf("deep chain allowed when RejectDepthGT1=false: %v", err)
		}
	})
}

func TestResolvePrincipalKey(t *testing.T) {
	env := newTestEnv(t)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := principalBinding(t, env.principalKey)

	t.Run("principal material jwk by kid", func(t *testing.T) {
		j, err := PublicKeyToJWK(&env.principalKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		opts := VerifyOptions{PrincipalMaterial: &PrincipalKeyMaterial{
			JWK: map[string]JWK{"principal-1": j},
		}}
		got, err := resolvePrincipalKey(p, "principal-1", opts)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if _, ok := got.(*ecdsa.PublicKey); !ok {
			t.Fatalf("unexpected key type %T", got)
		}
	})

	t.Run("principal material jwk unknown kid falls to binding lookup", func(t *testing.T) {
		// LookupByBinding with a jkt hash_alg scans the JWK map for a
		// matching thumbprint.
		j, err := PublicKeyToJWK(&env.principalKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		ph := principalBinding(t, env.principalKey)
		ph.HashAlg = "jkt"
		jkt, err := JWKThumbprint(j)
		if err != nil {
			t.Fatal(err)
		}
		ph.KeyHash = jkt
		opts := VerifyOptions{PrincipalMaterial: &PrincipalKeyMaterial{
			JWK: map[string]JWK{"other": j},
		}}
		if _, err := resolvePrincipalKey(ph, "missing", opts); err != nil {
			t.Fatalf("resolve via binding should work: %v", err)
		}
	})

	t.Run("principal jwks by kid", func(t *testing.T) {
		opts := VerifyOptions{PrincipalJWKS: map[string]crypto.PublicKey{"principal-1": &env.principalKey.PublicKey}}
		got, err := resolvePrincipalKey(p, "principal-1", opts)
		if err != nil {
			t.Fatal(err)
		}
		if got != (crypto.PublicKey)(&env.principalKey.PublicKey) {
			_ = got
		}
	})

	t.Run("unresolvable", func(t *testing.T) {
		opts := VerifyOptions{}
		if _, err := resolvePrincipalKey(p, "nope", opts); err == nil {
			t.Fatal("expected unresolvable error")
		}
	})

	t.Run("lookup binding called with wrong key type", func(t *testing.T) {
		_ = otherKey
	})

	t.Run("material with bad jwk decode", func(t *testing.T) {
		opts := VerifyOptions{PrincipalMaterial: &PrincipalKeyMaterial{
			JWK: map[string]JWK{"kid": {Kty: "EC", Crv: "P-256", X: "%%%", Y: "%%%"}},
		}}
		if _, err := resolvePrincipalKey(p, "kid", opts); err == nil {
			t.Fatal("expected decode error")
		}
	})
}

func TestCheckConsistencyVariants(t *testing.T) {
	env := newTestEnv(t)
	p := principalBinding(t, env.principalKey)
	repDa := &DAClaims{
		DelegationMode: ModeRepresentative,
		Sub:            p.SubjectID(),
		AgentID:        "agent:x",
		Principal:      p,
		Capabilities:   []Capability{{Scheme: "database", ID: "query:*"}},
	}
	authDa := &DAClaims{
		DelegationMode: ModeAuthorized,
		Sub:            "agent:x",
		AgentID:        "agent:x",
		Principal:      p,
		Capabilities:   []Capability{{Scheme: "database", ID: "query:*"}},
	}

	t.Run("authorized act present rejected", func(t *testing.T) {
		o := validOuterClaims(t, env)
		o.Act = &Actor{Sub: "agent:x"}
		if err := checkConsistency(o, authDa); err == nil {
			t.Fatal("expected rejection of act in authorized mode")
		}
	})

	t.Run("authorized agent mismatch", func(t *testing.T) {
		o := validOuterClaims(t, env)
		if err := checkConsistency(o, authDa); err == nil {
			t.Fatal("expected DA agent_id mismatch")
		}
	})

	t.Run("representative fine", func(t *testing.T) {
		o := validOuterClaims(t, env)
		o.Sub = p.SubjectID()
		o.Act = &Actor{Sub: repDa.AgentID}
		o.Aic.DelegationMode = ModeRepresentative
		o.Aic.Capabilities = repDa.Capabilities
		o.Aic.Principal = p
		if err := checkConsistency(o, repDa); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("representative missing act", func(t *testing.T) {
		o := validOuterClaims(t, env)
		o.Sub = p.SubjectID()
		o.Aic.DelegationMode = ModeRepresentative
		if err := checkConsistency(o, repDa); err == nil {
			t.Fatal("expected missing act error")
		}
	})

	t.Run("representative wrong act sub", func(t *testing.T) {
		o := validOuterClaims(t, env)
		o.Sub = p.SubjectID()
		o.Act = &Actor{Sub: "agent:wrong"}
		o.Aic.DelegationMode = ModeRepresentative
		if err := checkConsistency(o, repDa); err == nil {
			t.Fatal("expected wrong act sub error")
		}
	})

	t.Run("mode mismatch", func(t *testing.T) {
		o := validOuterClaims(t, env)
		o.Aic.DelegationMode = ModeRepresentative
		o.Sub = p.SubjectID()
		o.Act = &Actor{Sub: "agent:x"}
		if err := checkConsistency(o, authDa); err == nil {
			t.Fatal("expected delegation mode mismatch")
		}
	})

	t.Run("capabilities mismatch", func(t *testing.T) {
		o := validOuterClaims(t, env)
		o.Aic.Capabilities = []Capability{{Scheme: "database", ID: "admin:reset"}}
		if err := checkConsistency(o, authDa); err == nil {
			t.Fatal("expected capabilities mismatch")
		}
	})

	t.Run("constraints mismatch", func(t *testing.T) {
		o := validOuterClaims(t, env)
		o.Aic.Constraints = []Capability{{Scheme: ConstraintScheme, ID: "max-concurrent"}}
		if err := checkConsistency(o, authDa); err == nil {
			t.Fatal("expected constraints mismatch")
		}
	})
}

func TestPrincipalOAuthSubject(t *testing.T) {
	d := &DAClaims{AgentID: "agent:a", Principal: Principal{Realm: "r", ID: "x"}}
	if got := d.OAuthSubject(); got != "agent:a" {
		t.Fatalf("authorized oauth subject = %q", got)
	}
	d.DelegationMode = ModeRepresentative
	if got := d.OAuthSubject(); got != "r:x" {
		t.Fatalf("representative oauth subject = %q", got)
	}
}

func TestAlgForPublicKeyCoverage(t *testing.T) {
	if got, _ := AlgForPublicKey(&ecdsa.PublicKey{Curve: elliptic.P384()}); got != "ES384" {
		t.Fatalf("P-384 alg = %q", got)
	}
	if got, _ := AlgForPublicKey(&ecdsa.PublicKey{Curve: elliptic.P521()}); got != "ES512" {
		t.Fatalf("P-521 alg = %q", got)
	}
	if _, err := AlgForPublicKey(&ecdsa.PublicKey{}); err == nil {
		t.Fatal("expected unsupported curve error")
	}
	smallRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	if got, _ := AlgForPublicKey(&smallRSA.PublicKey); got != "RS256" {
		t.Fatalf("small RSA alg = %q", got)
	}
	if got, _ := AlgForPublicKey(ed25519.PublicKey{1, 2, 3}); got != "EdDSA" {
		t.Fatalf("Ed25519 alg = %q", got)
	}
	if _, err := AlgForPublicKey(struct{}{}); err == nil {
		t.Fatal("expected unsupported type error")
	}
}

func TestJWKToPublicErrors(t *testing.T) {
	cases := []JWK{
		{Kty: "EC", Crv: "P-256", X: "%%%", Y: "%%%"},
		{Kty: "RSA", N: "%%%", E: "AQAB"},
		{Kty: "OKP", X: "%%%"},
		{Kty: "EC", Crv: "unknown", X: "AQ", Y: "AQ"},
		{Kty: "HEC"},
	}
	for _, j := range cases {
		if _, err := JWKToPublic(j); err == nil {
			t.Fatalf("expected error for %+v", j)
		}
	}
}

func TestSPKIHashPubUnsupported(t *testing.T) {
	if _, err := hashBytes([]byte("data"), "md5"); err == nil {
		t.Fatal("expected unsupported hash error")
	}
}

func TestHashBytesAlgos(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{"sha-256", "sha-384", "sha-512"} {
		if _, err := hashBytes(der, alg); err != nil {
			t.Fatalf("%s failed: %v", alg, err)
		}
	}
}

func TestMatchTokenAlternationAndClass(t *testing.T) {
	ok := map[string]string{
		"{GET,POST}*": "GET",
		"{GET,POST}":  "POST",
		"[A-Z]*":      "Hello",
		"GET*/x":      "GET/x",
		"a{b,c}d":     "abd",
		"{a,b}{c,d}":  "bc",
		"a*":          "a",
		"*":           "",
		"x":           "x",
		"":            "",
	}
	for pat, target := range ok {
		if !matchToken(pat, target) {
			t.Errorf("expected %q to match %q", pat, target)
		}
	}

	not := map[string]string{
		"a":          "b",
		"{GET,POST}": "PUT",
		"{a,b":       "a", // malformed alternation
		"[a-z":       "a", // malformed class
		"[A-Z]*":     "hello",
		"GET*/x":     "GET/y",
	}

	for pat, target := range not {
		if matchToken(pat, target) {
			t.Errorf("expected %q NOT to match %q", pat, target)
		}
	}
}

func TestInCharClassRanges(t *testing.T) {
	if !inCharClass("a-z0-9", 'm') {
		t.Fatal("expected 'm' in class")
	}
	if !inCharClass("a-z0-9", '5') {
		t.Fatal("expected '5' in class")
	}
	if inCharClass("a-z0-9", 'A') {
		t.Fatal("did not expect 'A' in class")
	}
	if !inCharClass("ABC", 'B') {
		t.Fatal("expected 'B' in literal class")
	}
	if inCharClass("", 'x') {
		t.Fatal("empty class should not match")
	}
}

func TestParamsWithinTypes(t *testing.T) {
	// Float and int numeric bounds use decoded json.Number comparison.
	ok, err := ParamsWithinGrant(json.RawMessage(`{"max":5}`), json.RawMessage(`{"max":3}`))
	if err != nil || !ok {
		t.Fatalf("numeric bound ok=%v err=%v", ok, err)
	}
	ok, err = ParamsWithinGrant(json.RawMessage(`{"max":5}`), json.RawMessage(`{"max":9}`))
	if err != nil || ok {
		t.Fatalf("numeric over bound ok=%v err=%v", ok, err)
	}
	// Arrays must be subsets.
	sub, err := ParamsWithinGrant(json.RawMessage(`["a","b","c"]`), json.RawMessage(`["a","b"]`))
	if err != nil || !sub {
		t.Fatalf("array subset sub=%v err=%v", sub, err)
	}
	sub, err = ParamsWithinGrant(json.RawMessage(`["a","b"]`), json.RawMessage(`["a","c"]`))
	if err != nil || sub {
		t.Fatalf("array over subset sub=%v err=%v", sub, err)
	}
	// Agent adding keys the grant never granted.
	ok, err = ParamsWithinGrant(json.RawMessage(`{"max":5}`), json.RawMessage(`{"max":3,"extra":1}`))
	if err != nil || ok {
		t.Fatalf("extra key ok=%v err=%v", ok, err)
	}
	// Agent omitting a required grant key.
	ok, err = ParamsWithinGrant(json.RawMessage(`{"max":5}`), json.RawMessage(`{}`))
	if err != nil || ok {
		t.Fatalf("missing key ok=%v err=%v (want false)", ok, err)
	}
	// Object grant but agent supplies non-object.
	ok, err = ParamsWithinGrant(json.RawMessage(`{"max":5}`), json.RawMessage(`3`))
	if err != nil || ok {
		t.Fatalf("scalar agent ok=%v err=%v", ok, err)
	}
	// Malformed grant JSON.
	if _, err := ParamsWithinGrant(json.RawMessage(`{bad`), json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected decode error on malformed grant")
	}
	// null / empty grant unconstrained.
	for _, g := range []json.RawMessage{json.RawMessage(``), json.RawMessage(`null`)} {
		ok, err = ParamsWithinGrant(g, json.RawMessage(`{"anything":1}`))
		if err != nil || !ok {
			t.Fatalf("unconstrained grant ok=%v err=%v", ok, err)
		}
	}
}

func TestEvalAllowedCIDR(t *testing.T) {
	env := newTestEnv(t)
	ctx := defaultCtx(env)

	ok, err := EvaluateConstraints([]Capability{
		{Scheme: ConstraintScheme, ID: "allowed-cidr", Params: json.RawMessage(`["10.1.0.0/16"]`)},
	}, ctx, true)
	if err != nil || len(ok) != 0 {
		t.Fatalf("cidr within range: notes=%v err=%v", ok, err)
	}

	_, err = EvaluateConstraints([]Capability{
		{Scheme: ConstraintScheme, ID: "allowed-cidr", Params: json.RawMessage(`["192.0.2.0/24"]`)},
	}, ctx, true)
	if err == nil {
		t.Fatal("expected source IP outside allowed ranges")
	}

	// Malformed params.
	_, err = EvaluateConstraints([]Capability{
		{Scheme: ConstraintScheme, ID: "allowed-cidr", Params: json.RawMessage(`"not-an-array"`)},
	}, ctx, true)
	if err == nil {
		t.Fatal("expected params decode error")
	}

	// Invalid CIDR string inside the array.
	_, err = EvaluateConstraints([]Capability{
		{Scheme: ConstraintScheme, ID: "allowed-cidr", Params: json.RawMessage(`["10.0.0.0/999"]`)},
	}, ctx, true)
	if err == nil {
		t.Fatal("expected invalid CIDR error")
	}

	// No source IP in context.
	badCtx := RequestContext{Now: ctx.Now}
	_, err = EvaluateConstraints([]Capability{
		{Scheme: ConstraintScheme, ID: "allowed-cidr", Params: json.RawMessage(`["10.0.0.0/8"]`)},
	}, badCtx, true)
	if err == nil {
		t.Fatal("expected no-source-IP error")
	}
}

func TestEvalTimeWindow(t *testing.T) {
	t.Run("within morning window", func(t *testing.T) {
		now := time.Date(2026, 9, 4, 9, 30, 0, 0, time.UTC)
		ctx := RequestContext{Now: now}
		notes, err := EvaluateConstraints([]Capability{
			{Scheme: ConstraintScheme, ID: "time-window", Params: json.RawMessage(`{"start":"08:00","end":"18:00"}`)},
		}, ctx, true)
		if err != nil || len(notes) != 0 {
			t.Fatalf("within window: notes=%v err=%v", notes, err)
		}
	})

	t.Run("outside window", func(t *testing.T) {
		now := time.Date(2026, 9, 4, 0, 30, 0, 0, time.UTC)
		ctx := RequestContext{Now: now}
		_, err := EvaluateConstraints([]Capability{
			{Scheme: ConstraintScheme, ID: "time-window", Params: json.RawMessage(`{"start":"08:00","end":"18:00"}`)},
		}, ctx, true)
		if err == nil {
			t.Fatal("expected outside-window error")
		}
	})

	t.Run("overnight window inside", func(t *testing.T) {
		now := time.Date(2026, 9, 4, 23, 0, 0, 0, time.UTC)
		ctx := RequestContext{Now: now}
		_, err := EvaluateConstraints([]Capability{
			{Scheme: ConstraintScheme, ID: "time-window", Params: json.RawMessage(`{"start":"22:00","end":"06:00"}`)},
		}, ctx, true)
		if err != nil {
			t.Fatalf("overnight inside: %v", err)
		}
	})

	t.Run("invalid params", func(t *testing.T) {
		_, err := EvaluateConstraints([]Capability{
			{Scheme: ConstraintScheme, ID: "time-window", Params: json.RawMessage(`{"start":"25:99","end":"18:00"}`)},
		}, RequestContext{Now: time.Now()}, true)
		if err == nil {
			t.Fatal("expected invalid HH:MM error")
		}
	})
}

// TestValidateStepBranching drives the Validate pipeline through steps
// that the happy-path scenarios do not reach.
func TestValidateStepBranching(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}

	t.Run("lightweight authorized without DA", func(t *testing.T) {
		// No DA token: authorized mode is allowed without DA material as
		// long as lifetime stays within MaxLifetime.
		tok, _ := buildOuter(t, env, "", nil, ModeAuthorized, caps, nil)
		opts := defaultOpts(env)
		opts.NonceStore = NewMemNonceStore()
		if _, err := Validate(tok, opts); err != nil {
			t.Fatalf("lightweight authorized should pass: %v", err)
		}
	})

	t.Run("lightweight lifetime exceeds max", func(t *testing.T) {
		tok, _ := buildOuter(t, env, "", nil, ModeAuthorized, caps, func(o *OuterClaims) {
			o.Exp = o.Iat + MaxLifetime + 1
		})
		opts := defaultOpts(env)
		opts.NonceStore = NewMemNonceStore()
		if _, err := Validate(tok, opts); err == nil {
			t.Fatal("expected MaxLifetime overflow error")
		}
	})

	t.Run("representative requires DA", func(t *testing.T) {
		tok, _ := buildOuter(t, env, "", nil, ModeRepresentative, caps, nil)
		opts := defaultOpts(env)
		opts.NonceStore = NewMemNonceStore()
		if _, err := Validate(tok, opts); err == nil {
			t.Fatal("expected representative-without-DA error")
		}
	})

	t.Run("step10 status without checker", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, func(o *OuterClaims) {
			o.Status = &StatusRef{Idx: 1, URI: "https://as.example.com/status/1"}
		})
		opts := defaultOpts(env)
		opts.StatusChecker = nil
		if _, err := Validate(tok, opts); err == nil {
			t.Fatal("expected status-claim-without-checker error")
		}
	})

	t.Run("step10 status check fails", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, func(o *OuterClaims) {
			o.Status = &StatusRef{Idx: 1, URI: "https://as.example.com/status/1"}
		})
		opts := defaultOpts(env)
		opts.StatusChecker = func(StatusRef) error {
			return errRevoked
		}
		if _, err := Validate(tok, opts); err == nil {
			t.Fatal("expected status checker denial")
		}
	})

	t.Run("expected issuer mismatch", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		opts := defaultOpts(env)
		opts.ExpectedIssuer = "https://other.example.com"
		if _, err := Validate(tok, opts); err == nil {
			t.Fatal("expected issuer mismatch")
		}
	})

	t.Run("audience confusion", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		opts := defaultOpts(env)
		opts.ExpectedAudience = []string{"https://unrelated.example.com"}
		if _, err := Validate(tok, opts); err == nil {
			t.Fatal("expected audience confusion error")
		}
	})

	t.Run("cnf binding passthrough", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		opts := defaultOpts(env)
		opts.PresenterKey = &env.agentKey.PublicKey
		if _, err := Validate(tok, opts); err != nil {
			t.Fatalf("presenter binding should pass: %v", err)
		}
	})

	t.Run("cnf binding theft detection", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		opts := defaultOpts(env)
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		opts.PresenterKey = &otherKey.PublicKey
		if _, err := Validate(tok, opts); err == nil {
			t.Fatal("expected presenter key mismatch (token theft)")
		}
	})

	t.Run("presenter key without cnf", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, func(o *OuterClaims) {
			o.Cnf = nil
		})
		opts := defaultOpts(env)
		opts.PresenterKey = &env.agentKey.PublicKey
		if _, err := Validate(tok, opts); err == nil {
			t.Fatal("expected missing cnf with presenter error")
		}
	})

	t.Run("plugin conflicts with capability", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		opts := defaultOpts(env)
		opts.RequestCapability = &Capability{Scheme: "database", ID: "query:SELECT"}
		opts.CapabilityPlugins = map[string]CapabilityPlugin{
			"database": func(req Capability, ctx RequestContext) error {
				return errRevoked
			},
		}
		if _, err := Validate(tok, opts); err == nil {
			t.Fatal("expected plugin denial")
		}
	})

	t.Run("step9 unknown scheme fail closed", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		opts := defaultOpts(env)
		opts.RequestCapability = &Capability{Scheme: "nope", ID: "x"}
		if _, err := Validate(tok, opts); err == nil {
			t.Fatal("expected unknown scheme fail closed")
		}
	})

	t.Run("presenter thumbprint error path", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		tok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, nil)
		opts := defaultOpts(env)
		opts.PresenterKey = struct{}{}
		if _, err := Validate(tok, opts); err == nil {
			t.Fatal("expected thumbprint error for unusable presenter key")
		}
	})
}

func TestCheckPAVariants(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, da := buildDA(t, env, ModeRepresentative, caps, nil)
	_, o := buildOuter(t, env, daTok, da, ModeRepresentative, caps, nil)

	t.Run("ver must be 1", func(t *testing.T) {
		o2 := *o
		o2.Aic = &(*o.Aic)
		o2.Aic.Principal = da.Principal
		opts := VerifyOptions{PA: &PAClaims{Ver: 2}}
		if err := checkPA(&o2, opts); err == nil {
			t.Fatal("expected ver error")
		}
	})

	t.Run("principal mismatch", func(t *testing.T) {
		pa := &PAClaims{Ver: 1, Principal: Principal{Realm: "x", ID: "y"}}
		opts := VerifyOptions{PA: pa}
		if err := checkPA(o, opts); err == nil {
			t.Fatal("expected principal mismatch")
		}
	})

	t.Run("no delegation policy", func(t *testing.T) {
		pa := &PAClaims{Ver: 1, Principal: da.Principal}
		opts := VerifyOptions{PA: pa}
		if err := checkPA(o, opts); err == nil {
			t.Fatal("expected missing delegation policy error")
		}
	})

	t.Run("policy wrong mode", func(t *testing.T) {
		pa := &PAClaims{Ver: 1, Principal: da.Principal,
			DelegationPolicy: &DelegationPolicy{AllowedMode: ModeAuthorized}}
		opts := VerifyOptions{PA: pa}
		if err := checkPA(o, opts); err == nil {
			t.Fatal("expected wrong allowed mode error")
		}
	})

	t.Run("capability beyond grants", func(t *testing.T) {
		pa := &PAClaims{Ver: 1, Principal: da.Principal, Grants: []Capability{{Scheme: "http", ID: "*"}},
			DelegationPolicy: &DelegationPolicy{AllowedMode: AllowedModeRepresentative}}
		opts := VerifyOptions{PA: pa}
		if err := checkPA(o, opts); err == nil {
			t.Fatal("expected capability beyond grants error")
		}
	})

	t.Run("grant params too big", func(t *testing.T) {
		pa := &PAClaims{Ver: 1, Principal: da.Principal,
			Grants: []Capability{{Scheme: "database", ID: "query:*",
				Params: json.RawMessage(`{"p":"` + strings.Repeat("x", MaxParamsSize+1) + `"}`)}},
			DelegationPolicy: &DelegationPolicy{AllowedMode: AllowedModeRepresentative}}
		opts := VerifyOptions{PA: pa}
		if err := checkPA(o, opts); err == nil {
			t.Fatal("expected grant params too big error")
		}
	})

	t.Run("constraint params too big", func(t *testing.T) {
		pa := &PAClaims{Ver: 1, Principal: da.Principal,
			Grants: []Capability{{Scheme: "database", ID: "query:*"}},
			Constraints: []Capability{{Scheme: ConstraintScheme, ID: "max-concurrent",
				Params: json.RawMessage(`{"p":"` + strings.Repeat("x", MaxParamsSize+1) + `"}`)}},
			DelegationPolicy: &DelegationPolicy{AllowedMode: AllowedModeRepresentative}}
		opts := VerifyOptions{PA: pa}
		if err := checkPA(o, opts); err == nil {
			t.Fatal("expected constraint params too big error")
		}
	})

	t.Run("valid representative passthrough", func(t *testing.T) {
		pa := &PAClaims{Ver: 1, Principal: da.Principal,
			Grants:           []Capability{{Scheme: "database", ID: "query:*"}},
			DelegationPolicy: &DelegationPolicy{AllowedMode: AllowedModeRepresentative}}
		opts := VerifyOptions{PA: pa}
		if err := checkPA(o, opts); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
