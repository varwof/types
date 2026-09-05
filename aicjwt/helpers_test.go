package aicjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// testEnv bundles the keys and PA material used by conformance tests.
type testEnv struct {
	issuerKey     *ecdsa.PrivateKey
	principalKey  *ecdsa.PrivateKey
	agentKey      *ecdsa.PrivateKey
	principalCert *x509.Certificate
	now           time.Time
	pa            *PAClaims
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	agentKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	principalCert := selfSignedCert(t, principalKey, "zhangsan")
	pa := &PAClaims{
		Ver:       1,
		Principal: principalBinding(t, principalKey),
		Grants: []Capability{
			{Scheme: "database", ID: "query:*", Params: json.RawMessage(`{"max_rows":1000}`)},
			{Scheme: "database", ID: "admin:reset", Params: json.RawMessage(`{"window":"08:00-18:00"}`)},
		},
		DelegationPolicy: &DelegationPolicy{MaxAgents: 1, AllowedMode: AllowedModeRepresentative},
	}
	return &testEnv{
		issuerKey: issuerKey, principalKey: principalKey, agentKey: agentKey,
		principalCert: principalCert, now: now, pa: pa,
	}
}

func selfSignedCert(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func principalBinding(t *testing.T, key *ecdsa.PrivateKey) Principal {
	t.Helper()
	h, err := KeyHashOf(&key.PublicKey, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	return Principal{Realm: "corp.com", ID: "zhangsan", KeyHash: h, HashAlg: "sha-256"}
}

func agentJkt(t *testing.T, env *testEnv) string {
	t.Helper()
	h, err := KeyHashOf(&env.agentKey.PublicKey, "jkt")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// buildDA creates a principal-signed DA JWT.
func buildDA(t *testing.T, env *testEnv, mode string, caps []Capability, mut func(*DAClaims)) (string, *DAClaims) {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	p := principalBinding(t, env.principalKey)
	da := &DAClaims{
		Ver:               1,
		Iss:               p.SubjectID(),
		Aud:               Audience{"https://as.example.com"},
		AgentID:           "agent:db-analyst-01",
		Principal:         p,
		Reason:            Reason{Code: "DATA_ANALYSIS", Desc: "scheduled analysis"},
		Capabilities:      caps,
		DelegationMode:    mode,
		RequestedLifetime: 3600,
		TS:                env.now.Unix(),
		Nonce:             b64uEncode(nonce),
	}
	if mode == ModeRepresentative {
		da.Sub = p.SubjectID()
	} else {
		da.Sub = da.AgentID
	}
	da.Exp = da.TS + int64(da.RequestedLifetime)
	da.Iat = da.TS
	da.Jti = da.Nonce
	if mut != nil {
		mut(da)
	}
	pb, _ := json.Marshal(da)
	hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": TypDA, "kid": "principal-1"})
	tok, err := SignCompact(hb, pb, "ES256", env.principalKey)
	if err != nil {
		t.Fatal(err)
	}
	return tok, da
}

// buildOuter creates an outer AIC-JWT (used for negative tests that
// must bypass issuer-side checks).
func buildOuter(t *testing.T, env *testEnv, daToken string, da *DAClaims, mode string, caps []Capability, mut func(*OuterClaims)) (string, *OuterClaims) {
	t.Helper()
	jti := "test-jti"
	if da != nil {
		jti = da.Nonce
	}
	sub := "agent:db-analyst-01"
	rep := da != nil && da.DelegationMode == ModeRepresentative
	if rep {
		sub = da.Principal.SubjectID()
	}
	outer := &OuterClaims{
		Iss: "https://as.example.com",
		Sub: sub,
		Aud: Audience{"https://rs.example.com"},
		Iat: env.now.Unix(),
		Exp: env.now.Add(3600 * time.Second).Unix(),
		Jti: jti,
		Cnf: &Cnf{Jkt: agentJkt(t, env)},
		Aic: &AICClaims{
			Ver:            1,
			Principal:      principalBinding(t, env.principalKey),
			DelegationMode: mode,
			Capabilities:   caps,
		},
		Da: daToken,
	}
	if rep {
		outer.Act = &Actor{Sub: da.AgentID}
	}
	if mut != nil {
		mut(outer)
	}
	pb, _ := json.Marshal(outer)
	hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": TypOuter, "kid": "issuer-1"})
	tok, err := SignCompact(hb, pb, "ES256", env.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return tok, outer
}

func databasePlugins() map[string]CapabilityPlugin {
	return map[string]CapabilityPlugin{
		"database": func(req Capability, ctx RequestContext) error {
			if strings.HasPrefix(req.ID, "query:") || strings.HasPrefix(req.ID, "admin:") {
				return nil
			}
			return fmt.Errorf("database plugin denies %q", req.ID)
		},
		"http": func(req Capability, ctx RequestContext) error {
			return nil
		},
	}
}

func defaultCtx(env *testEnv) RequestContext {
	return RequestContext{
		Now:             env.now,
		SourceIP:        netip.MustParseAddr("10.1.2.3"),
		ConcurrentCount: 1,
	}
}

func defaultOpts(env *testEnv) VerifyOptions {
	return VerifyOptions{
		Now:               env.now,
		ExpectedIssuer:    "https://as.example.com",
		ExpectedAudience:  []string{"https://rs.example.com"},
		IssuerKeys:        map[string]crypto.PublicKey{"issuer-1": &env.issuerKey.PublicKey},
		PrincipalJWKS:     map[string]crypto.PublicKey{"principal-1": &env.principalKey.PublicKey},
		RequestCapability: &Capability{Scheme: "database", ID: "query:SELECT"},
		RequestContext:    defaultCtx(env),
		ConstraintStrict:  false,
		CapabilityPlugins: databasePlugins(),
		NonceStore:        NewMemNonceStore(),
		RejectDepthGT1:    true,
		PA:                env.pa,
	}
}

func requireErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got: %v", want, err)
	}
}
