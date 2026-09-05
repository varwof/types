package aicjwt

import (
	"crypto"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// L1: ParamsWithinGrant must reject an agent that omits required keys that the
// grant declares. Varying the grant but omitting the agent param is an escape.
func TestParamsWithinGrantRequiresGrantKeysL1(t *testing.T) {
	// Grant = object, agent = empty object (params omitted entirely).
	within, err := ParamsWithinGrant(json.RawMessage(`{"max":5}`), json.RawMessage(`{}`))
	if err != nil || within {
		t.Fatalf("grant non-empty, agent {}: expected (false, nil), got (%v, %v)", within, err)
	}
	// Grant object with a key the agent does not carry.
	within, err = ParamsWithinGrant(json.RawMessage(`{"max":5,"level":"admin"}`), json.RawMessage(`{"max":3}`))
	if err != nil || within {
		t.Fatalf("agent omits grant key level: expected (false, nil), got (%v, %v)", within, err)
	}
	// Grant max, agent max within -> still true (max is bounded below by grant).
	within, err = ParamsWithinGrant(json.RawMessage(`{"max":5}`), json.RawMessage(`{"max":3}`))
	if err != nil || !within {
		t.Fatalf("agent max<=grant max with all keys present: expected (true, nil), got (%v, %v)", within, err)
	}
	// Agent carries a key the grant does not -> not within.
	within, err = ParamsWithinGrant(json.RawMessage(`{"max":5}`), json.RawMessage(`{"max":3,"junk":1}`))
	if err != nil || within {
		t.Fatalf("agent extra key junk: expected (false, nil), got (%v, %v)", within, err)
	}
}

// L2: nested duplicate JSON keys must be rejected (the duplicate-key detection
// must be recursive over params objects).
func TestDuplicateJSONKeysNestedL2(t *testing.T) {
	if !hasDuplicateJSONKeys([]byte(`{"cap":{"p":{"max":1,"max":2}}}`)) {
		t.Fatal("nested duplicate key max not detected")
	}
	if hasDuplicateJSONKeys([]byte(`{"cap":{"p":{"max":1,"min":2}}}`)) {
		t.Fatal("no duplicate key but reported duplicate")
	}
}

// L3: evalMaxConcurrent must enforce the upper bound and require a plain object.
func TestEvalMaxConcurrentBoundsL3(t *testing.T) {
	base := RequestContext{ConcurrentCount: 1}
	cases := []struct {
		params string
		wantOK bool
	}{
		{`{"max":5}`, true},
		{`{"max":5000}`, false},       // above MaxConcurrentMax
		{`{"max":0}`, false},          // below MaxConcurrentMin
		{`{"max":5,"junk":1}`, false}, // unknown field
		{`5`, false},                  // scalar
		{`[1,2]`, false},              // array
		{`"5"`, false},                // string
		{`{"max":1}`, false},          // count(1) >= 1 -> exceeds max
		{`{"max":2}`, true},           // count(1) < 2 -> within
	}
	for _, c := range cases {
		cb := Capability{Params: json.RawMessage(c.params)}
		err := evalMaxConcurrent(cb, base)
		if (err == nil) != c.wantOK {
			t.Errorf("params=%s: wantOK=%v err=%v", c.params, c.wantOK, err)
		}
	}
	// count == max must fail.
	if err := evalMaxConcurrent(Capability{Params: json.RawMessage(`{"max":1}`)}, RequestContext{ConcurrentCount: 1}); err == nil {
		t.Fatal("count==max should exceed max")
	}
}

// L6: ValidateDA must reject a DA whose timestamp is older than its requested
// lifetime (stale/replay), even when the nonce is fresh.
func TestValidateDARejectsStaleL6(t *testing.T) {
	env := newTestEnv(t)
	tok, _ := buildDA(t, env, ModeAuthorized, []Capability{{Scheme: "database", ID: "query:SELECT"}}, func(d *DAClaims) {
		// Timestamp 2h in the past, RequestedLifetime stays 3600s.  With the
		// canonical exp = ts + requested_lifetime this DA is expired and must
		// be rejected even when the nonce is fresh.
		d.TS = time.Now().Add(-2 * time.Hour).Unix()
		d.Iat = d.TS
		d.Exp = d.TS + int64(d.RequestedLifetime)
	})
	_, err := ValidateDA(tok, VerifyOptions{
		PrincipalJWKS: map[string]crypto.PublicKey{"principal-1": &env.principalKey.PublicKey},
		NonceStore:    NewMemNonceStore(),
	})
	if err == nil {
		t.Fatal("expected stale DA rejection")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired/stale error, got: %v", err)
	}
}

// L5: a pattern with many '**' wildcards must not cause exponential
// backtracking (memoized matcher). Result must be identical to the naive
// matcher; the assertion here is that it terminates and is correct.
func TestMatchTokensNoBacktrackingBlowupL5(t *testing.T) {
	// Build a pattern that previously forced exponential ** backtracking:
	// many '**' segments vs a long non-matching target.
	pattern := "a:b" + strings.Repeat(":**", 24) + ":zzz_no_match"
	target := "a:b:c:d:e:f:g:h:i:j:k:l:m:n:o:p:q:r:s:t:u:v:w:x:y:z:0:1:2:3:4:5:6:7:8:9"
	if matchTokens(tokenize(strings.Split(pattern, ":")), tokenize(strings.Split(target, ":"))) {
		t.Fatal("pathological ** pattern unexpectedly matched")
	}
	// A matching case must still return true under the memoized matcher.
	ok := "db:**"
	if !matchTokens(tokenize(strings.Split(ok, ":")), tokenize(strings.Split("db:query:select", ":"))) {
		t.Fatal("memoized matcher regressed a legitimate ** match")
	}
}
