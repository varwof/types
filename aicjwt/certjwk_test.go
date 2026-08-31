// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package aicjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func mkCert(t *testing.T, keyType string) (*x509.Certificate, any) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	var signer any
	switch keyType {
	case "ecdsa":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer = k
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		signer = k
	default:
		t.Fatalf("unknown key type %q", keyType)
	}
	ss := signer.(crypto.Signer)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, ss.Public(), ss)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, signer
}

func TestCertToJWKRSAAndEC(t *testing.T) {
	for _, kt := range []string{"ecdsa", "rsa"} {
		cert, _ := mkCert(t, kt)
		j, err := CertToJWK(cert)
		if err != nil {
			t.Fatalf("%s CertToJWK: %v", kt, err)
		}
		if j.Kid == "" {
			t.Fatalf("%s: empty kid", kt)
		}
		want, err := SPKIHash(cert, "sha-256")
		if err != nil {
			t.Fatalf("SPKIHash: %v", err)
		}
		if j.Kid != want {
			t.Fatalf("%s kid = %q, want %q", kt, j.Kid, want)
		}
		if len(j.X5c) != 1 || j.X5t == "" || j.Use != "sig" {
			t.Fatalf("%s: bad x5c/x5t/use: %+v", kt, j)
		}
	}
}

func TestCertToJWKRoundTrip(t *testing.T) {
	cert, _ := mkCert(t, "rsa")
	j, err := CertToJWK(cert)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(j.X5c[0])
	if err != nil {
		t.Fatalf("x5c decode: %v", err)
	}
	c2, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x5c parse: %v", err)
	}
	r1 := cert.PublicKey.(*rsa.PublicKey)
	r2 := c2.PublicKey.(*rsa.PublicKey)
	if r1.N.Cmp(r2.N) != 0 || r1.E != r2.E {
		t.Fatal("x5c cert does not match original key")
	}
	alg, err := AlgForPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "RS256" {
		t.Fatalf("alg = %q, want RS256", alg)
	}
}

func TestBuildJWKS(t *testing.T) {
	c1, _ := mkCert(t, "ecdsa")
	c2, _ := mkCert(t, "rsa")
	ks, err := BuildJWKS([]*x509.Certificate{c1, c1, c2})
	if err != nil {
		t.Fatal(err)
	}
	if len(ks.Keys) != 2 {
		t.Fatalf("keys = %d, want 2 (dedupe)", len(ks.Keys))
	}
	b, err := BuildJWKSJSON([]*x509.Certificate{c1, c2})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct{ Keys []JWK }
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(parsed.Keys) != 2 {
		t.Fatalf("parsed keys = %d", len(parsed.Keys))
	}
}

func TestJWKThumbprintUnaffectedByMetadata(t *testing.T) {
	cert, _ := mkCert(t, "ecdsa")
	j, err := CertToJWK(cert)
	if err != nil {
		t.Fatal(err)
	}
	tp1, err := JWKThumbprint(j)
	if err != nil {
		t.Fatal(err)
	}
	tp2, err := JWKThumbprint(JWK{Kty: j.Kty, Crv: j.Crv, X: j.X, Y: j.Y})
	if err != nil {
		t.Fatal(err)
	}
	if tp1 != tp2 {
		t.Fatal("kid/x5c/x5t must not affect RFC 7638 thumbprint")
	}
}

func TestAlgForPublicKey(t *testing.T) {
	c1, _ := mkCert(t, "ecdsa")
	alg, err := AlgForPublicKey(c1.PublicKey)
	if err != nil || alg != "ES256" {
		t.Fatalf("ecdsa alg = %q, err=%v", alg, err)
	}
}
