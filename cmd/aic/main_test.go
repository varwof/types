// Copyright 2026 Jijie Wei
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

func writeCert(t *testing.T, dir, name string, cert *x509.Certificate, pemFmt bool) string {
	t.Helper()
	path := filepath.Join(dir, name)
	var data []byte
	if pemFmt {
		data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	} else {
		data = cert.Raw
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func certWithExtensions(t *testing.T, exts []pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "cli-test"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: exts,
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

func capturedStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func buildAICExt(t *testing.T) pkix.Extension {
	t.Helper()
	aic := pki.AIC{
		Version:      1,
		AgentId:      "agent:cli-01",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:admin"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "AUTO_RENEWAL", Description: "cli test"},
			Timestamp:          time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{1},
		},
	}
	val, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: pki.OIDAIC, Value: val}
}

func buildPAExt(t *testing.T) pkix.Extension {
	t.Helper()
	pa := pki.PrincipalAuthorization{
		Version: 1,
		Grants:  []pki.Capability{{CapabilityId: "gateway:admin"}},
	}
	val, err := asn1.Marshal(pa)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: pki.OIDPrincipalAuthorization, Value: val}
}

func TestCmdMatch(t *testing.T) {
	if err := cmdMatch([]string{"query:*", "query:SELECT"}); err != nil {
		t.Fatalf("match: %v", err)
	}
	out := capturedStdout(t, func() {
		if err := cmdMatch([]string{"scheme:id", "scheme:*"}); err != nil {
			t.Fatalf("match: %v", err)
		}
	})
	if !strings.Contains(out, "priority:") {
		t.Fatalf("expected priority line, got: %s", out)
	}
	if err := cmdMatch([]string{"only-one"}); err == nil {
		t.Fatal("expected usage error for 1 arg")
	}
}

func TestCmdFingerprint(t *testing.T) {
	dir := t.TempDir()
	cert := certWithExtensions(t, nil)

	t.Run("default sha256", func(t *testing.T) {
		path := writeCert(t, dir, "c.pem", cert, true)
		out := capturedStdout(t, func() {
			if err := cmdFingerprint([]string{path}); err != nil {
				t.Fatalf("fingerprint: %v", err)
			}
		})
		if !strings.Contains(out, "algo:") || !strings.Contains(out, "hash:") {
			t.Fatalf("unexpected output: %s", out)
		}
	})

	t.Run("explicit sha384", func(t *testing.T) {
		path := writeCert(t, dir, "c2.der", cert, false)
		out := capturedStdout(t, func() {
			if err := cmdFingerprint([]string{path, "sha384"}); err != nil {
				t.Fatalf("fingerprint: %v", err)
			}
		})
		if !strings.Contains(out, "sha384") {
			t.Fatalf("expected sha384 output: %s", out)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if err := cmdFingerprint([]string{filepath.Join(dir, "nope.pem")}); err == nil {
			t.Fatal("expected read error")
		}
	})

	t.Run("bad algo", func(t *testing.T) {
		path := writeCert(t, dir, "c3.pem", cert, true)
		if err := cmdFingerprint([]string{path, "md5"}); err == nil {
			t.Fatal("expected unsupported algo error")
		}
	})

	t.Run("wrong arg count", func(t *testing.T) {
		if err := cmdFingerprint([]string{}); err == nil {
			t.Fatal("expected usage error")
		}
	})
}

func TestCmdParse(t *testing.T) {
	dir := t.TempDir()

	t.Run("cert with AIC and PA", func(t *testing.T) {
		cert := certWithExtensions(t, []pkix.Extension{buildAICExt(t), buildPAExt(t)})
		path := writeCert(t, dir, "a.pem", cert, true)
		out := capturedStdout(t, func() {
			if err := cmdParse([]string{path}); err != nil {
				t.Fatalf("parse: %v", err)
			}
		})
		if !strings.Contains(out, "AIC:") || !strings.Contains(out, "PrincipalAuthorization:") {
			t.Fatalf("unexpected output: %s", out)
		}
		if !strings.Contains(out, "agent:cli-01") {
			t.Fatalf("expected agentId in output: %s", out)
		}
	})

	t.Run("cert without extensions", func(t *testing.T) {
		cert := certWithExtensions(t, nil)
		path := writeCert(t, dir, "b.pem", cert, true)
		out := capturedStdout(t, func() {
			if err := cmdParse([]string{path}); err != nil {
				t.Fatalf("parse: %v", err)
			}
		})
		if !strings.Contains(out, "no AIC extension found") {
			t.Fatalf("unexpected output: %s", out)
		}
	})

	t.Run("malformed cert file", func(t *testing.T) {
		path := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(path, []byte("not a cert"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cmdParse([]string{path}); err == nil {
			t.Fatal("expected parse error")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if err := cmdParse([]string{filepath.Join(dir, "nope")}); err == nil {
			t.Fatal("expected read error")
		}
	})

	t.Run("wrong arg count", func(t *testing.T) {
		if err := cmdParse([]string{}); err == nil {
			t.Fatal("expected usage error")
		}
		if err := cmdParse([]string{"a", "b"}); err == nil {
			t.Fatal("expected usage error")
		}
	})
}

func TestLoadCert(t *testing.T) {
	dir := t.TempDir()
	cert := certWithExtensions(t, nil)
	pathPEM := writeCert(t, dir, "p.pem", cert, true)
	pathDER := writeCert(t, dir, "d.der", cert, false)

	got, err := loadCert(pathPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject.CommonName != "cli-test" {
		t.Fatalf("got CN %q", got.Subject.CommonName)
	}
	if _, err := loadCert(pathDER); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCert(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected read error")
	}

	badPath := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(badPath, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCert(badPath); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestUsageSmoke(t *testing.T) {
	out := capturedStdout(t, usage)
	for _, want := range []string{"parse", "match", "fingerprint", "version"} {
		if !strings.Contains(out, want) {
			t.Fatalf("usage missing %q", want)
		}
	}
}

// TestMainDispatch exercises `main()` by re-executing the test binary as
// the CLI, covering the version/help/unknown-command branches.
func TestMainDispatch(t *testing.T) {
	cases := []struct {
		args []string
		want string
		code int
	}{
		{[]string{"version"}, pki.Version + "\n", 0},
		{[]string{"--help"}, "Usage: aic", 0},
		{[]string{"help"}, "Usage: aic", 0},
		{[]string{"bogus"}, "Usage: aic", 2},
		{[]string{""}, "Usage: aic", 2},
	}
	for _, tc := range cases {
		name := strings.Join(tc.args, "_")
		if name == "" {
			name = "no_args"
		}
		t.Run(name, func(t *testing.T) {
			out, code := runMainAsSubprocess(t, tc.args...)
			if code != tc.code {
				t.Fatalf("expected exit %d, got %d (out=%q)", tc.code, code, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("expected %q in output, got: %q", tc.want, out)
			}
		})
	}
}

func runMainAsSubprocess(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "AIC_HELPER_PROCESS=1")
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			t.Fatalf("exec: %v", err)
		}
	}
	return string(out), code
}

func TestMain(m *testing.M) {
	if os.Getenv("AIC_HELPER_PROCESS") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}
