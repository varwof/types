// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Copyright 2026 Jijie Wei
// SPDX-License-Identifier: Apache-2.0

// Command aic is a small CLI for the Varwof AIC protocol core.
//
// It provides certificate inspection (AIC / PrincipalAuthorization
// extension parsing), capability matching, and SPKI key hash computation.
// It has no dependencies beyond the standard library and the varwof/types package.
package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	pki "github.com/varwof/types"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "parse":
		err = cmdParse(os.Args[2:])
	case "match":
		err = cmdMatch(os.Args[2:])
	case "fingerprint":
		err = cmdFingerprint(os.Args[2:])
	case "version":
		fmt.Println(pki.Version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "aic:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`Usage: aic <command> [args]

Commands:
  parse <cert.pem|cert.der>   Parse and display the AIC and
                              PrincipalAuthorization extensions of a
                              certificate.
  match <id> <pattern>        Test a capability identifier against a
                              glob pattern; prints match result and
                              priority.
  fingerprint <cert> [algo]   Compute the SPKI key hash of a
                              certificate. algo is one of:
                              ` + strings.Join(pki.SupportedHashAlgos(), ", ") + `
                              (default: sha256).
  version                     Print the library version.
  help                        Show this help.`)
}

func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}
	return cert, nil
}

func cmdParse(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: aic parse <cert.pem|cert.der>")
	}
	cert, err := loadCert(args[0])
	if err != nil {
		return err
	}
	aic, err := pki.ParseAIC(cert)
	if err != nil {
		return fmt.Errorf("parse AIC: %w", err)
	}
	if aic == nil {
		fmt.Println("no AIC extension found")
	} else {
		fmt.Printf("AIC:\n")
		fmt.Printf("  version:          %d\n", aic.Version)
		fmt.Printf("  agentId:          %s\n", aic.AgentId)
		fmt.Printf("  principalUid:     %s\n", aic.Principal())
		fmt.Printf("  delegationMode:   %d\n", aic.DelegationMode)
		fmt.Printf("  capabilities:     %d\n", len(aic.Capabilities))
		for _, c := range aic.Capabilities {
			fmt.Printf("    - %s\n", c.FullID())
		}
		fmt.Printf("  constraints:      %d\n", len(aic.AuthorizationConstraints))
		if aic.DelegationAuthorization.IsPresent() {
			da := aic.DelegationAuthorization
			fmt.Printf("  delegationAuth:   reason=%s/%s lifetime=%d\n",
				da.Reason.ReasonCode, da.Reason.Description, da.RequestedLifetime)
		}
	}
	pa, err := pki.ParseUserPermissionExtension(cert)
	if err != nil {
		return fmt.Errorf("parse PrincipalAuthorization: %w", err)
	}
	if pa != nil {
		fmt.Printf("PrincipalAuthorization:\n")
		fmt.Printf("  grants: %d\n", len(pa.Grants))
		for _, g := range pa.Grants {
			fmt.Printf("    - %s\n", g.FullID())
		}
	}
	return nil
}

func cmdMatch(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: aic match <id> <pattern>")
	}
	id, pattern := args[0], args[1]
	ok := pki.MatchCapability(id, pattern)
	fmt.Printf("match(%q, %q) = %v\n", id, pattern, ok)
	if !ok {
		return nil
	}
	p := pki.MatchCapabilityPriority(id, pattern)
	fmt.Printf("priority: %s\n", pki.MatchCapabilityPriorityString(p))
	return nil
}

func cmdFingerprint(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: aic fingerprint <cert> [algo]")
	}
	cert, err := loadCert(args[0])
	if err != nil {
		return err
	}
	algo := pki.DefaultHashAlgo()
	if len(args) == 2 {
		algo, err = pki.ParseHashAlgo(args[1])
		if err != nil {
			return err
		}
	}
	kh, err := pki.KeyHashFromCertSPKI(algo, cert)
	if err != nil {
		return err
	}
	fmt.Printf("algo:  %s\n", pki.HashOIDName(algo))
	fmt.Printf("hash:  %s\n", hex.EncodeToString(kh))
	return nil
}
