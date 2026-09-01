// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"encoding/asn1"
	"testing"
)

// TestCapabilityParamsJSONContainer verifies AIC capability and PA grant
// parameters must be JSON object/array containers (P0-2).
func TestCapabilityParamsJSONContainer(t *testing.T) {
	base := func() *AIC {
		return &AIC{
			Version:      1,
			AgentId:      "agent-1",
			PrincipalUid: PrincipalUid{Realm: "r", Identifier: "p", KeyHash: make([]byte, 32)},
			Capabilities: []Capability{
				{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"},
			},
			DelegationAuthorization: DelegationAuthorization{
				Reason:             Reason{ReasonCode: "X", Description: "d"},
				RequestedLifetime:  3600,
				SignatureAlgorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
				SignatureValue:     []byte("sig"),
				Nonce:              make([]byte, 32),
			},
		}
	}

	good := base()
	good.Capabilities[0].Parameters = []byte(`{"tables":["customers"],"limit":{"max":500}}`)
	if err := ValidateAIC(good); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}

	bad := base()
	bad.Capabilities[0].Parameters = []byte(`500`)
	if err := ValidateAIC(bad); err == nil {
		t.Fatal("scalar capability params must be rejected")
	}

	pa := &PrincipalAuthorization{
		Version: 1,
		Grants: []Capability{
			{SchemeId: "std/database-v1", CapabilityId: "query:SELECT",
				Parameters: []byte(`"x"`)},
		},
	}
	if err := ValidatePrincipalAuthorization(pa); err == nil {
		t.Fatal("scalar PA grant params must be rejected")
	}
}
