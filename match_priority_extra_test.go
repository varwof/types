// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"testing"

	pki "github.com/varwof/types"
)

func TestMatchCapabilityPriorityString(t *testing.T) {
	tests := []struct {
		p    int
		want string
	}{
		{pki.MatchPriorityNoMatch, "no-match"},
		{pki.MatchPriorityGlobal, "global"},
		{pki.MatchPriorityScheme, "scheme"},
		{pki.MatchPriorityMulti, "multi-segment"},
		{pki.MatchPrioritySingle, "single-segment"},
		{pki.MatchPriorityExact, "exact"},
		{99, "unknown(99)"},
	}
	for _, tt := range tests {
		got := pki.MatchCapabilityPriorityString(tt.p)
		if got != tt.want {
			t.Errorf("MatchCapabilityPriorityString(%d) = %q, want %q", tt.p, got, tt.want)
		}
	}
}
