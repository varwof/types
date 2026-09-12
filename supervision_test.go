package pki_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// va66Hex is a valid 64-character lowercase hexadecimal da_hash.
const vlda64Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validSupervisionEvent() *pki.SupervisionEvent {
	return &pki.SupervisionEvent{
		Type:        pki.SupervisionConsent,
		Source:      "user-signer",
		OperationID: "op-0001",
		DaHash:      vlda64Hex,
		AgentID:     "agent:db-analyst-01",
		Actor:       "zhangsan",
		Reason:      "scheduled analysis approved",
		EvidenceRef: "ev-0001",
		Decision:    pki.SupervisionDecisionApproved,
		Ts:          time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC),
	}
}

func TestSupervisionEventTypesValid(t *testing.T) {
	for _, etype := range []pki.SupervisionEventType{
		pki.SupervisionConsent,
		pki.SupervisionDenied,
		pki.SupervisionStepUp,
		pki.SupervisionApproval,
		pki.SupervisionBreakGlass,
		pki.SupervisionOverride,
	} {
		if !etype.Valid() {
			t.Errorf("%q.Valid() = false, want true", etype)
		}
	}
	for _, bad := range []pki.SupervisionEventType{"", "unknown", "CONSENT", "approve"} {
		if bad.Valid() {
			t.Errorf("%q.Valid() = true, want false", bad)
		}
	}
}

func TestValidateSupervisionEventOK(t *testing.T) {
	if err := pki.ValidateSupervisionEvent(validSupervisionEvent()); err != nil {
		t.Fatalf("validate full event: %v", err)
	}

	// Minimal event: only required fields, optional DaHash left empty.
	min := &pki.SupervisionEvent{
		Type:     pki.SupervisionDenied,
		Source:   "aic-verifier",
		Actor:    "lisi",
		Decision: pki.SupervisionDecisionDenied,
		Ts:       time.Now().UTC(),
	}
	if err := pki.ValidateSupervisionEvent(min); err != nil {
		t.Fatalf("validate minimal event: %v", err)
	}
}

func TestValidateSupervisionEventErrors(t *testing.T) {
	base := validSupervisionEvent()

	overlong := func(s string, n int) string {
		if len(s) >= n {
			return s
		}
		return strings.Repeat(s, n/len(s)+1)[:n]
	}

	cases := []struct {
		name    string
		mutate  func(*pki.SupervisionEvent)
		wantSub string
	}{
		{"empty type", func(e *pki.SupervisionEvent) { e.Type = "" }, "invalid type"},
		{"unknown type", func(e *pki.SupervisionEvent) { e.Type = "watchdog" }, "invalid type"},
		{"empty source", func(e *pki.SupervisionEvent) { e.Source = "" }, "source is required"},
		{"long source", func(e *pki.SupervisionEvent) { e.Source = overlong("s", 65) }, "source length"},
		{"empty actor", func(e *pki.SupervisionEvent) { e.Actor = "" }, "actor is required"},
		{"long actor", func(e *pki.SupervisionEvent) { e.Actor = overlong("a", 129) }, "actor length"},
		{"long reason", func(e *pki.SupervisionEvent) { e.Reason = overlong("r", 513) }, "reason length"},
		{"invalid decision", func(e *pki.SupervisionEvent) { e.Decision = "approved-extra" }, "invalid decision"},
		{"da hash non-hex", func(e *pki.SupervisionEvent) { e.DaHash = strings.Repeat("z", 64) }, "da_hash"},
		{"da hash short", func(e *pki.SupervisionEvent) { e.DaHash = "abc" }, "da_hash"},
		{"da hash uppercase", func(e *pki.SupervisionEvent) { e.DaHash = strings.Repeat("A", 64) }, "da_hash"},
		{"zero ts", func(e *pki.SupervisionEvent) { e.Ts = time.Time{} }, "ts"},
		{"long operation_id", func(e *pki.SupervisionEvent) { e.OperationID = overlong("o", 129) }, "operation_id"},
		{"long agent_id", func(e *pki.SupervisionEvent) { e.AgentID = overlong("g", 257) }, "agent_id"},
		{"long evidence_ref", func(e *pki.SupervisionEvent) { e.EvidenceRef = overlong("e", 257) }, "evidence_ref"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := *base
			tc.mutate(&e)
			err := pki.ValidateSupervisionEvent(&e)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}

	// The nil case is separate because the mutate func receives a copy of base.
	if err := pki.ValidateSupervisionEvent(nil); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("nil event: err = %v", err)
	}
}

func TestSupervisionEventJSONOmitEmpty(t *testing.T) {
	min := &pki.SupervisionEvent{
		Type:     pki.SupervisionBreakGlass,
		Source:   "admin-console",
		Actor:    "wangwu",
		Decision: pki.SupervisionDecisionApproved,
		Ts:       time.Now().UTC(),
	}
	der, err := json.Marshal(min)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"operation_id"`, `"da_hash"`, `"agent_id"`, `"evidence_ref"`} {
		if strings.Contains(string(der), k) {
			t.Errorf("optional field %s should be omitted when empty, got %s", k, der)
		}
	}

	var back pki.SupervisionEvent
	if err := json.Unmarshal(der, &back); err != nil {
		t.Fatal(err)
	}
	if back.Type != min.Type || back.Source != min.Source || back.Actor != min.Actor ||
		back.Decision != min.Decision || back.OperationID != "" || back.DaHash != "" ||
		back.AgentID != "" || back.EvidenceRef != "" {
		t.Fatalf("round-trip mismatch: %+v vs %+v", back, *min)
	}
}

func TestSupervisionEventJSONRoundTrip(t *testing.T) {
	full := validSupervisionEvent()
	der, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var back pki.SupervisionEvent
	if err := json.Unmarshal(der, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, *full) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v\njson %s", back, *full, der)
	}
}
