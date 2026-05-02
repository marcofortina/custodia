package audit

import (
	"testing"
	"time"

	"custodia/internal/model"
)

func TestVerifyChainAcceptsLinkedAuditEvents(t *testing.T) {
	first := model.AuditEvent{EventID: "evt-1", OccurredAt: time.Unix(1, 0).UTC(), Action: "secret.create", ResourceType: "secret", Outcome: "success"}
	first.EventHash = ComputeHash(nil, first)
	second := model.AuditEvent{EventID: "evt-2", OccurredAt: time.Unix(2, 0).UTC(), Action: "secret.read", ResourceType: "secret", Outcome: "success", PreviousHash: first.EventHash}
	second.EventHash = ComputeHash(second.PreviousHash, second)

	result := VerifyChain([]model.AuditEvent{first, second})
	if !result.Valid {
		t.Fatalf("expected valid audit chain, got %#v", result)
	}
	if result.VerifiedEvents != 2 || result.HeadHash == "" {
		t.Fatalf("unexpected verification result: %#v", result)
	}
}

func TestVerifyChainRejectsTamperedAuditEvents(t *testing.T) {
	event := model.AuditEvent{EventID: "evt-1", OccurredAt: time.Unix(1, 0).UTC(), Action: "secret.create", ResourceType: "secret", Outcome: "success"}
	event.EventHash = ComputeHash(nil, event)
	event.Action = "secret.delete"

	result := VerifyChain([]model.AuditEvent{event})
	if result.Valid {
		t.Fatal("expected tampered audit chain to be invalid")
	}
	if result.FailureReason != "event_hash_mismatch" {
		t.Fatalf("unexpected failure reason: %#v", result)
	}
}
