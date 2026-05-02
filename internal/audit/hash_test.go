package audit

import (
	"bytes"
	"testing"
	"time"

	"custodia/internal/model"
)

func TestComputeHashDependsOnPreviousHash(t *testing.T) {
	event := model.AuditEvent{
		EventID:      "evt-1",
		OccurredAt:   time.Unix(10, 0).UTC(),
		Action:       "secret.read",
		ResourceType: "secret",
		Outcome:      "success",
	}

	first := ComputeHash(nil, event)
	second := ComputeHash([]byte("previous"), event)

	if bytes.Equal(first, second) {
		t.Fatal("expected previous hash to affect the audit event hash")
	}
}
