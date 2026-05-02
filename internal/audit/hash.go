package audit

import (
	"crypto/sha256"
	"encoding/json"

	"custodia/internal/model"
)

type hashableEvent struct {
	EventID       string          `json:"event_id"`
	OccurredAt    string          `json:"occurred_at"`
	ActorClientID string          `json:"actor_client_id,omitempty"`
	Action        string          `json:"action"`
	ResourceType  string          `json:"resource_type"`
	ResourceID    string          `json:"resource_id,omitempty"`
	Outcome       string          `json:"outcome"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	PreviousHash  []byte          `json:"previous_hash,omitempty"`
}

func ComputeHash(previous []byte, event model.AuditEvent) []byte {
	payload := hashableEvent{
		EventID:       event.EventID,
		OccurredAt:    event.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		ActorClientID: event.ActorClientID,
		Action:        event.Action,
		ResourceType:  event.ResourceType,
		ResourceID:    event.ResourceID,
		Outcome:       event.Outcome,
		Metadata:      event.Metadata,
		PreviousHash:  previous,
	}
	encoded, _ := json.Marshal(payload)
	hash := sha256.Sum256(encoded)
	return hash[:]
}
