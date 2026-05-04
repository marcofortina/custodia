// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package audit

import (
	"crypto/sha256"
	"encoding/json"

	"custodia/internal/model"
)

// hashableEvent is the canonical audit hash payload. Only stable, intentional
// fields are included so verification stays reproducible across stores/exporters.
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

// ComputeHash links each event to the previous event hash. The timestamp format is
// fixed to nanosecond UTC to avoid locale or database-driver drift.
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
