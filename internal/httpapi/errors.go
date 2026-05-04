// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"custodia/internal/id"
	"custodia/internal/model"
	"custodia/internal/store"
)

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errorResponse{Error: code})
}

func writeRateLimited(w http.ResponseWriter, code string) {
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusTooManyRequests, code)
}

func writeMappedError(w http.ResponseWriter, err error) {
	status, code := mapStoreError(err)
	writeError(w, status, code)
}

func mapStoreError(err error) (int, string) {
	switch {
	case errors.Is(err, store.ErrInvalidInput):
		return http.StatusBadRequest, "invalid_input"
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, store.ErrForbidden):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, store.ErrConflict):
		return http.StatusConflict, "conflict"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func (s *Server) auditFailure(r *http.Request, action, resourceType, resourceID string, fields map[string]string) {
	metadata, _ := json.Marshal(fields)
	s.audit(r, action, resourceType, resourceID, "failure", metadata)
}

func (s *Server) auditStoreFailure(r *http.Request, action, resourceType, resourceID string, err error) {
	_, code := mapStoreError(err)
	s.auditFailure(r, action, resourceType, resourceID, map[string]string{"reason": code})
}

func enrichAuditMetadata(metadata json.RawMessage, requestID string) json.RawMessage {
	if requestID == "" {
		return metadata
	}
	fields := map[string]any{}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &fields); err != nil {
			fields = map[string]any{"metadata": string(metadata)}
		}
	}
	fields["request_id"] = requestID
	enriched, err := json.Marshal(fields)
	if err != nil {
		return metadata
	}
	return enriched
}

func (s *Server) audit(r *http.Request, action, resourceType, resourceID, outcome string, metadata json.RawMessage) {
	_ = s.store.AppendAudit(r.Context(), model.AuditEvent{
		EventID:       id.New(),
		OccurredAt:    time.Now().UTC(),
		ActorClientID: clientIDFromContext(r),
		Action:        action,
		ResourceType:  resourceType,
		ResourceID:    resourceID,
		Outcome:       outcome,
		Metadata:      enrichAuditMetadata(metadata, requestIDFromContext(r)),
	})
}
