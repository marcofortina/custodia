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

func writeMappedError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "invalid_input")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, store.ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error")
	}
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
		Metadata:      metadata,
	})
}
