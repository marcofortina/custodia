package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"custodia/internal/audit"
	"custodia/internal/model"
	"custodia/internal/ratelimit"
)

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Health(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable")
		return
	}
	if checker, ok := s.limiter.(ratelimit.HealthChecker); ok {
		if err := checker.Health(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "rate_limiter_unavailable")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleWeb(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Custodia</title></head>
<body>
<h1>Custodia metadata console</h1>
<p>Phase 1 web surface is metadata-only and requires an authenticated admin subject. The vault never decrypts or manages client-side encryption keys.</p>
</body>
</html>`))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	storeStatus := "ok"
	if err := s.store.Health(r.Context()); err != nil {
		storeStatus = "unavailable"
	}
	rateLimiterStatus := "ok"
	if checker, ok := s.limiter.(ratelimit.HealthChecker); ok {
		if err := checker.Health(r.Context()); err != nil {
			rateLimiterStatus = "unavailable"
		}
	}
	outcome := "success"
	if storeStatus != "ok" || rateLimiterStatus != "ok" {
		outcome = "degraded"
	}
	s.audit(r, "status.read", "system", "", outcome, nil)
	writeJSON(w, http.StatusOK, model.OperationalStatus{
		Status:                outcome,
		Store:                 storeStatus,
		RateLimiter:           rateLimiterStatus,
		MaxEnvelopesPerSecret: s.maxEnvelopesPerSecret,
		ClientRateLimitPerSec: s.clientRateLimit,
		GlobalRateLimitPerSec: s.globalRateLimit,
		IPRateLimitPerSec:     s.ipRateLimit,
	})
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		s.auditStoreFailure(r, "client.list", "client", "", err)
		writeMappedError(w, err)
		return
	}
	if rawActive := strings.TrimSpace(r.URL.Query().Get("active")); rawActive != "" {
		active, ok := parseBoolQuery(rawActive)
		if !ok {
			s.auditFailure(r, "client.list", "client", "", map[string]string{"reason": "invalid_active_filter"})
			writeError(w, http.StatusBadRequest, "invalid_active_filter")
			return
		}
		filtered := clients[:0]
		for _, client := range clients {
			if client.IsActive == active {
				filtered = append(filtered, client)
			}
		}
		clients = filtered
	}
	s.audit(r, "client.list", "client", "", "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	client, err := s.store.GetClient(r.Context(), clientID)
	if err != nil {
		s.auditStoreFailure(r, "client.read", "client", clientID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "client.read", "client", clientID, "success", nil)
	writeJSON(w, http.StatusOK, client)
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req model.CreateClientRequest
	if !decodeJSON(w, r, &req) {
		s.auditFailure(r, "client.create", "client", "", map[string]string{"reason": "invalid_json"})
		return
	}
	client := model.Client{ClientID: req.ClientID, MTLSSubject: req.MTLSSubject}
	if err := s.store.CreateClient(r.Context(), client); err != nil {
		s.auditStoreFailure(r, "client.create", "client", req.ClientID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "client.create", "client", req.ClientID, "success", nil)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "client_id": req.ClientID})
}

func (s *Server) handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	var req model.RevokeClientRequest
	if !decodeJSON(w, r, &req) {
		s.auditFailure(r, "client.revoke", "client", "", map[string]string{"reason": "invalid_json"})
		return
	}
	if err := s.store.RevokeClient(r.Context(), req.ClientID); err != nil {
		s.auditStoreFailure(r, "client.revoke", "client", req.ClientID, err)
		writeMappedError(w, err)
		return
	}
	metadata, _ := json.Marshal(map[string]string{"reason": strings.TrimSpace(req.Reason)})
	s.audit(r, "client.revoke", "client", req.ClientID, "success", metadata)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 || parsed > 500 {
			s.auditFailure(r, "audit.list", "audit_event", "", map[string]string{"reason": "invalid_limit"})
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = parsed
	}
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	if err != nil {
		s.auditStoreFailure(r, "audit.list", "audit_event", "", err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "audit.list", "audit_event", "", "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"audit_events": events})
}

func (s *Server) handleExportAuditEvents(w http.ResponseWriter, r *http.Request) {
	limit := 500
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 || parsed > 500 {
			s.auditFailure(r, "audit.export", "audit_event", "", map[string]string{"reason": "invalid_limit"})
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = parsed
	}
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	if err != nil {
		s.auditStoreFailure(r, "audit.export", "audit_event", "", err)
		writeMappedError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	encoder := json.NewEncoder(w)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return
		}
	}
	s.audit(r, "audit.export", "audit_event", "", "success", nil)
}

func (s *Server) handleVerifyAuditEvents(w http.ResponseWriter, r *http.Request) {
	limit := 500
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 || parsed > 500 {
			s.auditFailure(r, "audit.verify", "audit_event", "", map[string]string{"reason": "invalid_limit"})
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = parsed
	}
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	if err != nil {
		s.auditStoreFailure(r, "audit.verify", "audit_event", "", err)
		writeMappedError(w, err)
		return
	}
	result := audit.VerifyChain(events)
	outcome := "success"
	if !result.Valid {
		outcome = "failure"
	}
	metadata, _ := json.Marshal(map[string]any{"valid": result.Valid, "verified_events": result.VerifiedEvents})
	s.audit(r, "audit.verify", "audit_event", "", outcome, metadata)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	var req model.CreateSecretRequest
	if !decodeJSON(w, r, &req) {
		s.auditFailure(r, "secret.create", "secret", "", map[string]string{"reason": "invalid_json"})
		return
	}
	if len(req.Envelopes) > s.maxEnvelopesPerSecret {
		s.auditFailure(r, "secret.create", "secret", "", map[string]string{"reason": "too_many_envelopes"})
		writeError(w, http.StatusRequestEntityTooLarge, "too_many_envelopes")
		return
	}
	ref, err := s.store.CreateSecret(r.Context(), clientIDFromContext(r), req)
	if err != nil {
		s.auditStoreFailure(r, "secret.create", "secret", "", err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.create", "secret", ref.SecretID, "success", nil)
	writeJSON(w, http.StatusCreated, ref)
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	secrets, err := s.store.ListSecrets(r.Context(), clientIDFromContext(r))
	if err != nil {
		s.auditStoreFailure(r, "secret.list", "secret", "", err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.list", "secret", "", "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"secrets": secrets})
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	response, err := s.store.GetSecret(r.Context(), clientIDFromContext(r), secretID)
	if err != nil {
		s.auditStoreFailure(r, "secret.read", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.read", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleListSecretVersions(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	versions, err := s.store.ListSecretVersions(r.Context(), clientIDFromContext(r), secretID)
	if err != nil {
		s.auditStoreFailure(r, "secret.version_list", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.version_list", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

func (s *Server) handleListSecretAccess(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	accesses, err := s.store.ListSecretAccess(r.Context(), clientIDFromContext(r), secretID)
	if err != nil {
		s.auditStoreFailure(r, "secret.access_list", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.access_list", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"access": accesses})
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	if err := s.store.DeleteSecret(r.Context(), clientIDFromContext(r), secretID); err != nil {
		s.auditStoreFailure(r, "secret.delete", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.delete", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleShareSecret(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	var req model.ShareSecretRequest
	if !decodeJSON(w, r, &req) {
		s.auditFailure(r, "secret.share", "secret", secretID, map[string]string{"reason": "invalid_json"})
		return
	}
	if err := s.store.ShareSecret(r.Context(), clientIDFromContext(r), secretID, req); err != nil {
		s.auditStoreFailure(r, "secret.share", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.share", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "shared"})
}

func (s *Server) handleRequestAccessGrant(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	var req model.AccessGrantRequest
	if !decodeJSON(w, r, &req) {
		s.auditFailure(r, "secret.access_request", "secret", secretID, map[string]string{"reason": "invalid_json"})
		return
	}
	ref, err := s.store.RequestAccessGrant(r.Context(), clientIDFromContext(r), secretID, req)
	if err != nil {
		s.auditStoreFailure(r, "secret.access_request", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.access_request", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusCreated, ref)
}

func (s *Server) handleListAccessGrantRequests(w http.ResponseWriter, r *http.Request) {
	secretID := strings.TrimSpace(r.URL.Query().Get("secret_id"))
	requests, err := s.store.ListAccessGrantRequests(r.Context(), secretID)
	if err != nil {
		s.auditStoreFailure(r, "secret.access_request_list", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		if !validAccessRequestStatus(status) {
			s.auditFailure(r, "secret.access_request_list", "secret", secretID, map[string]string{"reason": "invalid_status_filter"})
			writeError(w, http.StatusBadRequest, "invalid_status_filter")
			return
		}
		filtered := requests[:0]
		for _, request := range requests {
			if request.Status == status {
				filtered = append(filtered, request)
			}
		}
		requests = filtered
	}
	s.audit(r, "secret.access_request_list", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"access_requests": requests})
}

func (s *Server) handleActivateAccessGrant(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	targetClientID := r.PathValue("client_id")
	var req model.ActivateAccessRequest
	if !decodeJSON(w, r, &req) {
		s.auditFailure(r, "secret.access_activate", "secret", secretID, map[string]string{"reason": "invalid_json"})
		return
	}
	if err := s.store.ActivateAccessGrant(r.Context(), clientIDFromContext(r), secretID, targetClientID, req); err != nil {
		s.auditStoreFailure(r, "secret.access_activate", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.access_activate", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "activated"})
}

func (s *Server) handleRevokeAccess(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	targetClientID := r.PathValue("client_id")
	if err := s.store.RevokeAccess(r.Context(), clientIDFromContext(r), secretID, targetClientID); err != nil {
		s.auditStoreFailure(r, "secret.access_revoke", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.access_revoke", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleCreateSecretVersion(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("secret_id")
	var req model.CreateSecretVersionRequest
	if !decodeJSON(w, r, &req) {
		s.auditFailure(r, "secret.version_create", "secret", secretID, map[string]string{"reason": "invalid_json"})
		return
	}
	if len(req.Envelopes) > s.maxEnvelopesPerSecret {
		s.auditFailure(r, "secret.version_create", "secret", secretID, map[string]string{"reason": "too_many_envelopes"})
		writeError(w, http.StatusRequestEntityTooLarge, "too_many_envelopes")
		return
	}
	ref, err := s.store.CreateSecretVersion(r.Context(), clientIDFromContext(r), secretID, req)
	if err != nil {
		s.auditStoreFailure(r, "secret.version_create", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.version_create", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusCreated, ref)
}

func validAccessRequestStatus(value string) bool {
	switch value {
	case "pending", "activated", "revoked", "expired":
		return true
	default:
		return false
	}
}

func parseBoolQuery(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes":
		return true, true
	case "false", "0", "no":
		return false, true
	default:
		return false, false
	}
}

const maxJSONBodyBytes = 1 << 20

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if errors.As(err, new(*http.MaxBytesError)) {
			writeError(w, http.StatusRequestEntityTooLarge, "json_body_too_large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}
