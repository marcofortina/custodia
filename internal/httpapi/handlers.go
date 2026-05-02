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
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                    outcome,
		"store":                     storeStatus,
		"rate_limiter":              rateLimiterStatus,
		"max_envelopes_per_secret":  s.maxEnvelopesPerSecret,
		"client_rate_limit_per_sec": s.clientRateLimit,
		"global_rate_limit_per_sec": s.globalRateLimit,
	})
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		s.auditStoreFailure(r, "client.list", "client", "", err)
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
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
