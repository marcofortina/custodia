package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"custodia/internal/audit"
	"custodia/internal/build"
	"custodia/internal/model"
	"custodia/internal/ratelimit"
)

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleLive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "live"})
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
	body := "<h1>Custodia metadata console</h1>" +
		webParagraph("The web console is metadata-only and requires an authenticated admin subject.") +
		webParagraph("The vault never decrypts secrets and never manages client-side encryption keys.")
	writeWebPage(w, "Metadata console", body)
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
		StoreBackend:          s.storeBackend,
		RateLimiter:           rateLimiterStatus,
		RateLimitBackend:      s.rateLimitBackend,
		MaxEnvelopesPerSecret: s.maxEnvelopesPerSecret,
		ClientRateLimitPerSec: s.clientRateLimit,
		GlobalRateLimitPerSec: s.globalRateLimit,
		IPRateLimitPerSec:     s.ipRateLimit,
		Build:                 model.BuildInfo(build.Current()),
		WebMFARequired:        s.webMFARequired,
		WebPasskeyEnabled:     s.webPasskeyEnabled,
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	s.audit(r, "version.read", "system", "", "success", nil)
	writeJSON(w, http.StatusOK, model.BuildInfo(build.Current()))
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	diagnostics := model.RuntimeDiagnostics{
		StartedAt:       s.startedAt,
		UptimeSeconds:   int64(time.Since(s.startedAt).Seconds()),
		Goroutines:      runtime.NumGoroutine(),
		AllocBytes:      mem.Alloc,
		TotalAllocBytes: mem.TotalAlloc,
		SysBytes:        mem.Sys,
	}
	s.audit(r, "diagnostics.read", "system", "", "success", nil)
	writeJSON(w, http.StatusOK, diagnostics)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	clientID := clientIDFromContext(r)
	client, err := s.store.GetClient(r.Context(), clientID)
	if err != nil {
		s.auditStoreFailure(r, "client.me", "client", clientID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "client.me", "client", clientID, "success", nil)
	writeJSON(w, http.StatusOK, client)
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	limit, ok := s.optionalLimit(w, r, "client.list", "client", "")
	if !ok {
		return
	}
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
	if limit > 0 && len(clients) > limit {
		clients = clients[:limit]
	}
	s.audit(r, "client.list", "client", "", "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	clientID, ok := s.requireClientID(w, r, "client.read")
	if !ok {
		return
	}
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
	if !model.ValidRevocationReason(req.Reason) {
		s.auditFailure(r, "client.revoke", "client", req.ClientID, map[string]string{"reason": "invalid_revoke_reason"})
		writeError(w, http.StatusBadRequest, "invalid_revoke_reason")
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
	filtered, ok := s.filterAuditEventsForRequest(w, r, "audit.list", events)
	if !ok {
		return
	}
	events = filtered
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
	filtered, ok := s.filterAuditEventsForRequest(w, r, "audit.export", events)
	if !ok {
		return
	}
	events = filtered
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			s.auditFailure(r, "audit.export", "audit_event", "", map[string]string{"reason": "encode_failed"})
			writeError(w, http.StatusInternalServerError, "export_failed")
			return
		}
	}
	digest := sha256.Sum256(body.Bytes())
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="custodia-audit.jsonl"`)
	w.Header().Set("X-Custodia-Audit-Export-SHA256", hex.EncodeToString(digest[:]))
	w.Header().Set("X-Custodia-Audit-Export-Events", strconv.Itoa(len(events)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body.Bytes())
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
	limit, ok := s.optionalLimit(w, r, "secret.list", "secret", "")
	if !ok {
		return
	}
	secrets, err := s.store.ListSecrets(r.Context(), clientIDFromContext(r))
	if err != nil {
		s.auditStoreFailure(r, "secret.list", "secret", "", err)
		writeMappedError(w, err)
		return
	}
	if limit > 0 && len(secrets) > limit {
		secrets = secrets[:limit]
	}
	s.audit(r, "secret.list", "secret", "", "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"secrets": secrets})
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	secretID, ok := s.requireSecretID(w, r, "secret.read")
	if !ok {
		return
	}
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
	secretID, ok := s.requireSecretID(w, r, "secret.version_list")
	if !ok {
		return
	}
	limit, ok := s.optionalLimit(w, r, "secret.version_list", "secret", secretID)
	if !ok {
		return
	}
	versions, err := s.store.ListSecretVersions(r.Context(), clientIDFromContext(r), secretID)
	if err != nil {
		s.auditStoreFailure(r, "secret.version_list", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	if limit > 0 && len(versions) > limit {
		versions = versions[:limit]
	}
	s.audit(r, "secret.version_list", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

func (s *Server) handleListSecretAccess(w http.ResponseWriter, r *http.Request) {
	secretID, ok := s.requireSecretID(w, r, "secret.access_list")
	if !ok {
		return
	}
	limit, ok := s.optionalLimit(w, r, "secret.access_list", "secret", secretID)
	if !ok {
		return
	}
	accesses, err := s.store.ListSecretAccess(r.Context(), clientIDFromContext(r), secretID)
	if err != nil {
		s.auditStoreFailure(r, "secret.access_list", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	if limit > 0 && len(accesses) > limit {
		accesses = accesses[:limit]
	}
	s.audit(r, "secret.access_list", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"access": accesses})
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	secretID, ok := s.requireSecretID(w, r, "secret.delete")
	if !ok {
		return
	}
	if err := s.store.DeleteSecret(r.Context(), clientIDFromContext(r), secretID); err != nil {
		s.auditStoreFailure(r, "secret.delete", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.delete", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleShareSecret(w http.ResponseWriter, r *http.Request) {
	secretID, ok := s.requireSecretID(w, r, "secret.share")
	if !ok {
		return
	}
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
	secretID, ok := s.requireSecretID(w, r, "secret.access_request")
	if !ok {
		return
	}
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
	limit := 100
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 || parsed > 500 {
			s.auditFailure(r, "secret.access_request_list", "secret", "", map[string]string{"reason": "invalid_limit"})
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = parsed
	}
	secretID := strings.TrimSpace(r.URL.Query().Get("secret_id"))
	if secretID != "" && !model.ValidUUIDID(secretID) {
		s.auditFailure(r, "secret.access_request_list", "secret", secretID, map[string]string{"reason": "invalid_secret_id_filter"})
		writeError(w, http.StatusBadRequest, "invalid_secret_id_filter")
		return
	}
	requests, err := s.store.ListAccessGrantRequests(r.Context(), secretID)
	if err != nil {
		s.auditStoreFailure(r, "secret.access_request_list", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		if !model.ValidAccessRequestStatus(status) {
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
	if targetClientID := strings.TrimSpace(r.URL.Query().Get("client_id")); targetClientID != "" {
		if !model.ValidClientID(targetClientID) {
			s.auditFailure(r, "secret.access_request_list", "secret", secretID, map[string]string{"reason": "invalid_client_id_filter"})
			writeError(w, http.StatusBadRequest, "invalid_client_id_filter")
			return
		}
		filtered := requests[:0]
		for _, request := range requests {
			if request.ClientID == targetClientID {
				filtered = append(filtered, request)
			}
		}
		requests = filtered
	}
	if requestedBy := strings.TrimSpace(r.URL.Query().Get("requested_by_client_id")); requestedBy != "" {
		if !model.ValidClientID(requestedBy) {
			s.auditFailure(r, "secret.access_request_list", "secret", secretID, map[string]string{"reason": "invalid_requested_by_filter"})
			writeError(w, http.StatusBadRequest, "invalid_requested_by_filter")
			return
		}
		filtered := requests[:0]
		for _, request := range requests {
			if request.RequestedByClientID == requestedBy {
				filtered = append(filtered, request)
			}
		}
		requests = filtered
	}
	if len(requests) > limit {
		requests = requests[:limit]
	}
	s.audit(r, "secret.access_request_list", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"access_requests": requests})
}

func (s *Server) handleActivateAccessGrant(w http.ResponseWriter, r *http.Request) {
	secretID, ok := s.requireSecretID(w, r, "secret.access_activate")
	if !ok {
		return
	}
	targetClientID, ok := s.requireClientID(w, r, "secret.access_activate")
	if !ok {
		return
	}
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
	secretID, ok := s.requireSecretID(w, r, "secret.access_revoke")
	if !ok {
		return
	}
	targetClientID, ok := s.requireClientID(w, r, "secret.access_revoke")
	if !ok {
		return
	}
	if err := s.store.RevokeAccess(r.Context(), clientIDFromContext(r), secretID, targetClientID); err != nil {
		s.auditStoreFailure(r, "secret.access_revoke", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.access_revoke", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleCreateSecretVersion(w http.ResponseWriter, r *http.Request) {
	secretID, ok := s.requireSecretID(w, r, "secret.version_create")
	if !ok {
		return
	}
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

func (s *Server) requireClientID(w http.ResponseWriter, r *http.Request, action string) (string, bool) {
	clientID := r.PathValue("client_id")
	if !model.ValidClientID(clientID) {
		s.auditFailure(r, action, "client", clientID, map[string]string{"reason": "invalid_client_id"})
		writeError(w, http.StatusBadRequest, "invalid_client_id")
		return "", false
	}
	return clientID, true
}

func (s *Server) requireSecretID(w http.ResponseWriter, r *http.Request, action string) (string, bool) {
	secretID := r.PathValue("secret_id")
	if !model.ValidUUIDID(secretID) {
		s.auditFailure(r, action, "secret", secretID, map[string]string{"reason": "invalid_secret_id"})
		writeError(w, http.StatusBadRequest, "invalid_secret_id")
		return "", false
	}
	return secretID, true
}

func (s *Server) optionalLimit(w http.ResponseWriter, r *http.Request, action, resourceType, resourceID string) (int, bool) {
	rawLimit := strings.TrimSpace(r.URL.Query().Get("limit"))
	if rawLimit == "" {
		return 0, true
	}
	parsed, err := strconv.Atoi(rawLimit)
	if err != nil || parsed <= 0 || parsed > 500 {
		s.auditFailure(r, action, resourceType, resourceID, map[string]string{"reason": "invalid_limit"})
		writeError(w, http.StatusBadRequest, "invalid_limit")
		return 0, false
	}
	return parsed, true
}

func (s *Server) filterAuditEventsForRequest(w http.ResponseWriter, r *http.Request, action string, events []model.AuditEvent) ([]model.AuditEvent, bool) {
	if outcome := strings.TrimSpace(r.URL.Query().Get("outcome")); outcome != "" {
		if outcome != "success" && outcome != "failure" && outcome != "degraded" {
			s.auditFailure(r, action, "audit_event", "", map[string]string{"reason": "invalid_outcome_filter"})
			writeError(w, http.StatusBadRequest, "invalid_outcome_filter")
			return nil, false
		}
		events = filterAuditEvents(events, func(event model.AuditEvent) bool { return event.Outcome == outcome })
	}
	if auditAction := strings.TrimSpace(r.URL.Query().Get("action")); auditAction != "" {
		if !model.ValidAuditAction(auditAction) {
			s.auditFailure(r, action, "audit_event", "", map[string]string{"reason": "invalid_action_filter"})
			writeError(w, http.StatusBadRequest, "invalid_action_filter")
			return nil, false
		}
		events = filterAuditEvents(events, func(event model.AuditEvent) bool { return event.Action == auditAction })
	}
	if actorClientID := strings.TrimSpace(r.URL.Query().Get("actor_client_id")); actorClientID != "" {
		if !model.ValidClientID(actorClientID) {
			s.auditFailure(r, action, "audit_event", "", map[string]string{"reason": "invalid_actor_client_id_filter"})
			writeError(w, http.StatusBadRequest, "invalid_actor_client_id_filter")
			return nil, false
		}
		events = filterAuditEvents(events, func(event model.AuditEvent) bool { return event.ActorClientID == actorClientID })
	}
	if resourceType := strings.TrimSpace(r.URL.Query().Get("resource_type")); resourceType != "" {
		if !model.ValidAuditResourceType(resourceType) {
			s.auditFailure(r, action, "audit_event", "", map[string]string{"reason": "invalid_resource_type_filter"})
			writeError(w, http.StatusBadRequest, "invalid_resource_type_filter")
			return nil, false
		}
		events = filterAuditEvents(events, func(event model.AuditEvent) bool { return event.ResourceType == resourceType })
	}
	if resourceID := strings.TrimSpace(r.URL.Query().Get("resource_id")); resourceID != "" {
		if !model.ValidAuditResourceID(resourceID) {
			s.auditFailure(r, action, "audit_event", "", map[string]string{"reason": "invalid_resource_id_filter"})
			writeError(w, http.StatusBadRequest, "invalid_resource_id_filter")
			return nil, false
		}
		events = filterAuditEvents(events, func(event model.AuditEvent) bool { return event.ResourceID == resourceID })
	}
	return events, true
}

func filterAuditEvents(events []model.AuditEvent, keep func(model.AuditEvent) bool) []model.AuditEvent {
	filtered := events[:0]
	for _, event := range events {
		if keep(event) {
			filtered = append(filtered, event)
		}
	}
	return filtered
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
