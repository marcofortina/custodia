// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

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
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"custodia/internal/audit"
	"custodia/internal/build"
	"custodia/internal/model"
	"custodia/internal/mtls"
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

// handleWeb intentionally exposes a metadata-only console. Browser-side secret
// decryption is a separate client concern and must not be added here without a
// dedicated WebCrypto/key-management design.
func (s *Server) handleWeb(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/web/" {
		writeWebNotFoundPage(w, true)
		return
	}
	body := `<section class="console-hero"><p class="console-kicker">Custodia Console</p><h1>Custodia Console</h1><p>The console is a responsive metadata-only control plane for operators. It never decrypts secrets and never manages client-side encryption keys.</p></section>` +
		`<section class="console-grid" aria-label="Console sections">` +
		`<a class="console-link-card" href="/web/status" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true"><strong>Operational Status</strong><span>Store, rate limiter, build and web auth posture.</span></a>` +
		`<a class="console-link-card" href="/web/clients" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true"><strong>Clients</strong><span>mTLS identities and active/revoked state.</span></a>` +
		`<a class="console-link-card" href="/web/access-requests" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true"><strong>Access Requests</strong><span>Pending grant metadata without envelopes.</span></a>` +
		`<a class="console-link-card" href="/web/audit" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true"><strong>Audit Events</strong><span>Recent admin-visible audit metadata.</span></a>` +
		`<a class="console-link-card" href="/web/audit/verify" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true"><strong>Verify Audit</strong><span>Hash-chain integrity summary.</span></a>` +
		`<a class="console-link-card" href="/web/diagnostics" hx-boost="true" hx-target="#console-main" hx-select="#console-main" hx-push-url="true"><strong>Runtime Diagnostics</strong><span>Runtime counters and uptime only.</span></a>` +
		`</section>` +
		`<section class="console-panel console-security-boundary"><p class="console-panel-label">Security boundary</p><p>The web surface remains metadata-only: it displays operational status, client records, access workflow metadata and audit summaries, but never renders plaintext, ciphertext, recipient envelopes, DEKs, private keys or key discovery endpoints.</p></section>`
	writeWebPage(w, "Custodia Console", body)
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
		Status:                         outcome,
		Store:                          storeStatus,
		StoreBackend:                   s.storeBackend,
		RateLimiter:                    rateLimiterStatus,
		RateLimitBackend:               s.rateLimitBackend,
		MaxEnvelopesPerSecret:          s.maxEnvelopesPerSecret,
		ClientRateLimitPerSec:          s.clientRateLimit,
		GlobalRateLimitPerSec:          s.globalRateLimit,
		IPRateLimitPerSec:              s.ipRateLimit,
		Build:                          model.BuildInfo(build.Current()),
		WebMFARequired:                 s.webMFARequired,
		WebPasskeyEnabled:              s.webPasskeyEnabled,
		WebPasskeyCredentials:          s.webPasskeyCredentials.Count(),
		WebPasskeyUserVerification:     "required",
		WebPasskeyCredentialKeyStorage: "opaque_cose",
		WebPasskeyCredentialKeyParser:  "cose_es256_rs256",
		WebPasskeyAssertionVerifier:    passkeyAssertionVerifierStatus(s.webPasskeyAssertionVerifyCommand),
		DeploymentMode:                 s.deploymentMode,
		DatabaseHATarget:               s.databaseHATarget,
		AuditShipmentSink:              s.auditShipmentSink,
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

func (s *Server) handleRevocationStatus(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.clientCRLFile) == "" {
		s.audit(r, "revocation.status", "system", "", "success", nil)
		writeJSON(w, http.StatusOK, model.RevocationStatus{Configured: false, Valid: true})
		return
	}
	caPEM, err := os.ReadFile(s.clientCAFile)
	if err != nil {
		s.auditFailure(r, "revocation.status", "system", "", map[string]string{"reason": "client_ca_unavailable"})
		writeJSON(w, http.StatusServiceUnavailable, model.RevocationStatus{Configured: true, Valid: false, Source: s.clientCRLFile, Error: "client_ca_unavailable"})
		return
	}
	crlStatus, err := mtls.LoadClientCRLStatus(s.clientCRLFile, caPEM)
	if err != nil {
		s.auditFailure(r, "revocation.status", "system", "", map[string]string{"reason": "client_crl_invalid"})
		writeJSON(w, http.StatusServiceUnavailable, model.RevocationStatus{Configured: true, Valid: false, Source: s.clientCRLFile, Error: "client_crl_invalid"})
		return
	}
	expiresIn := int64(0)
	if !crlStatus.NextUpdate.IsZero() {
		expiresIn = int64(time.Until(crlStatus.NextUpdate).Seconds())
	}
	s.audit(r, "revocation.status", "system", "", "success", nil)
	writeJSON(w, http.StatusOK, model.RevocationStatus{
		Configured:       true,
		Valid:            true,
		Source:           crlStatus.Source,
		Issuer:           crlStatus.Issuer,
		ThisUpdate:       crlStatus.ThisUpdate,
		NextUpdate:       crlStatus.NextUpdate,
		RevokedCount:     crlStatus.RevokedCount,
		ExpiresInSeconds: expiresIn,
	})
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

// handleCreateSecret stores client-produced ciphertext and recipient envelopes
// without interpreting crypto_metadata. Authorization is server-side; encryption
// semantics remain entirely client-side.
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

// handleGetSecret returns only the envelope authorized for the authenticated
// mTLS client. Other recipients' envelopes stay hidden even though they refer
// to the same secret version.
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

func (s *Server) handleGetSecretByKey(w http.ResponseWriter, r *http.Request) {
	namespace, key, ok := s.requireSecretKeyspaceQuery(w, r, "secret.read")
	if !ok {
		return
	}
	secretID, err := s.store.ResolveSecretIDByKey(r.Context(), clientIDFromContext(r), namespace, key, model.PermissionRead)
	if err != nil {
		s.auditStoreFailure(r, "secret.read", "secret_key", secretKeyspaceResource(namespace, key), err)
		writeMappedError(w, err)
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

func (s *Server) handleDeleteSecretByKey(w http.ResponseWriter, r *http.Request) {
	namespace, key, ok := s.requireSecretKeyspaceQuery(w, r, "secret.delete")
	if !ok {
		return
	}
	secretID, err := s.store.ResolveSecretIDByKey(r.Context(), clientIDFromContext(r), namespace, key, model.PermissionRead)
	if err != nil {
		s.auditStoreFailure(r, "secret.delete", "secret_key", secretKeyspaceResource(namespace, key), err)
		writeMappedError(w, err)
		return
	}
	if err := s.store.DeleteSecret(r.Context(), clientIDFromContext(r), secretID, secretCascadeQuery(r)); err != nil {
		s.auditStoreFailure(r, "secret.delete", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.delete", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleShareSecretByKey(w http.ResponseWriter, r *http.Request) {
	namespace, key, ok := s.requireSecretKeyspaceQuery(w, r, "secret.share")
	if !ok {
		return
	}
	secretID, err := s.store.ResolveSecretIDByKey(r.Context(), clientIDFromContext(r), namespace, key, model.PermissionShare)
	if err != nil {
		s.auditStoreFailure(r, "secret.share", "secret_key", secretKeyspaceResource(namespace, key), err)
		writeMappedError(w, err)
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

func (s *Server) handleRevokeAccessByKey(w http.ResponseWriter, r *http.Request) {
	namespace, key, ok := s.requireSecretKeyspaceQuery(w, r, "secret.access_revoke")
	if !ok {
		return
	}
	targetClientID, ok := s.requireClientID(w, r, "secret.access_revoke")
	if !ok {
		return
	}
	secretID, err := s.store.ResolveSecretIDByKey(r.Context(), clientIDFromContext(r), namespace, key, model.PermissionShare)
	if err != nil {
		s.auditStoreFailure(r, "secret.access_revoke", "secret_key", secretKeyspaceResource(namespace, key), err)
		writeMappedError(w, err)
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

func (s *Server) handleCreateSecretVersionByKey(w http.ResponseWriter, r *http.Request) {
	namespace, key, ok := s.requireSecretKeyspaceQuery(w, r, "secret.version_create")
	if !ok {
		return
	}
	secretID, err := s.store.ResolveSecretIDByKey(r.Context(), clientIDFromContext(r), namespace, key, model.PermissionWrite)
	if err != nil {
		s.auditStoreFailure(r, "secret.version_create", "secret_key", secretKeyspaceResource(namespace, key), err)
		writeMappedError(w, err)
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

func (s *Server) handleListSecretVersions(w http.ResponseWriter, r *http.Request) {
	secretID, ok := s.requireSecretID(w, r, "secret.version_list")
	if !ok {
		return
	}
	s.listSecretVersions(w, r, secretID)
}

func (s *Server) handleListSecretVersionsByKey(w http.ResponseWriter, r *http.Request) {
	namespace, key, ok := s.requireSecretKeyspaceQuery(w, r, "secret.version_list")
	if !ok {
		return
	}
	secretID, err := s.store.ResolveSecretIDByKey(r.Context(), clientIDFromContext(r), namespace, key, model.PermissionRead)
	if err != nil {
		s.auditStoreFailure(r, "secret.version_list", "secret_key", secretKeyspaceResource(namespace, key), err)
		writeMappedError(w, err)
		return
	}
	s.listSecretVersions(w, r, secretID)
}

func (s *Server) listSecretVersions(w http.ResponseWriter, r *http.Request, secretID string) {
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
	s.listSecretAccess(w, r, secretID)
}

func (s *Server) handleListSecretAccessByKey(w http.ResponseWriter, r *http.Request) {
	namespace, key, ok := s.requireSecretKeyspaceQuery(w, r, "secret.access_list")
	if !ok {
		return
	}
	secretID, err := s.store.ResolveSecretIDByKey(r.Context(), clientIDFromContext(r), namespace, key, model.PermissionShare)
	if err != nil {
		s.auditStoreFailure(r, "secret.access_list", "secret_key", secretKeyspaceResource(namespace, key), err)
		writeMappedError(w, err)
		return
	}
	s.listSecretAccess(w, r, secretID)
}

func (s *Server) listSecretAccess(w http.ResponseWriter, r *http.Request, secretID string) {
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
	if err := s.store.DeleteSecret(r.Context(), clientIDFromContext(r), secretID, secretCascadeQuery(r)); err != nil {
		s.auditStoreFailure(r, "secret.delete", "secret", secretID, err)
		writeMappedError(w, err)
		return
	}
	s.audit(r, "secret.delete", "secret", secretID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleShareSecret activates access using an envelope supplied by a client
// that already holds share permission. The server records the grant but never
// manufactures or validates recipient key material.
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

func (s *Server) handleRequestAccessGrantByKey(w http.ResponseWriter, r *http.Request) {
	namespace, key, ok := s.requireSecretKeyspaceQuery(w, r, "secret.access_request")
	if !ok {
		return
	}
	secretID, err := s.store.ResolveSecretIDByKey(r.Context(), clientIDFromContext(r), namespace, key, model.PermissionShare)
	if err != nil {
		s.auditStoreFailure(r, "secret.access_request", "secret_key", secretKeyspaceResource(namespace, key), err)
		writeMappedError(w, err)
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

func (s *Server) handleActivateAccessGrantByKey(w http.ResponseWriter, r *http.Request) {
	namespace, key, ok := s.requireSecretKeyspaceQuery(w, r, "secret.access_activate")
	if !ok {
		return
	}
	targetClientID, ok := s.requireClientID(w, r, "secret.access_activate")
	if !ok {
		return
	}
	secretID, err := s.store.ResolveSecretIDByKey(r.Context(), clientIDFromContext(r), namespace, key, model.PermissionShare)
	if err != nil {
		s.auditStoreFailure(r, "secret.access_activate", "secret_key", secretKeyspaceResource(namespace, key), err)
		writeMappedError(w, err)
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

// handleCreateSecretVersion models strong rotation: clients upload a fresh
// ciphertext and fresh recipient envelopes after revocation or key rollover.
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

func (s *Server) requireSecretKeyspaceQuery(w http.ResponseWriter, r *http.Request, action string) (string, string, bool) {
	namespace := model.NormalizeSecretNamespace(r.URL.Query().Get("namespace"))
	key := model.NormalizeSecretKey(r.URL.Query().Get("key"))
	if !model.ValidSecretNamespace(namespace) {
		s.auditFailure(r, action, "secret_key", secretKeyspaceResource(namespace, key), map[string]string{"reason": "invalid_secret_namespace"})
		writeError(w, http.StatusBadRequest, "invalid_secret_namespace")
		return "", "", false
	}
	if !model.ValidSecretKey(key) {
		s.auditFailure(r, action, "secret_key", secretKeyspaceResource(namespace, key), map[string]string{"reason": "invalid_secret_key"})
		writeError(w, http.StatusBadRequest, "invalid_secret_key")
		return "", "", false
	}
	return namespace, key, true
}

func secretKeyspaceResource(namespace, key string) string {
	return model.NormalizeSecretNamespace(namespace) + "/" + model.NormalizeSecretKey(key)
}

func secretCascadeQuery(r *http.Request) bool {
	cascade, err := strconv.ParseBool(strings.TrimSpace(r.URL.Query().Get("cascade")))
	return err == nil && cascade
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
	writeFilterError := func(code string) {
		if strings.HasPrefix(action, "web.") {
			writeWebStatusError(w, http.StatusBadRequest, code)
			return
		}
		writeError(w, http.StatusBadRequest, code)
	}
	if outcome := strings.TrimSpace(r.URL.Query().Get("outcome")); outcome != "" {
		if outcome != "success" && outcome != "failure" && outcome != "degraded" {
			s.auditFailure(r, action, "audit_event", "", map[string]string{"reason": "invalid_outcome_filter"})
			writeFilterError("invalid_outcome_filter")
			return nil, false
		}
		events = filterAuditEvents(events, func(event model.AuditEvent) bool { return event.Outcome == outcome })
	}
	if auditAction := strings.TrimSpace(r.URL.Query().Get("action")); auditAction != "" {
		if !model.ValidAuditAction(auditAction) {
			s.auditFailure(r, action, "audit_event", "", map[string]string{"reason": "invalid_action_filter"})
			writeFilterError("invalid_action_filter")
			return nil, false
		}
		events = filterAuditEvents(events, func(event model.AuditEvent) bool { return event.Action == auditAction })
	}
	if actorClientID := strings.TrimSpace(r.URL.Query().Get("actor_client_id")); actorClientID != "" {
		if !model.ValidClientID(actorClientID) {
			s.auditFailure(r, action, "audit_event", "", map[string]string{"reason": "invalid_actor_client_id_filter"})
			writeFilterError("invalid_actor_client_id_filter")
			return nil, false
		}
		events = filterAuditEvents(events, func(event model.AuditEvent) bool { return event.ActorClientID == actorClientID })
	}
	if resourceType := strings.TrimSpace(r.URL.Query().Get("resource_type")); resourceType != "" {
		if !model.ValidAuditResourceType(resourceType) {
			s.auditFailure(r, action, "audit_event", "", map[string]string{"reason": "invalid_resource_type_filter"})
			writeFilterError("invalid_resource_type_filter")
			return nil, false
		}
		events = filterAuditEvents(events, func(event model.AuditEvent) bool { return event.ResourceType == resourceType })
	}
	if resourceID := strings.TrimSpace(r.URL.Query().Get("resource_id")); resourceID != "" {
		if !model.ValidAuditResourceID(resourceID) {
			s.auditFailure(r, action, "audit_event", "", map[string]string{"reason": "invalid_resource_id_filter"})
			writeFilterError("invalid_resource_id_filter")
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
