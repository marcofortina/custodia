// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"custodia/internal/model"
	"custodia/internal/ratelimit"
	"custodia/internal/store"
	"custodia/internal/webauth"
)

func TestAPIPropagatesRequestID(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-ID", "operator-trace-1")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if got := res.Header().Get("X-Request-ID"); got != "operator-trace-1" {
		t.Fatalf("expected request id to be propagated, got %q", got)
	}
}

func TestAPIAuditMetadataIncludesRequestID(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/status", "", "admin")
	req.Header.Set("X-Request-ID", "audit-trace-1")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	events := memoryStore.AuditEvents()
	last := events[len(events)-1]
	if !strings.Contains(string(last.Metadata), "audit-trace-1") {
		t.Fatalf("expected request id in audit metadata, got %s", string(last.Metadata))
	}
}

func TestAPIAdminDiagnosticsEndpoint(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/diagnostics", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload model.RuntimeDiagnostics
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode diagnostics: %v", err)
	}
	if payload.StartedAt.IsZero() || payload.Goroutines <= 0 {
		t.Fatalf("unexpected diagnostics payload: %+v", payload)
	}
}

func TestWebDiagnosticsPageIsAdminOnlyMetadata(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/diagnostics", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	if !strings.Contains(body, "Runtime Diagnostics") || strings.Contains(body, "ciphertext") || strings.Contains(body, "envelope") {
		t.Fatalf("unexpected diagnostics page body: %s", body)
	}
}

func TestAPISetsSecurityHeaders(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=(), payment=()",
	}
	for header, value := range expected {
		if got := res.Header().Get(header); got != value {
			t.Fatalf("expected %s=%q, got %q", header, value, got)
		}
	}
	if got := res.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") || !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("unexpected CSP header: %q", got)
	}
}

func TestWebMutationsRejectCrossOriginBrowserRequests(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100, EnrollmentServerURL: "https://custodia.example.internal:8443"})

	req := mtlsRequest(http.MethodPost, "/web/client-enrollments", "ttl=15m", "admin")
	req.Host = "custodia.example.internal"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("expected cross-origin web mutation to be rejected, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "Cross-origin request blocked") {
		t.Fatalf("expected cross-origin error page, got: %s", res.Body.String())
	}
}

func TestWebMutationsAllowSameOriginBrowserRequests(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100, EnrollmentServerURL: "https://custodia.example.internal:8443"})

	req := mtlsRequest(http.MethodPost, "/web/client-enrollments", "ttl=15m", "admin")
	req.Host = "custodia.example.internal"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://custodia.example.internal")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected same-origin web mutation to be allowed, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "Enrollment token") {
		t.Fatalf("expected enrollment token response, got: %s", res.Body.String())
	}
}

func TestAPILiveEndpointIsDependencyFree(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	handler := New(Options{Store: memoryStore, Limiter: failingHealthLimiter{}, AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := httptest.NewRequest(http.MethodGet, "/live", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "live") {
		t.Fatalf("expected live status, got %s", res.Body.String())
	}
}

func TestReadyFailsWhenRateLimiterHealthFails(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	handler := New(Options{Store: memoryStore, Limiter: failingHealthLimiter{}, AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "rate_limiter_unavailable") {
		t.Fatalf("expected rate limiter readiness error, got %s", res.Body.String())
	}
}

type failingHealthLimiter struct{}

func (failingHealthLimiter) Allow(context.Context, string, int) (bool, error) { return true, nil }
func (failingHealthLimiter) Health(context.Context) error                     { return errors.New("down") }

func TestAPIRejectsRequestsWithoutClientCertificate(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})
	req := httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(`{}`))
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}
}

func TestAPIEnrollmentClaimIsOnlyPublicBootstrapEndpoint(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	claimReq := httptest.NewRequest(http.MethodPost, "/v1/client-enrollments/claim", strings.NewReader(`{}`))
	claimReq.Header.Set("Content-Type", "application/json")
	claimRes := httptest.NewRecorder()
	handler.ServeHTTP(claimRes, claimReq)
	assertHTTPError(t, claimRes, http.StatusBadRequest, "invalid_input")

	for _, tt := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/v1/me"},
		{method: http.MethodGet, path: "/v1/status"},
		{method: http.MethodGet, path: "/v1/secrets"},
	} {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			res := httptest.NewRecorder()

			handler.ServeHTTP(res, req)

			assertHTTPError(t, res, http.StatusUnauthorized, "missing_client_certificate")
		})
	}
}

func assertHTTPError(t *testing.T, res *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if res.Code != status {
		t.Fatalf("expected %d, got %d: %s", status, res.Code, res.Body.String())
	}
	var payload errorResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if payload.Error != code {
		t.Fatalf("expected error %q, got %q", code, payload.Error)
	}
}

func TestAPIClientRevokeAuditsReason(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_bob", MTLSSubject: "client_bob"}); err != nil {
		t.Fatalf("create bob: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodPost, "/v1/clients/revoke", `{"client_id":"client_bob","reason":"compromised certificate"}`, "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	events := memoryStore.AuditEvents()
	last := events[len(events)-1]
	if last.Action != "client.revoke" || last.Outcome != "success" {
		t.Fatalf("unexpected audit event: %+v", last)
	}
	if !strings.Contains(string(last.Metadata), "compromised certificate") {
		t.Fatalf("expected revoke reason in audit metadata, got %s", string(last.Metadata))
	}
}

func TestAPIClientRevokeRejectsInvalidReason(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodPost, "/v1/clients/revoke", `{"client_id":"client_bob","reason":"bad\nreason"}`, "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestAPIAdminAccessRequestsFilterByRequester(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "operator", "client_alice", "client_bob", "client_charlie"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	ref, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Key: "secret", Ciphertext: "Y2lwaGVydGV4dA==", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}}, Permissions: int(model.PermissionAll)})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := memoryStore.RequestAccessGrant(ctx, "admin", ref.SecretID, model.AccessGrantRequest{TargetClientID: "client_bob", Permissions: int(model.PermissionRead)}); err != nil {
		t.Fatalf("request grant admin: %v", err)
	}
	if _, err := memoryStore.RequestAccessGrant(ctx, "operator", ref.SecretID, model.AccessGrantRequest{TargetClientID: "client_charlie", Permissions: int(model.PermissionRead)}); err != nil {
		t.Fatalf("request grant operator: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/access-requests?requested_by_client_id=operator", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Requests []model.AccessGrantMetadata `json:"access_requests"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode access requests: %v", err)
	}
	if len(payload.Requests) != 1 || payload.Requests[0].RequestedByClientID != "operator" {
		t.Fatalf("unexpected filtered requests: %+v", payload.Requests)
	}
}

func TestAPIAdminAccessRequestsFilterByTargetClientID(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_alice", "client_bob", "client_charlie"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	ref, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Key: "secret", Ciphertext: "Y2lwaGVydGV4dA==", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}}, Permissions: int(model.PermissionAll)})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := memoryStore.RequestAccessGrant(ctx, "admin", ref.SecretID, model.AccessGrantRequest{TargetClientID: "client_bob", Permissions: int(model.PermissionRead)}); err != nil {
		t.Fatalf("request grant bob: %v", err)
	}
	if _, err := memoryStore.RequestAccessGrant(ctx, "admin", ref.SecretID, model.AccessGrantRequest{TargetClientID: "client_charlie", Permissions: int(model.PermissionRead)}); err != nil {
		t.Fatalf("request grant charlie: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/access-requests?client_id=client_bob", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Requests []model.AccessGrantMetadata `json:"access_requests"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode access requests: %v", err)
	}
	if len(payload.Requests) != 1 || payload.Requests[0].ClientID != "client_bob" {
		t.Fatalf("unexpected filtered requests: %+v", payload.Requests)
	}
}

func TestAPIAuditExportAppliesMetadataFilters(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	_ = memoryStore.AppendAudit(ctx, model.AuditEvent{EventID: "1", ActorClientID: "admin", Action: "secret.read", ResourceType: "secret", ResourceID: "secret_a", Outcome: "success"})
	_ = memoryStore.AppendAudit(ctx, model.AuditEvent{EventID: "2", ActorClientID: "admin", Action: "client.list", ResourceType: "client", ResourceID: "client_a", Outcome: "success"})
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events/export?resource_type=secret", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	if !strings.Contains(body, "secret.read") || strings.Contains(body, "client.list") {
		t.Fatalf("expected filtered JSONL export, got %s", body)
	}
}

func TestAPIAuditListRejectsInvalidActionFilter(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events?action=secret/read", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "invalid_action_filter") {
		t.Fatalf("expected invalid action filter error, got %s", res.Body.String())
	}
}

func TestAPIAuditListRejectsInvalidResourceIDFilter(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events?resource_id=secret%0Aid", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "invalid_resource_id_filter") {
		t.Fatalf("expected invalid resource id filter error, got %s", res.Body.String())
	}
}

func TestAPIAuditListFiltersByResourceID(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	_ = memoryStore.AppendAudit(ctx, model.AuditEvent{EventID: "1", ActorClientID: "admin", Action: "secret.read", ResourceType: "secret", ResourceID: "secret_a", Outcome: "success"})
	_ = memoryStore.AppendAudit(ctx, model.AuditEvent{EventID: "2", ActorClientID: "admin", Action: "secret.read", ResourceType: "secret", ResourceID: "secret_b", Outcome: "success"})
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events?resource_id=secret_b", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Events []model.AuditEvent `json:"audit_events"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode audit events: %v", err)
	}
	if len(payload.Events) != 1 || payload.Events[0].ResourceID != "secret_b" {
		t.Fatalf("unexpected filtered audit events: %+v", payload.Events)
	}
}

func TestAPIAuditListRejectsInvalidResourceTypeFilter(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events?resource_type=secret/type", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "invalid_resource_type_filter") {
		t.Fatalf("expected invalid resource type filter error, got %s", res.Body.String())
	}
}

func TestAPIAuditListFiltersByResourceType(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	_ = memoryStore.AppendAudit(ctx, model.AuditEvent{EventID: "1", ActorClientID: "admin", Action: "client.list", ResourceType: "client", Outcome: "success"})
	_ = memoryStore.AppendAudit(ctx, model.AuditEvent{EventID: "2", ActorClientID: "admin", Action: "audit.list", ResourceType: "audit_event", Outcome: "success"})
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events?resource_type=audit_event", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Events []model.AuditEvent `json:"audit_events"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode audit events: %v", err)
	}
	if len(payload.Events) != 1 || payload.Events[0].ResourceType != "audit_event" {
		t.Fatalf("unexpected filtered audit events: %+v", payload.Events)
	}
}

func TestAPIAuditListFiltersByActorClientID(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := memoryStore.AppendAudit(ctx, model.AuditEvent{EventID: "1", ActorClientID: "admin", Action: "client.list", ResourceType: "client", Outcome: "success"}); err != nil {
		t.Fatalf("append audit: %v", err)
	}
	if err := memoryStore.AppendAudit(ctx, model.AuditEvent{EventID: "2", ActorClientID: "client_alice", Action: "secret.read", ResourceType: "secret", Outcome: "success"}); err != nil {
		t.Fatalf("append audit: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events?actor_client_id=client_alice", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Events []model.AuditEvent `json:"audit_events"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode audit events: %v", err)
	}
	if len(payload.Events) != 1 || payload.Events[0].ActorClientID != "client_alice" {
		t.Fatalf("unexpected filtered audit events: %+v", payload.Events)
	}
}

func TestAPIMeReturnsAuthenticatedClientMetadata(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/me", "", "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var client model.Client
	if err := json.NewDecoder(res.Body).Decode(&client); err != nil {
		t.Fatalf("decode client: %v", err)
	}
	if client.ClientID != "client_alice" || !client.IsActive {
		t.Fatalf("unexpected client metadata: %+v", client)
	}
	assertLastAudit(t, memoryStore, "client.me", "success", "")
}

func TestAPIClientPublishesAndReadsPublicKey(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	publicKeyB64 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", model.X25519PublicKeyBytes)))
	req := mtlsRequest(http.MethodPut, "/v1/me/public-key", `{"scheme":"hpke-v1","public_key_b64":"`+publicKeyB64+`"}`, "client_bob")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected publish 200, got %d: %s", res.Code, res.Body.String())
	}
	var published model.ClientPublicKey
	if err := json.NewDecoder(res.Body).Decode(&published); err != nil {
		t.Fatalf("decode published key: %v", err)
	}
	if published.ClientID != "client_bob" || published.Scheme != "hpke-v1" || published.Fingerprint == "" {
		t.Fatalf("unexpected published key: %+v", published)
	}

	req = mtlsRequest(http.MethodGet, "/v1/clients/client_bob/public-key", "", "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected read 200, got %d: %s", res.Code, res.Body.String())
	}
	var fetched model.ClientPublicKey
	if err := json.NewDecoder(res.Body).Decode(&fetched); err != nil {
		t.Fatalf("decode fetched key: %v", err)
	}
	if fetched.ClientID != "client_bob" || fetched.PublicKeyB64 != publicKeyB64 || fetched.Fingerprint != published.Fingerprint {
		t.Fatalf("unexpected fetched key: %+v", fetched)
	}
	assertLastAudit(t, memoryStore, "client.public_key.read", "success", "")
}

func TestAPIRejectsMalformedClientPublicKey(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodPut, "/v1/me/public-key", `{"scheme":"hpke-v1","public_key_b64":"too-short"}`, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestAPIAdminListsClientsWithActiveFilter(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_active", "client_revoked"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	if err := memoryStore.RevokeClient(ctx, "client_revoked"); err != nil {
		t.Fatalf("revoke client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/clients?active=false", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Clients []model.Client `json:"clients"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode clients: %v", err)
	}
	if len(payload.Clients) != 1 || payload.Clients[0].ClientID != "client_revoked" {
		t.Fatalf("unexpected inactive clients: %+v", payload.Clients)
	}
}

func TestAPIAdminCreatesClientMetadata(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodPost, "/v1/clients", `{"client_id":"client_bob","mtls_subject":"client_bob"}`, "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "client.create", "success", "")

	createBody := `{"key":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_bob","envelope":"ZW52ZWxvcGUtZm9yLWJvYg=="}],"permissions":7}`
	req = mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_bob")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected created client to authenticate and create a secret, got %d: %s", res.Code, res.Body.String())
	}
}

func TestAPIRejectsClientCreateFromNonAdmin(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodPost, "/v1/clients", `{"client_id":"client_bob","mtls_subject":"client_bob"}`, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "auth.admin", "failure", "admin_required")
}

func TestAPICreateAndReadOpaqueSecret(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})
	createBody := `{"key":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", res.Code, res.Body.String())
	}
	var created model.SecretVersionRef
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode created: %v", err)
	}

	req = mtlsRequest(http.MethodGet, "/v1/secrets/"+created.SecretID, "", "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var read model.SecretReadResponse
	if err := json.NewDecoder(res.Body).Decode(&read); err != nil {
		t.Fatalf("decode read: %v", err)
	}
	if read.Ciphertext != "Y2lwaGVydGV4dA==" || read.Envelope != "ZW52ZWxvcGUtZm9yLWFsaWNl" || read.GrantedAt.IsZero() {
		t.Fatalf("unexpected opaque payload: %+v", read)
	}
}

func TestAPIReadsSharesAndVersionsSecretByKeyspace(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	createBody := `{"namespace":"db01","key":"user:sys","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", res.Code, res.Body.String())
	}

	req = mtlsRequest(http.MethodGet, "/v1/secrets/by-key?namespace=db01&key=user:sys", "", "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected read by key 200, got %d: %s", res.Code, res.Body.String())
	}
	var read model.SecretReadResponse
	if err := json.NewDecoder(res.Body).Decode(&read); err != nil {
		t.Fatalf("decode read: %v", err)
	}
	if read.Namespace != "db01" || read.Key != "user:sys" || read.Ciphertext != "Y2lwaGVydGV4dA==" {
		t.Fatalf("unexpected keyspace read: %+v", read)
	}

	shareBody := `{"target_client_id":"client_bob","envelope":"ZW52ZWxvcGUtZm9yLWJvYg==","permissions":4}`
	req = mtlsRequest(http.MethodPost, "/v1/secrets/by-key/share?namespace=db01&key=user:sys", shareBody, "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected share by key 200, got %d: %s", res.Code, res.Body.String())
	}

	req = mtlsRequest(http.MethodGet, "/v1/secrets/by-key?namespace=db01&key=user:sys", "", "client_bob")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected bob read by key 200, got %d: %s", res.Code, res.Body.String())
	}
	read = model.SecretReadResponse{}
	if err := json.NewDecoder(res.Body).Decode(&read); err != nil {
		t.Fatalf("decode bob read: %v", err)
	}
	if read.Envelope != "ZW52ZWxvcGUtZm9yLWJvYg==" {
		t.Fatalf("unexpected bob envelope: %+v", read)
	}

	versionBody := `{"ciphertext":"bmV3LWNpcGhlcnRleHQ=","envelopes":[{"client_id":"client_alice","envelope":"bmV3LWVudmVsb3BlLWFsaWNl"},{"client_id":"client_bob","envelope":"bmV3LWVudmVsb3BlLWJvYg=="}],"permissions":7}`
	req = mtlsRequest(http.MethodPost, "/v1/secrets/by-key/versions?namespace=db01&key=user:sys", versionBody, "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected version by key 201, got %d: %s", res.Code, res.Body.String())
	}

	req = mtlsRequest(http.MethodGet, "/v1/secrets/by-key/versions?namespace=db01&key=user:sys&limit=1", "", "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected version list by key 200, got %d: %s", res.Code, res.Body.String())
	}
	var versionList struct {
		Versions []model.SecretVersionMetadata `json:"versions"`
	}
	if err := json.NewDecoder(res.Body).Decode(&versionList); err != nil {
		t.Fatalf("decode version list: %v", err)
	}
	if len(versionList.Versions) != 1 {
		t.Fatalf("expected limited version list, got %+v", versionList.Versions)
	}

	req = mtlsRequest(http.MethodGet, "/v1/secrets/by-key/access?namespace=db01&key=user:sys&limit=10", "", "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected access list by key 200, got %d: %s", res.Code, res.Body.String())
	}
	var accessList struct {
		Access []model.SecretAccessMetadata `json:"access"`
	}
	if err := json.NewDecoder(res.Body).Decode(&accessList); err != nil {
		t.Fatalf("decode access list: %v", err)
	}
	if len(accessList.Access) == 0 {
		t.Fatalf("expected access list rows")
	}

	req = mtlsRequest(http.MethodDelete, "/v1/secrets/by-key/access/client_bob?namespace=db01&key=user:sys", "", "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected revoke by key 200, got %d: %s", res.Code, res.Body.String())
	}

	req = mtlsRequest(http.MethodGet, "/v1/secrets/by-key?namespace=db01&key=user:sys", "", "client_bob")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden && res.Code != http.StatusNotFound {
		t.Fatalf("expected bob read by key after revoke to fail, got %d: %s", res.Code, res.Body.String())
	}
}

func TestAPIRejectsMissingSecretKeyspaceKey(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/secrets/by-key?namespace=db01", "", "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "invalid_secret_key") {
		t.Fatalf("expected invalid_secret_key, got %s", res.Body.String())
	}
}

func TestAPIRejectsInvalidPermissionBits(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	body := `{"key":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":8}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", body, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestAPIRejectsInvalidOpaquePayloadEncoding(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	body := `{"key":"secret","ciphertext":"not base64","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", body, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "secret.create", "failure", "invalid_input")
}

func TestAPIRejectsUnsupportedJSONContentType(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(`{"key":"secret"}`))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{"client_alice"}, Subject: pkix.Name{CommonName: "client_alice"}}}}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "secret.create", "failure", "invalid_json")
}

func TestAPIRejectsTrailingJSONPayload(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	body := `{"key":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}{}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", body, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "secret.create", "failure", "invalid_json")
}

func TestAPIRejectsOversizedJSONPayload(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	body := `{"key":"` + strings.Repeat("a", maxJSONBodyBytes+1) + `"}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", body, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "secret.create", "failure", "invalid_json")
}

func TestAPIDefaultsEnvelopeLimitWhenOptionIsUnset(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, ClientRateLimit: 100, GlobalRateLimit: 100})

	body := `{"key":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", body, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", res.Code, res.Body.String())
	}
}

func TestAPIRejectsTooManyCreateEnvelopes(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 1, ClientRateLimit: 100, GlobalRateLimit: 100})

	body := `{"key":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"},{"client_id":"client_bob","envelope":"ZW52ZWxvcGUtZm9yLWJvYg=="}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", body, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "secret.create", "failure", "too_many_envelopes")
}

func TestAPIRejectsTooManyVersionEnvelopes(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 1, ClientRateLimit: 100, GlobalRateLimit: 100})

	createBody := `{"key":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", res.Code, res.Body.String())
	}
	var created model.SecretVersionRef
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode created: %v", err)
	}

	versionBody := `{"ciphertext":"bmV3LWNpcGhlcnRleHQ=","envelopes":[{"client_id":"client_alice","envelope":"bmV3LWVudmVsb3BlLWFsaWNl"},{"client_id":"client_bob","envelope":"bmV3LWVudmVsb3BlLWJvYg=="}],"permissions":7}`
	req = mtlsRequest(http.MethodPost, "/v1/secrets/"+created.SecretID+"/versions", versionBody, "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "secret.version_create", "failure", "too_many_envelopes")
}

func TestAPIAuditsMissingClientCertificate(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})
	req := httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(`{}`))
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}
	assertLastAudit(t, memoryStore, "auth.mtls", "failure", "missing_client_certificate")
}

func TestAPIAuditsForbiddenSecretRead(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_bob", MTLSSubject: "client_bob"}); err != nil {
		t.Fatalf("create bob: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	createBody := `{"key":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", res.Code, res.Body.String())
	}
	var created model.SecretVersionRef
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode created: %v", err)
	}

	req = mtlsRequest(http.MethodGet, "/v1/secrets/"+created.SecretID, "", "client_bob")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("expected read 403, got %d: %s", res.Code, res.Body.String())
	}

	last := assertLastAudit(t, memoryStore, "secret.read", "failure", "forbidden")
	if last.ActorClientID != "client_bob" || last.ResourceID != created.SecretID {
		t.Fatalf("unexpected audit event: %+v", last)
	}
}

func TestAPIGrantRequestRequiresActivationByShareClient(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	createBody := `{"key":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", res.Code, res.Body.String())
	}
	var created model.SecretVersionRef
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode created: %v", err)
	}

	grantBody := `{"target_client_id":"client_bob","permissions":4}`
	req = mtlsRequest(http.MethodPost, "/v1/secrets/"+created.SecretID+"/access-requests", grantBody, "admin")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected grant request 201, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "secret.access_request", "success", "")

	req = mtlsRequest(http.MethodGet, "/v1/secrets/"+created.SecretID, "", "client_bob")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("expected bob read before activation 403, got %d: %s", res.Code, res.Body.String())
	}

	activateBody := `{"envelope":"ZW52ZWxvcGUtZm9yLWJvYg=="}`
	req = mtlsRequest(http.MethodPost, "/v1/secrets/"+created.SecretID+"/access/client_bob/activate", activateBody, "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected activate 200, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "secret.access_activate", "success", "")

	req = mtlsRequest(http.MethodGet, "/v1/secrets/"+created.SecretID, "", "client_bob")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected bob read after activation 200, got %d: %s", res.Code, res.Body.String())
	}
	var read model.SecretReadResponse
	if err := json.NewDecoder(res.Body).Decode(&read); err != nil {
		t.Fatalf("decode read: %v", err)
	}
	if read.Envelope != "ZW52ZWxvcGUtZm9yLWJvYg==" || read.Permissions != int(model.PermissionRead) {
		t.Fatalf("unexpected activated access: %+v", read)
	}
}

func TestAPICreateSecretVersionSupersedesOldVersionAccessWorkflow(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	createBody := `{"key":"secret","ciphertext":"Y2lwaGVydGV4dC12MQ==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtYWxpY2UtdjE="}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", res.Code, res.Body.String())
	}
	var created model.SecretVersionRef
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode created: %v", err)
	}

	grantBody := `{"version_id":"` + created.VersionID + `","target_client_id":"client_bob","permissions":4}`
	req = mtlsRequest(http.MethodPost, "/v1/secrets/"+created.SecretID+"/access-requests", grantBody, "admin")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected grant request 201, got %d: %s", res.Code, res.Body.String())
	}

	versionBody := `{"ciphertext":"Y2lwaGVydGV4dC12Mg==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtYWxpY2UtdjI="}],"permissions":7}`
	req = mtlsRequest(http.MethodPost, "/v1/secrets/"+created.SecretID+"/versions", versionBody, "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected version create 201, got %d: %s", res.Code, res.Body.String())
	}
	var rotated model.SecretVersionRef
	if err := json.NewDecoder(res.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode rotated: %v", err)
	}
	if rotated.VersionID == created.VersionID {
		t.Fatalf("expected rotated version id to differ from %q", created.VersionID)
	}

	req = mtlsRequest(http.MethodGet, "/v1/secrets/"+created.SecretID, "", "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected alice read 200, got %d: %s", res.Code, res.Body.String())
	}
	var read model.SecretReadResponse
	if err := json.NewDecoder(res.Body).Decode(&read); err != nil {
		t.Fatalf("decode read: %v", err)
	}
	if read.VersionID != rotated.VersionID || read.Ciphertext != "Y2lwaGVydGV4dC12Mg==" {
		t.Fatalf("expected latest rotated version, got %+v", read)
	}

	activateBody := `{"envelope":"ZW52ZWxvcGUtYm9iLW9sZA=="}`
	req = mtlsRequest(http.MethodPost, "/v1/secrets/"+created.SecretID+"/access/client_bob/activate", activateBody, "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("expected old pending activation 404, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "secret.access_activate", "failure", "not_found")
}

func TestAPIListsOnlyReadableSecretMetadata(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	createBody := `{"key":"visible","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", res.Code, res.Body.String())
	}

	req = mtlsRequest(http.MethodGet, "/v1/secrets", "", "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected list 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Secrets []model.SecretMetadata `json:"secrets"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(payload.Secrets) != 1 || payload.Secrets[0].Key != "visible" || payload.Secrets[0].VersionID == "" || payload.Secrets[0].CreatedByClientID != "client_alice" {
		t.Fatalf("unexpected alice metadata list: %+v", payload.Secrets)
	}
	assertLastAudit(t, memoryStore, "secret.list", "success", "")

	req = mtlsRequest(http.MethodGet, "/v1/secrets", "", "client_bob")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected bob list 200, got %d: %s", res.Code, res.Body.String())
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode bob list: %v", err)
	}
	if len(payload.Secrets) != 0 {
		t.Fatalf("expected no bob-visible metadata, got %+v", payload.Secrets)
	}
}

func TestAdminCanListAuditEvents(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	createBody := `{"key":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", res.Code, res.Body.String())
	}

	req = mtlsRequest(http.MethodGet, "/v1/audit-events?limit=10", "", "admin")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected audit list 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		AuditEvents []model.AuditEvent `json:"audit_events"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode audit list: %v", err)
	}
	if len(payload.AuditEvents) < 1 {
		t.Fatal("expected at least one audit event")
	}
	if payload.AuditEvents[0].EventHash == nil {
		t.Fatalf("expected hash-chained audit event, got %+v", payload.AuditEvents[0])
	}
	assertLastAudit(t, memoryStore, "audit.list", "success", "")
}

func TestAdminCanFilterAuditEventsByOutcome(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	memoryStore.AppendAudit(ctx, model.AuditEvent{Action: "secret.read", ResourceType: "secret", Outcome: "success"})
	memoryStore.AppendAudit(ctx, model.AuditEvent{Action: "secret.read", ResourceType: "secret", Outcome: "failure"})
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events?limit=10&outcome=failure", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		AuditEvents []model.AuditEvent `json:"audit_events"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode audit list: %v", err)
	}
	if len(payload.AuditEvents) != 1 || payload.AuditEvents[0].Outcome != "failure" {
		t.Fatalf("unexpected filtered audit events: %+v", payload.AuditEvents)
	}
}

func TestAdminCanFilterAuditEventsByAction(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	memoryStore.AppendAudit(ctx, model.AuditEvent{Action: "secret.read", ResourceType: "secret", Outcome: "success"})
	memoryStore.AppendAudit(ctx, model.AuditEvent{Action: "client.list", ResourceType: "client", Outcome: "success"})
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events?limit=10&action=client.list", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		AuditEvents []model.AuditEvent `json:"audit_events"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode audit list: %v", err)
	}
	if len(payload.AuditEvents) != 1 || payload.AuditEvents[0].Action != "client.list" {
		t.Fatalf("unexpected filtered audit events: %+v", payload.AuditEvents)
	}
}

func TestAdminAuditListRejectsInvalidLimit(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events?limit=501", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
	assertLastAudit(t, memoryStore, "audit.list", "failure", "invalid_limit")
}

func assertLastAudit(t *testing.T, memoryStore *store.MemoryStore, action, outcome, reason string) model.AuditEvent {
	t.Helper()
	events := memoryStore.AuditEvents()
	if len(events) == 0 {
		t.Fatal("expected at least one audit event")
	}
	last := events[len(events)-1]
	if last.Action != action || last.Outcome != outcome {
		t.Fatalf("expected audit %s/%s, got %+v", action, outcome, last)
	}
	if reason == "" {
		return last
	}
	var metadata map[string]string
	if err := json.Unmarshal(last.Metadata, &metadata); err != nil {
		t.Fatalf("decode audit metadata: %v", err)
	}
	if metadata["reason"] != reason {
		t.Fatalf("expected audit reason %q, got %q", reason, metadata["reason"])
	}
	return last
}

func mtlsRequest(method, target, body, clientID string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{clientID}, Subject: pkix.Name{CommonName: clientID}}}}
	return req
}

func TestVerifyAuditEventsRequiresAdminAndReturnsChainStatus(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events/verify?limit=10", "", "admin")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var body struct {
		Valid          bool `json:"valid"`
		VerifiedEvents int  `json:"verified_events"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Valid {
		t.Fatalf("expected audit chain to verify: %#v", body)
	}
}

func TestVerifyAuditEventsRejectsInvalidLimit(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events/verify?limit=999", "", "admin")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebConsoleRequiresAdminClient(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "operator", MTLSSubject: "operator"}); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := httptest.NewRequest(http.MethodGet, "/web/", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing certificate to be rejected, got %d: %s", res.Code, res.Body.String())
	}

	req = mtlsRequest(http.MethodGet, "/web/", "", "operator")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("expected non-admin to be rejected, got %d: %s", res.Code, res.Body.String())
	}

	req = mtlsRequest(http.MethodGet, "/web/", "", "admin")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected admin web console, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "metadata-only") || strings.Contains(res.Body.String(), "decrypt") && !strings.Contains(res.Body.String(), "never decrypts") {
		t.Fatalf("web console must remain metadata-only: %s", res.Body.String())
	}
}

func TestWebClientEnrollmentCreatesOneShotToken(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100, EnrollmentServerURL: "https://custodia.example.internal:8443"})

	getReq := mtlsRequest(http.MethodGet, "/web/client-enrollments", "", "admin")
	getRes := httptest.NewRecorder()
	handler.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("expected enrollment form 200, got %d: %s", getRes.Code, getRes.Body.String())
	}
	if !strings.Contains(getRes.Body.String(), `Create enrollment token`) || !strings.Contains(getRes.Body.String(), `method="post" action="/web/client-enrollments"`) {
		t.Fatalf("enrollment form missing expected controls: %s", getRes.Body.String())
	}

	postReq := httptest.NewRequest(http.MethodPost, "/web/client-enrollments", strings.NewReader("ttl=15m"))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{"admin"}, Subject: pkix.Name{CommonName: "admin"}}}}
	postRes := httptest.NewRecorder()
	handler.ServeHTTP(postRes, postReq)
	if postRes.Code != http.StatusOK {
		t.Fatalf("expected enrollment token 200, got %d: %s", postRes.Code, postRes.Body.String())
	}
	body := postRes.Body.String()
	for _, expected := range []string{"Enrollment token", "https://custodia.example.internal:8443", "custodia-client mtls enroll", "--enrollment-token", "--insecure", "Copy server URL", "Copy token", `data-copy-target="enrollment-server-url"`, `data-copy-target="enrollment-token"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("enrollment page expected token %q, got: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"private key", "private_key", "dek", "plaintext"} {
		if strings.Contains(strings.ToLower(body), forbidden) && !strings.Contains(body, "private keys remain client-side") {
			t.Fatalf("enrollment page leaked forbidden concept %q: %s", forbidden, body)
		}
	}
	assertLastAudit(t, memoryStore, "web.client_enrollment_create", "success", "")
}

func TestWebClientEnrollmentRequiresWebMFASession(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	handler := New(Options{
		Store:                 memoryStore,
		Limiter:               ratelimit.NewMemoryLimiter(),
		AdminClientIDs:        map[string]bool{"admin": true},
		MaxEnvelopesPerSecret: 100,
		ClientRateLimit:       100,
		GlobalRateLimit:       100,
		EnrollmentServerURL:   "https://custodia.example.internal:8443",
		WebMFARequired:        true,
		WebTOTPSecret:         secret,
		WebSessionSecret:      "01234567890123456789012345678901",
		WebSessionTTL:         time.Minute,
		WebSessionSecure:      false,
	})

	blocked := mtlsRequest(http.MethodPost, "/web/client-enrollments", "ttl=15m", "admin")
	blocked.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	blockedRes := httptest.NewRecorder()
	handler.ServeHTTP(blockedRes, blocked)
	if blockedRes.Code != http.StatusSeeOther || blockedRes.Header().Get("Location") != "/web/login" {
		t.Fatalf("expected Web MFA redirect before enrollment creation, got %d location=%q body=%s", blockedRes.Code, blockedRes.Header().Get("Location"), blockedRes.Body.String())
	}

	code, err := webauth.TOTPCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("TOTPCode() error = %v", err)
	}
	login := mtlsRequest(http.MethodPost, "/web/login", "totp="+code, "admin")
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRes := httptest.NewRecorder()
	handler.ServeHTTP(loginRes, login)
	if loginRes.Code != http.StatusSeeOther {
		t.Fatalf("expected login redirect, got %d: %s", loginRes.Code, loginRes.Body.String())
	}
	cookies := loginRes.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected Web MFA session cookie")
	}

	req := mtlsRequest(http.MethodPost, "/web/client-enrollments", "ttl=15m", "admin")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookies[0])
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected enrollment creation after Web MFA session, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "Enrollment token") {
		t.Fatalf("expected token page after Web MFA session, got: %s", res.Body.String())
	}
}

func TestWebClientDetailRevokesClient(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	getReq := mtlsRequest(http.MethodGet, "/web/clients/client_bob", "", "admin")
	getRes := httptest.NewRecorder()
	handler.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("expected client detail 200, got %d: %s", getRes.Code, getRes.Body.String())
	}
	if !strings.Contains(getRes.Body.String(), "Revoke Client") || !strings.Contains(getRes.Body.String(), `action="/web/clients/client_bob/revoke"`) {
		t.Fatalf("client detail missing revoke controls: %s", getRes.Body.String())
	}

	postReq := httptest.NewRequest(http.MethodPost, "/web/clients/client_bob/revoke", strings.NewReader("reason=lost+device&confirm=yes"))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{"admin"}, Subject: pkix.Name{CommonName: "admin"}}}}
	postRes := httptest.NewRecorder()
	handler.ServeHTTP(postRes, postReq)
	if postRes.Code != http.StatusSeeOther {
		t.Fatalf("expected client revoke redirect, got %d: %s", postRes.Code, postRes.Body.String())
	}
	if got := postRes.Header().Get("Location"); got != "/web/clients/client_bob?revoked=1" {
		t.Fatalf("unexpected revoke redirect location %q", got)
	}
	client, err := memoryStore.GetClient(ctx, "client_bob")
	if err != nil {
		t.Fatalf("get revoked client: %v", err)
	}
	if client.IsActive || client.RevokedAt == nil {
		t.Fatalf("expected client to be revoked, got %+v", client)
	}
	assertLastAudit(t, memoryStore, "web.client_revoke", "success", "")
}

func TestWebSecretMetadataWorkflow(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	createBody := `{"namespace":"default","key":"alice-bob-demo","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtYWxpY2U="},{"client_id":"client_bob","envelope":"ZW52ZWxvcGUtYm9i"}],"permissions":7}`
	createReq := mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_alice")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", createRes.Code, createRes.Body.String())
	}

	getReq := mtlsRequest(http.MethodGet, "/web/secret-metadata?namespace=default&key=alice-bob-demo", "", "admin")
	getRes := httptest.NewRecorder()
	handler.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("expected secret metadata 200, got %d: %s", getRes.Code, getRes.Body.String())
	}
	body := getRes.Body.String()
	for _, expected := range []string{"Secret Metadata", "alice-bob-demo", "client_alice", "client_bob", "Access Grants", `action="/web/secret-metadata/revoke"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("secret metadata page missing %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"Y2lwaGVydGV4dA==", "ZW52ZWxvcGUt", "private_key", "wrapped_dek"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("secret metadata leaked cryptographic material %q: %s", forbidden, body)
		}
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/web/secret-metadata/revoke", strings.NewReader("namespace=default&key=alice-bob-demo&owner_client_id=client_alice&target_client_id=client_bob&confirm=yes"))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeReq.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{"admin"}, Subject: pkix.Name{CommonName: "admin"}}}}
	revokeRes := httptest.NewRecorder()
	handler.ServeHTTP(revokeRes, revokeReq)
	if revokeRes.Code != http.StatusSeeOther {
		t.Fatalf("expected secret access revoke redirect, got %d: %s", revokeRes.Code, revokeRes.Body.String())
	}
	if got := revokeRes.Header().Get("Location"); !strings.Contains(got, "/web/secret-metadata?") || !strings.Contains(got, "revoked_client_id=client_bob") {
		t.Fatalf("unexpected revoke redirect location %q", got)
	}

	bobReq := mtlsRequest(http.MethodGet, "/v1/secrets/by-key?namespace=default&key=alice-bob-demo", "", "client_bob")
	bobRes := httptest.NewRecorder()
	handler.ServeHTTP(bobRes, bobReq)
	if bobRes.Code != http.StatusForbidden && bobRes.Code != http.StatusNotFound {
		t.Fatalf("expected bob read after web access revoke to fail, got %d: %s", bobRes.Code, bobRes.Body.String())
	}
	assertLastAudit(t, memoryStore, "secret.read", "failure", "")
}

func TestWebRevocationStatusPage(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/revocation", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected revocation status page 200, got %d: %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	for _, expected := range []string{"Revocation Status", "Client CRL", "not configured", "Check serial", "strong revocation"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("revocation status page missing %q: %s", expected, body)
		}
	}
	assertLastAudit(t, memoryStore, "web.revocation_status", "success", "")
}

func TestWebRevocationCRLDownloadAndSerialCheck(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	caFile, crlFile := writeTestClientCRL(t, big.NewInt(0x64))
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100, ClientCAFile: caFile, ClientCRLFile: crlFile})

	pageReq := mtlsRequest(http.MethodGet, "/web/revocation", "", "admin")
	pageRes := httptest.NewRecorder()
	handler.ServeHTTP(pageRes, pageReq)
	if pageRes.Code != http.StatusOK {
		t.Fatalf("expected revocation page 200, got %d: %s", pageRes.Code, pageRes.Body.String())
	}
	for _, expected := range []string{"Download client CRL PEM", "Check serial", "Revoked certificates", "1"} {
		if !strings.Contains(pageRes.Body.String(), expected) {
			t.Fatalf("revocation page missing %q: %s", expected, pageRes.Body.String())
		}
	}

	downloadReq := mtlsRequest(http.MethodGet, "/web/revocation/client.crl.pem", "", "admin")
	downloadRes := httptest.NewRecorder()
	handler.ServeHTTP(downloadRes, downloadReq)
	if downloadRes.Code != http.StatusOK {
		t.Fatalf("expected CRL download 200, got %d: %s", downloadRes.Code, downloadRes.Body.String())
	}
	if got := downloadRes.Header().Get("Content-Type"); got != "application/pkix-crl" {
		t.Fatalf("unexpected CRL content type %q", got)
	}
	if got := downloadRes.Header().Get("Content-Disposition"); !strings.Contains(got, "custodia-client.crl.pem") {
		t.Fatalf("unexpected CRL content disposition %q", got)
	}
	if !strings.Contains(downloadRes.Body.String(), "BEGIN X509 CRL") {
		t.Fatalf("expected PEM CRL body, got: %s", downloadRes.Body.String())
	}

	revokedReq := mtlsRequest(http.MethodGet, "/web/revocation/check-serial?serial_hex=64", "", "admin")
	revokedRes := httptest.NewRecorder()
	handler.ServeHTTP(revokedRes, revokedReq)
	if revokedRes.Code != http.StatusOK {
		t.Fatalf("expected serial check 200, got %d: %s", revokedRes.Code, revokedRes.Body.String())
	}
	for _, expected := range []string{"Serial result", "revoked", "64"} {
		if !strings.Contains(revokedRes.Body.String(), expected) {
			t.Fatalf("revoked serial page missing %q: %s", expected, revokedRes.Body.String())
		}
	}

	goodReq := mtlsRequest(http.MethodGet, "/web/revocation/check-serial?serial_hex=65", "", "admin")
	goodRes := httptest.NewRecorder()
	handler.ServeHTTP(goodRes, goodReq)
	if goodRes.Code != http.StatusOK || !strings.Contains(goodRes.Body.String(), "good") {
		t.Fatalf("expected good serial status, got %d: %s", goodRes.Code, goodRes.Body.String())
	}

	missingReq := mtlsRequest(http.MethodGet, "/web/revocation/check-serial", "", "admin")
	missingRes := httptest.NewRecorder()
	handler.ServeHTTP(missingRes, missingReq)
	if missingRes.Code != http.StatusBadRequest || !strings.Contains(missingRes.Body.String(), "missing_serial_hex") {
		t.Fatalf("expected missing serial error, got %d: %s", missingRes.Code, missingRes.Body.String())
	}
}

func writeTestClientCRL(t *testing.T, revokedSerial *big.Int) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now().UTC().Add(-time.Minute)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Custodia Test Client CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   revokedSerial,
			RevocationTime: now,
		}},
	}, caCert, key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	dir := t.TempDir()
	caFile := dir + "/client-ca.crt"
	crlFile := dir + "/client.crl.pem"
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	if err := os.WriteFile(crlFile, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}), 0o600); err != nil {
		t.Fatalf("write CRL file: %v", err)
	}
	return caFile, crlFile
}

func TestWebClientEnrollmentRejectsInvalidTTL(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100, EnrollmentServerURL: "https://custodia.example.internal:8443"})

	req := httptest.NewRequest(http.MethodPost, "/web/client-enrollments", strings.NewReader("ttl=25h"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{"admin"}, Subject: pkix.Name{CommonName: "admin"}}}}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid ttl 400, got %d: %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	if !strings.Contains(body, "invalid_ttl") || !strings.Contains(body, "TTL must not exceed 24h") || !strings.Contains(body, "Enrollment error") {
		t.Fatalf("expected friendly invalid_ttl page, got: %s", body)
	}
}

func TestAPIListsSecretAccessMetadataOnlyForShareClient(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	createBody := `{"key":"shared","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"},{"client_id":"client_bob","envelope":"ZW52ZWxvcGUtZm9yLWJvYg=="}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", res.Code, res.Body.String())
	}
	var created model.SecretVersionRef
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode created: %v", err)
	}

	req = mtlsRequest(http.MethodGet, "/v1/secrets/"+created.SecretID+"/access", "", "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected access list 200, got %d: %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	if strings.Contains(body, "ZW52ZWxvcGUt") || strings.Contains(body, "ciphertext") {
		t.Fatalf("access listing leaked opaque secret material: %s", body)
	}
	var payload struct {
		Access []model.SecretAccessMetadata `json:"access"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode access list: %v", err)
	}
	if len(payload.Access) != 2 {
		t.Fatalf("expected two access metadata rows, got %+v", payload.Access)
	}
	assertLastAudit(t, memoryStore, "secret.access_list", "success", "")
}

func TestAPIListsSecretVersionsMetadataOnly(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	createBody := `{"key":"rotated","ciphertext":"Y2lwaGVydGV4dC12MQ==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtdjE="}],"permissions":7}`
	req := mtlsRequest(http.MethodPost, "/v1/secrets", createBody, "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", res.Code, res.Body.String())
	}
	var created model.SecretVersionRef
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode created: %v", err)
	}

	versionBody := `{"ciphertext":"Y2lwaGVydGV4dC12Mg==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtdjI="}],"permissions":7}`
	req = mtlsRequest(http.MethodPost, "/v1/secrets/"+created.SecretID+"/versions", versionBody, "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected version 201, got %d: %s", res.Code, res.Body.String())
	}

	req = mtlsRequest(http.MethodGet, "/v1/secrets/"+created.SecretID+"/versions", "", "client_alice")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected version list 200, got %d: %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	if strings.Contains(body, "Y2lwaGVydGV4d") || strings.Contains(body, "ZW52ZWxvcGU") {
		t.Fatalf("version listing leaked opaque secret material: %s", body)
	}
	var payload struct {
		Versions []model.SecretVersionMetadata `json:"versions"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode versions: %v", err)
	}
	if len(payload.Versions) != 2 || payload.Versions[0].RevokedAt != nil || payload.Versions[1].RevokedAt == nil {
		t.Fatalf("unexpected version metadata: %+v", payload.Versions)
	}
	assertLastAudit(t, memoryStore, "secret.version_list", "success", "")
}

func TestAdminCanExportAuditEventsAsJSONL(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/audit-events?limit=10", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected audit list 200, got %d: %s", res.Code, res.Body.String())
	}

	req = mtlsRequest(http.MethodGet, "/v1/audit-events/export?limit=10", "", "admin")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected audit export 200, got %d: %s", res.Code, res.Body.String())
	}
	if got := res.Header().Get("Content-Type"); !strings.Contains(got, "application/x-ndjson") {
		t.Fatalf("expected JSONL content type, got %q", got)
	}
	if got := res.Header().Get("X-Custodia-Audit-Export-SHA256"); len(got) != 64 {
		t.Fatalf("expected SHA-256 export header, got %q", got)
	}
	if got := res.Header().Get("X-Custodia-Audit-Export-Events"); got == "" {
		t.Fatalf("expected exported event count header")
	}
	lines := strings.Split(strings.TrimSpace(res.Body.String()), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], `"action":"audit.list"`) {
		t.Fatalf("expected exported audit JSONL, got %q", res.Body.String())
	}
	assertLastAudit(t, memoryStore, "audit.export", "success", "")
}

func TestWebAuditExportDownloadsFilteredJSONL(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := memoryStore.AppendAudit(ctx, model.AuditEvent{EventID: "event-1", ActorClientID: "admin", Action: "secret.read", ResourceType: "secret", ResourceID: "secret-one", Outcome: "success", OccurredAt: time.Now().UTC()}); err != nil {
		t.Fatalf("append audit: %v", err)
	}
	if err := memoryStore.AppendAudit(ctx, model.AuditEvent{EventID: "event-2", ActorClientID: "admin", Action: "secret.read", ResourceType: "secret", ResourceID: "secret-two", Outcome: "failure", OccurredAt: time.Now().UTC()}); err != nil {
		t.Fatalf("append audit: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/audit/export?limit=10&outcome=failure&action=secret.read&resource_type=secret&resource_id=secret-two", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected web audit export 200, got %d: %s", res.Code, res.Body.String())
	}
	if got := res.Header().Get("Content-Type"); !strings.Contains(got, "application/x-ndjson") {
		t.Fatalf("expected JSONL content type, got %q", got)
	}
	if got := res.Header().Get("Content-Disposition"); !strings.Contains(got, "custodia-web-audit.jsonl") {
		t.Fatalf("expected web audit export filename, got %q", got)
	}
	if got := res.Header().Get("X-Custodia-Audit-Export-SHA256"); len(got) != 64 {
		t.Fatalf("expected SHA-256 export header, got %q", got)
	}
	if got := res.Header().Get("X-Custodia-Audit-Export-Events"); got != "1" {
		t.Fatalf("expected one exported event, got %q", got)
	}
	body := res.Body.String()
	if !strings.Contains(body, `"event_id":"event-2"`) || strings.Contains(body, `"event_id":"event-1"`) {
		t.Fatalf("expected filtered JSONL body, got %q", body)
	}
	assertLastAudit(t, memoryStore, "web.audit_export", "success", "")
}

func TestAdminCanReadVersion(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/version", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected version 200, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"version"`) || !strings.Contains(res.Body.String(), `"commit"`) {
		t.Fatalf("expected build metadata, got %s", res.Body.String())
	}
	assertLastAudit(t, memoryStore, "version.read", "success", "")
}

func TestAdminCanReadOperationalStatus(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 5000, StoreBackend: "memory", RateLimitBackend: "memory", DeploymentMode: "multi-region", DatabaseHATarget: "cockroachdb", AuditShipmentSink: "s3://audit/custodia"})

	req := mtlsRequest(http.MethodGet, "/v1/status", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	for _, token := range []string{`"status":"success"`, `"store":"ok"`, `"store_backend":"memory"`, `"rate_limiter":"ok"`, `"rate_limit_backend":"memory"`, `"max_envelopes_per_secret":100`, `"web_mfa_required":false`, `"web_passkey_enabled":false`, `"web_passkey_user_verification":"required"`, `"web_passkey_credential_key_storage":"opaque_cose"`, `"web_passkey_credential_key_parser":"cose_es256_rs256"`, `"web_passkey_assertion_verifier":"preverify_only"`, `"deployment_mode":"multi-region"`, `"database_ha_target":"cockroachdb"`, `"audit_shipment_sink":"s3://audit/custodia"`} {
		if !strings.Contains(body, token) {
			t.Fatalf("expected %s in status body: %s", token, body)
		}
	}
	assertLastAudit(t, memoryStore, "status.read", "success", "")
}

func TestAPIAdminGetsClientMetadata(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_bob", MTLSSubject: "client_bob"}); err != nil {
		t.Fatalf("create bob: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/clients/client_bob", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var client model.Client
	if err := json.NewDecoder(res.Body).Decode(&client); err != nil {
		t.Fatalf("decode client: %v", err)
	}
	if client.ClientID != "client_bob" || client.MTLSSubject != "client_bob" {
		t.Fatalf("unexpected client metadata: %+v", client)
	}
}

func TestAPIAdminListsPendingAccessRequestsWithStatusFilter(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	created, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Key:         "secret",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := memoryStore.RequestAccessGrant(ctx, "admin", created.SecretID, model.AccessGrantRequest{TargetClientID: "client_bob", Permissions: int(model.PermissionRead)}); err != nil {
		t.Fatalf("request grant: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/access-requests?status=pending", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		AccessRequests []model.AccessGrantMetadata `json:"access_requests"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode requests: %v", err)
	}
	if len(payload.AccessRequests) != 1 || payload.AccessRequests[0].Status != "pending" {
		t.Fatalf("unexpected pending requests: %+v", payload.AccessRequests)
	}
}

func TestAPIAdminListsPendingAccessRequestsWithoutEnvelopes(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, id := range []string{"admin", "client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: id, MTLSSubject: id}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	created, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Key:         "secret",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := memoryStore.RequestAccessGrant(ctx, "admin", created.SecretID, model.AccessGrantRequest{TargetClientID: "client_bob", Permissions: int(model.PermissionRead)}); err != nil {
		t.Fatalf("request access: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/access-requests?secret_id="+created.SecretID, "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), "envelope") || !strings.Contains(res.Body.String(), "client_bob") {
		t.Fatalf("expected metadata-only pending grant listing, got %s", res.Body.String())
	}
}

func TestAPIRateLimitsUnauthenticatedRequestsByRemoteIP(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100, IPRateLimit: 1})

	for i, expected := range []int{http.StatusUnauthorized, http.StatusTooManyRequests} {
		req := httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(`{}`))
		req.RemoteAddr = "192.0.2.10:12345"
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != expected {
			t.Fatalf("request %d expected %d, got %d: %s", i+1, expected, res.Code, res.Body.String())
		}
	}
}

func TestAPIRejectsInvalidSecretIDPath(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})
	req := mtlsRequest(http.MethodGet, "/v1/secrets/not-a-uuid", "", "client_alice")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "invalid_secret_id") {
		t.Fatalf("expected invalid secret id error, got %s", res.Body.String())
	}
}

func TestAPIAdminAccessRequestsRejectsInvalidKeyspaceFilters(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	tests := []struct {
		name      string
		path      string
		wantError string
	}{
		{name: "namespace", path: "/v1/access-requests?namespace=db%0A01", wantError: "invalid_namespace_filter"},
		{name: "key", path: "/v1/access-requests?key=user%0Asys", wantError: "invalid_key_filter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mtlsRequest(http.MethodGet, tt.path, "", "admin")
			res := httptest.NewRecorder()

			handler.ServeHTTP(res, req)

			if res.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
			}
			if !strings.Contains(res.Body.String(), tt.wantError) {
				t.Fatalf("expected %s, got %s", tt.wantError, res.Body.String())
			}
		})
	}
}

func TestAPIAdminAccessRequestsRejectsInvalidLimit(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})
	req := mtlsRequest(http.MethodGet, "/v1/access-requests?limit=501", "", "admin")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "invalid_limit") {
		t.Fatalf("expected invalid limit error, got %s", res.Body.String())
	}
}

func TestAPIRejectsInvalidClientIDPathSegments(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/clients/bad%20id", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "invalid_client_id") {
		t.Fatalf("expected invalid client id error, got %s", res.Body.String())
	}
}

func TestAPIAdminClientListSupportsLimit(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_a", "client_b"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/clients?limit=1", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Clients []model.Client `json:"clients"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode clients: %v", err)
	}
	if len(payload.Clients) != 1 {
		t.Fatalf("expected one client after limit, got %+v", payload.Clients)
	}
}

func TestAPISecretListSupportsLimit(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	for _, name := range []string{"secret-a", "secret-b"} {
		if _, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Key: name, Ciphertext: "Y2lwaGVydGV4dA==", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}}, Permissions: int(model.PermissionAll)}); err != nil {
			t.Fatalf("create secret %s: %v", name, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/secrets?limit=1", "", "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Secrets []model.SecretMetadata `json:"secrets"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode secrets: %v", err)
	}
	if len(payload.Secrets) != 1 {
		t.Fatalf("expected one secret after limit, got %+v", payload.Secrets)
	}
}

func TestAPISecretVersionListSupportsLimit(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	ref, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Key: "secret", Ciphertext: "Y2lwaGVydGV4dA==", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}}, Permissions: int(model.PermissionAll)})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := memoryStore.CreateSecretVersion(ctx, "client_alice", ref.SecretID, model.CreateSecretVersionRequest{Ciphertext: "bmV3LWNpcGhlcnRleHQ=", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "bmV3LWVudmVsb3Bl"}}, Permissions: int(model.PermissionAll)}); err != nil {
		t.Fatalf("create version: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/secrets/"+ref.SecretID+"/versions?limit=1", "", "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Versions []model.SecretVersionMetadata `json:"versions"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode versions: %v", err)
	}
	if len(payload.Versions) != 1 {
		t.Fatalf("expected one version after limit, got %+v", payload.Versions)
	}
}

func TestAPISecretAccessListSupportsLimit(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	ref, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Key: "secret", Ciphertext: "Y2lwaGVydGV4dA==", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}, {ClientID: "client_bob", Envelope: "ZW52ZWxvcGUy"}}, Permissions: int(model.PermissionAll)})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/secrets/"+ref.SecretID+"/access?limit=1", "", "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Access []model.SecretAccessMetadata `json:"access"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode access: %v", err)
	}
	if len(payload.Access) != 1 {
		t.Fatalf("expected one access row after limit, got %+v", payload.Access)
	}
}

func TestAPIRateLimitResponsesIncludeRetryAfter(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	handler := New(Options{Store: memoryStore, Limiter: denyLimiter{}, AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100, IPRateLimit: 100})
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", res.Code, res.Body.String())
	}
	if got := res.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("expected Retry-After=1, got %q", got)
	}
}

type denyLimiter struct{}

func (denyLimiter) Allow(context.Context, string, int) (bool, error) { return false, nil }

func TestWebConsoleRequiresAdminMTLS(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/", "", "client_alice")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebAccessRequestsRejectsInvalidRequesterFilter(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/access-requests?requested_by_client_id=bad/client", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebAccessRequestsRejectsInvalidClientFilter(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/access-requests?client_id=bad/client", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebAccessRequestsRejectsInvalidStatusFilter(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/access-requests?status=done", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebAccessRequestsRejectsInvalidLimit(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/access-requests?limit=-1", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebClientsRejectsInvalidActiveFilter(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/clients?active=maybe", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebAuditVerifyRejectsInvalidLimit(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/audit/verify?limit=999", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebAuditRejectsInvalidOutcomeFilter(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/audit?outcome=maybe", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebAuditRejectsInvalidLimit(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/audit?limit=0", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebConsoleDataTablesAreClientPaginated(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	for i := 0; i < 16; i++ {
		clientID := "client_" + strconv.Itoa(i+1)
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %d: %v", i, err)
		}
		if err := memoryStore.AppendAudit(ctx, model.AuditEvent{EventID: strconv.Itoa(i + 1), ActorClientID: "admin", Action: "web.audit_list", ResourceType: "audit_event", Outcome: "success"}); err != nil {
			t.Fatalf("append audit %d: %v", i, err)
		}
	}
	ref, err := memoryStore.CreateSecret(ctx, "admin", model.CreateSecretRequest{Key: "pagination secret", Ciphertext: "c2VjcmV0LWNpcGhlcnRleHQ=", Envelopes: []model.RecipientEnvelope{{ClientID: "admin", Envelope: "c2VjcmV0LWVudmVsb3Bl"}}, Permissions: int(model.PermissionAll)})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	for i := 0; i < 16; i++ {
		clientID := "client_" + strconv.Itoa(i+1)
		if _, err := memoryStore.RequestAccessGrant(ctx, "admin", ref.SecretID, model.AccessGrantRequest{TargetClientID: clientID, Permissions: int(model.PermissionRead)}); err != nil {
			t.Fatalf("request grant %d: %v", i, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	assertWebConsolePagination(t, handler, "/web/audit", "Audit Events pagination")
	assertWebConsolePagination(t, handler, "/web/clients", "Clients pagination")
	assertWebConsolePagination(t, handler, "/web/access-requests", "Access Requests pagination")
}

func assertWebConsolePagination(t *testing.T, handler http.Handler, path string, label string) {
	t.Helper()
	req := mtlsRequest(http.MethodGet, path, "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("%s expected 200, got %d: %s", path, res.Code, res.Body.String())
	}
	body := res.Body.String()
	for _, expected := range []string{`data-console-pagination="true"`, `data-page-size="10"`, `data-pagination-label="` + label + `"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("%s expected pagination token %q, got: %s", path, expected, body)
		}
	}
}

func TestWebConsoleRendersMetadataOnlyPages(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	ref, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Key: "db password", Ciphertext: "c2VjcmV0LWNpcGhlcnRleHQ=", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "c2VjcmV0LWVudmVsb3Bl"}}, Permissions: int(model.PermissionAll)})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := memoryStore.RequestAccessGrant(ctx, "admin", ref.SecretID, model.AccessGrantRequest{TargetClientID: "client_bob", Permissions: int(model.PermissionRead)}); err != nil {
		t.Fatalf("request grant: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	for _, path := range []string{"/web/", "/web/status", "/web/clients", "/web/client-enrollments", "/web/revocation", "/web/access-requests", "/web/audit", "/web/audit/verify"} {
		req := mtlsRequest(http.MethodGet, path, "", "admin")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s expected 200, got %d: %s", path, res.Code, res.Body.String())
		}
		body := res.Body.String()
		if strings.Contains(body, "c2VjcmV0LWNpcGhlcnRleHQ=") || strings.Contains(body, "c2VjcmV0LWVudmVsb3Bl") {
			t.Fatalf("%s leaked opaque crypto payload: %s", path, body)
		}
		if path == "/web/access-requests" {
			for _, expected := range []string{`class="console-keyspace"`, `class="console-keyspace__namespace">default</span>`, `<code>db password</code>`, `Filter grants by the public keyspace tuple used by clients. Internal secret identifiers are intentionally not part of this workflow.`} {
				if !strings.Contains(body, expected) {
					t.Fatalf("access requests page expected keyspace token %q, got: %s", expected, body)
				}
			}
		}
	}
}

func TestWebClientDetailShowsVisibleKeyspaceAndShares(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	if _, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Namespace:  "db01",
		Key:        "user:sys",
		Ciphertext: "c2VjcmV0LWNpcGhlcnRleHQ=",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "YWxpY2UtZW52ZWxvcGU="},
			{ClientID: "client_bob", Envelope: "Ym9iLWVudmVsb3Bl"},
		},
		Permissions: int(model.PermissionAll),
	}); err != nil {
		t.Fatalf("create shared secret: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	listReq := mtlsRequest(http.MethodGet, "/web/clients", "", "admin")
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("expected clients 200, got %d: %s", listRes.Code, listRes.Body.String())
	}
	if !strings.Contains(listRes.Body.String(), `href="/web/clients/client_alice"`) {
		t.Fatalf("clients page did not link client detail: %s", listRes.Body.String())
	}

	detailReq := mtlsRequest(http.MethodGet, "/web/clients/client_alice", "", "admin")
	detailRes := httptest.NewRecorder()
	handler.ServeHTTP(detailRes, detailReq)
	if detailRes.Code != http.StatusOK {
		t.Fatalf("expected client detail 200, got %d: %s", detailRes.Code, detailRes.Body.String())
	}
	body := detailRes.Body.String()
	for _, expected := range []string{
		"Visible Keyspace",
		"Shares From This Client",
		`class="console-keyspace__namespace">db01</span>`,
		"<code>user:sys</code>",
		"owned by this client",
		"client_bob",
		"read, update, share",
		"Secret plaintext, ciphertext, envelopes and DEKs are never rendered.",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("client detail expected token %q, got: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"c2VjcmV0LWNpcGhlcnRleHQ=", "YWxpY2UtZW52ZWxvcGU=", "Ym9iLWVudmVsb3Bl"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("client detail leaked crypto payload token %q: %s", forbidden, body)
		}
	}

	sharedReq := mtlsRequest(http.MethodGet, "/web/clients/client_bob", "", "admin")
	sharedRes := httptest.NewRecorder()
	handler.ServeHTTP(sharedRes, sharedReq)
	if sharedRes.Code != http.StatusOK {
		t.Fatalf("expected shared client detail 200, got %d: %s", sharedRes.Code, sharedRes.Body.String())
	}
	if !strings.Contains(sharedRes.Body.String(), "shared with this client") || !strings.Contains(sharedRes.Body.String(), "client_alice") {
		t.Fatalf("shared client detail did not show owner/relationship: %s", sharedRes.Body.String())
	}
}

func TestWebConsoleRendersResponsiveHTMXSkeleton(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected console page, got %d: %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	for _, expected := range []string{
		`class="console-app-shell"`,
		`class="console-sidebar"`,
		`class="console-mobile-nav"`,
		`id="console-main"`,
		`hx-boost="true"`,
		`hx-target="#console-main"`,
		`/web/assets/console.css`,
		`/web/assets/console.js`,
		`/web/assets/favicon.svg`,
		`data-console-refresh-control`,
		`data-refresh-interval`,
		`data-refresh-now`,
		`data-refresh-updated`,
		`<option value="5">5 seconds</option>`,
		`<option value="10" selected>10 seconds</option>`,
		`<option value="15">15 seconds</option>`,
		`<option value="30">30 seconds</option>`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected responsive console skeleton token %q in body: %s", expected, body)
		}
	}
	if strings.Contains(body, "prefers-color-scheme") {
		t.Fatalf("web console must not keep dark/light mode switching CSS: %s", body)
	}
	if strings.Contains(body, "<style>") || strings.Contains(body, "style-src 'unsafe-inline'") {
		t.Fatalf("web console must load local CSS asset instead of inline styles: %s", body)
	}
}

func TestWebConsoleAssetIsLocalAndAdminOnly(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	cases := []struct {
		path        string
		contentType string
		file        string
		tokens      []string
	}{
		{
			path:        "/web/assets/console.js",
			contentType: "text/javascript",
			file:        "web_assets/console.js",
			tokens:      []string{"swapMain", "initPaginatedTables", "initCopyButtons", "initRefreshControls", "refreshCurrentView", "custodia.console.refreshSeconds", "Refresh in ${remaining}s", "Refresh paused while editing", "document.visibilityState === 'hidden'", "setLastUpdated", "Table pagination", "custodia.console.paginationPage.", "data-pagination-first", "Showing ${start + 1}–${Math.min(end, rows.length)} of ${rows.length}", "Page ${currentPage + 1} of ${pageCount}", "responseURL.pathname === '/web/login'", "nextMain.classList.contains('console-auth-shell')", "data-copy-value", "Copied", "Select and copy"},
		},
		{
			path:        "/web/assets/console.css",
			contentType: "text/css",
			file:        "web_assets/console.css",
			tokens:      []string{"SPDX-License-Identifier: AGPL-3.0-only", ".console-refresh-controls {", ".console-refresh-status, .console-refresh-updated", ".console-hero p { max-width: none; }", ".console-auth-card h1 { font-size: clamp(3.4rem, 8vw, 5rem); line-height: 0.76; text-align: center; }", ".console-security-boundary p:not(.console-panel-label) { max-width: none; margin-bottom: 0; }"},
		},
	}

	for _, tc := range cases {
		unauthenticatedReq := httptest.NewRequest(http.MethodGet, tc.path, nil)
		unauthenticatedRes := httptest.NewRecorder()
		handler.ServeHTTP(unauthenticatedRes, unauthenticatedReq)
		if unauthenticatedRes.Code != http.StatusUnauthorized {
			t.Fatalf("expected unauthenticated asset request %s to require mTLS, got %d", tc.path, unauthenticatedRes.Code)
		}

		req := mtlsRequest(http.MethodGet, tc.path, "", "admin")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("expected local console asset %s, got %d: %s", tc.path, res.Code, res.Body.String())
		}
		if contentType := res.Header().Get("Content-Type"); !strings.Contains(contentType, tc.contentType) {
			t.Fatalf("expected %s content type for %s, got %q", tc.contentType, tc.path, contentType)
		}
		body := res.Body.String()
		for _, expected := range tc.tokens {
			if !strings.Contains(body, expected) {
				t.Fatalf("expected local console asset %s token %q, got: %s", tc.path, expected, body)
			}
		}
		if strings.Contains(body, "https://") {
			t.Fatalf("expected self-hosted console asset without remote URLs: %s", body)
		}
		asset, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read console asset %s: %v", tc.file, err)
		}
		if body != string(asset) {
			t.Fatalf("expected console asset response %s to match embedded local file", tc.path)
		}
	}
}

func TestWebConsoleServesLocalFavicon(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	for _, path := range []string{"/favicon.ico", "/web/assets/favicon.svg"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s expected local favicon, got %d: %s", path, res.Code, res.Body.String())
		}
		if contentType := res.Header().Get("Content-Type"); !strings.Contains(contentType, "image/svg+xml") {
			t.Fatalf("%s expected svg favicon content type, got %q", path, contentType)
		}
		if !strings.Contains(res.Body.String(), "Custodia") || strings.Contains(res.Body.String(), "https://") {
			t.Fatalf("%s expected self-hosted Custodia favicon without remote references: %s", path, res.Body.String())
		}
	}
}

func TestWebConsoleRendersStyledNotFoundPages(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "operator", MTLSSubject: "operator"}); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	unauthenticatedWebReq := httptest.NewRequest(http.MethodGet, "/web/", nil)
	unauthenticatedWebRes := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticatedWebRes, unauthenticatedWebReq)
	if unauthenticatedWebRes.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing web mTLS to render 401, got %d: %s", unauthenticatedWebRes.Code, unauthenticatedWebRes.Body.String())
	}
	if body := unauthenticatedWebRes.Body.String(); !strings.Contains(body, `>401</h1>`) || !strings.Contains(body, `console-error-shell`) || strings.Contains(body, `{"error"`) {
		t.Fatalf("expected missing web mTLS to render styled html 401, got: %s", body)
	}

	forbiddenWebReq := mtlsRequest(http.MethodGet, "/web/", "", "operator")
	forbiddenWebRes := httptest.NewRecorder()
	handler.ServeHTTP(forbiddenWebRes, forbiddenWebReq)
	if forbiddenWebRes.Code != http.StatusForbidden {
		t.Fatalf("expected non-admin web mTLS client to render 403, got %d: %s", forbiddenWebRes.Code, forbiddenWebRes.Body.String())
	}
	if body := forbiddenWebRes.Body.String(); !strings.Contains(body, `>403</h1>`) || !strings.Contains(body, `console-error-shell`) || strings.Contains(body, `{"error"`) {
		t.Fatalf("expected non-admin web client to render styled html 403, got: %s", body)
	}

	passkeyReq := mtlsRequest(http.MethodGet, "/web/passkey/authenticate/options", "", "operator")
	passkeyRes := httptest.NewRecorder()
	handler.ServeHTTP(passkeyRes, passkeyReq)
	if passkeyRes.Code != http.StatusForbidden || !strings.Contains(passkeyRes.Body.String(), `{"error":"admin_required"}`) {
		t.Fatalf("expected passkey JSON endpoint to keep JSON auth errors, got %d: %s", passkeyRes.Code, passkeyRes.Body.String())
	}

	passkeyMethodReq := mtlsRequest(http.MethodPut, "/web/passkey/authenticate/options", "", "admin")
	passkeyMethodRes := httptest.NewRecorder()
	handler.ServeHTTP(passkeyMethodRes, passkeyMethodReq)
	if passkeyMethodRes.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected passkey method error to stay non-html 405, got %d: %s", passkeyMethodRes.Code, passkeyMethodRes.Body.String())
	}
	if strings.Contains(passkeyMethodRes.Body.String(), "console-error-shell") || strings.Contains(passkeyMethodRes.Body.String(), "Custodia Console") {
		t.Fatalf("passkey JSON endpoint method errors must not render HTML console errors: %s", passkeyMethodRes.Body.String())
	}

	unknownWebReq := mtlsRequest(http.MethodGet, "/web/does-not-exist", "", "admin")
	unknownWebRes := httptest.NewRecorder()
	handler.ServeHTTP(unknownWebRes, unknownWebReq)
	if unknownWebRes.Code != http.StatusNotFound {
		t.Fatalf("expected unknown web console route to return 404, got %d: %s", unknownWebRes.Code, unknownWebRes.Body.String())
	}
	unknownWebBody := unknownWebRes.Body.String()
	if !strings.Contains(unknownWebBody, ">404</h1>") || !strings.Contains(unknownWebBody, "Back to home") {
		t.Fatalf("expected styled console 404 body, got: %s", unknownWebBody)
	}
	if strings.Contains(unknownWebBody, ">Page not found</h1>") {
		t.Fatalf("expected compact numeric 404 title, got: %s", unknownWebBody)
	}
	if !strings.Contains(unknownWebBody, "console-error-shell") || strings.Contains(unknownWebBody, `class="console-login-brand"`) {
		t.Fatalf("expected compact standalone 404 layout, got: %s", unknownWebBody)
	}
	if strings.Contains(unknownWebBody, `aria-label="Console sections"`) {
		t.Fatalf("unknown web route rendered the overview instead of 404: %s", unknownWebBody)
	}
	if !strings.Contains(unknownWebBody, `/web/assets/console.css`) || strings.Contains(unknownWebBody, "<style>") {
		t.Fatalf("expected styled 404 to load local CSS asset without inline style: %s", unknownWebBody)
	}
	if !strings.Contains(unknownWebRes.Header().Get("Content-Security-Policy"), "style-src 'self'") || strings.Contains(unknownWebRes.Header().Get("Content-Security-Policy"), "style-src 'unsafe-inline'") {
		t.Fatalf("expected strict web CSP on styled 404, got %q", unknownWebRes.Header().Get("Content-Security-Policy"))
	}

	outsideWebReq := httptest.NewRequest(http.MethodGet, "/404pagina", nil)
	outsideWebRes := httptest.NewRecorder()
	WebOnly(handler).ServeHTTP(outsideWebRes, outsideWebReq)
	if outsideWebRes.Code != http.StatusNotFound {
		t.Fatalf("expected web listener unknown route to return 404, got %d: %s", outsideWebRes.Code, outsideWebRes.Body.String())
	}
	if contentType := outsideWebRes.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
		t.Fatalf("expected web listener unknown route to render html 404, got %q", contentType)
	}
	outsideWebBody := outsideWebRes.Body.String()
	if !strings.Contains(outsideWebBody, ">404</h1>") {
		t.Fatalf("expected styled web listener 404 body, got: %s", outsideWebBody)
	}
	if !strings.Contains(outsideWebBody, "console-error-shell") || strings.Contains(outsideWebBody, `class="console-login-brand"`) {
		t.Fatalf("expected compact standalone web listener 404 layout, got: %s", outsideWebBody)
	}

	invalidFilterReq := mtlsRequest(http.MethodGet, "/web/clients?active=maybe", "", "admin")
	invalidFilterRes := httptest.NewRecorder()
	handler.ServeHTTP(invalidFilterRes, invalidFilterReq)
	if invalidFilterRes.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid web filter to render 400, got %d: %s", invalidFilterRes.Code, invalidFilterRes.Body.String())
	}
	invalidFilterBody := invalidFilterRes.Body.String()
	for _, expected := range []string{`<title>Bad request – Custodia</title>`, `aria-label="Bad request"`, `>400</h1>`, "The Custodia Console could not process this request. Check the submitted values and try again."} {
		if !strings.Contains(invalidFilterBody, expected) {
			t.Fatalf("expected generic bad request error token %q, got: %s", expected, invalidFilterBody)
		}
	}
	if strings.Contains(invalidFilterBody, `{"error"`) {
		t.Fatalf("expected web filter error to render html, got JSON: %s", invalidFilterBody)
	}

	methodReq := mtlsRequest(http.MethodPut, "/web/login", "", "admin")
	methodRes := httptest.NewRecorder()
	handler.ServeHTTP(methodRes, methodReq)
	if methodRes.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected login method error to render 405, got %d: %s", methodRes.Code, methodRes.Body.String())
	}
	methodBody := methodRes.Body.String()
	for _, expected := range []string{`<title>Method not allowed – Custodia</title>`, `aria-label="Method not allowed"`, `>405</h1>`, "The requested method is not allowed for this Custodia Console page."} {
		if !strings.Contains(methodBody, expected) {
			t.Fatalf("expected generic method error token %q, got: %s", expected, methodBody)
		}
	}
}

func TestWebConsoleCSPAllowsOnlyLocalEnhancements(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	policy := res.Header().Get("Content-Security-Policy")
	for _, expected := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'", "img-src 'self' data:", "frame-ancestors 'none'", "form-action 'self'"} {
		if !strings.Contains(policy, expected) {
			t.Fatalf("expected web CSP token %q in %q", expected, policy)
		}
	}
	if strings.Contains(policy, "unsafe-inline") {
		t.Fatalf("web CSP must not allow inline styles after CSS asset extraction: %q", policy)
	}
}

func TestWebConsoleFilterFormsPreserveSubmittedValues(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	cases := []struct {
		path     string
		expected []string
	}{
		{
			path: "/web/clients?active=true",
			expected: []string{
				`<option value="true" selected>Active</option>`,
			},
		},
		{
			path: "/web/audit?limit=25&outcome=failure&action=secret.read&actor_client_id=client_alice&resource_type=secret&resource_id=secret-one",
			expected: []string{
				`name="limit" inputmode="numeric" placeholder="100" value="25"`,
				`<option value="failure" selected>Failure</option>`,
				`name="action" placeholder="secret.read" value="secret.read"`,
				`name="actor_client_id" placeholder="client_alice" value="client_alice"`,
				`name="resource_type" placeholder="secret" value="secret"`,
				`name="resource_id" placeholder="client_alice" value="secret-one"`,
				`href="/web/audit/export?action=secret.read&amp;actor_client_id=client_alice&amp;limit=25&amp;outcome=failure&amp;resource_id=secret-one&amp;resource_type=secret"`,
			},
		},
		{
			path: "/web/access-requests?limit=25&namespace=db01&key=user:sys&status=pending&client_id=client_bob&requested_by_client_id=admin",
			expected: []string{
				`name="limit" inputmode="numeric" placeholder="100" value="25"`,
				`name="namespace" placeholder="default" value="db01"`,
				`name="key" placeholder="user:sys" value="user:sys"`,
				`<option value="pending" selected>Pending</option>`,
				`name="client_id" placeholder="client_bob" value="client_bob"`,
				`name="requested_by_client_id" placeholder="admin" value="admin"`,
			},
		},
		{
			path: "/web/audit/verify?limit=17",
			expected: []string{
				`name="limit" inputmode="numeric" placeholder="500" value="17"`,
			},
		},
	}
	for _, tc := range cases {
		req := mtlsRequest(http.MethodGet, tc.path, "", "admin")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s expected 200, got %d: %s", tc.path, res.Code, res.Body.String())
		}
		body := res.Body.String()
		for _, expected := range tc.expected {
			if !strings.Contains(body, expected) {
				t.Fatalf("%s expected submitted filter token %q, got: %s", tc.path, expected, body)
			}
		}
	}
}

func TestWebConsoleFinalGuardrails(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	for _, path := range []string{"/web/", "/web/status", "/web/clients", "/web/client-enrollments", "/web/audit", "/web/login", "/web/does-not-exist"} {
		method := http.MethodGet
		req := mtlsRequest(method, path, "", "admin")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code < 200 || res.Code >= 500 {
			t.Fatalf("%s expected non-5xx console response, got %d: %s", path, res.Code, res.Body.String())
		}
		body := res.Body.String()
		for _, forbidden := range []string{"https://", "http://", "<style>", "style-src 'unsafe-inline'", "Admin metadata console", "Custodia Metadata Console", `class="console-login-brand"`} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s contains forbidden console token %q: %s", path, forbidden, body)
			}
		}
		if !strings.Contains(body, `/web/assets/console.css`) {
			t.Fatalf("%s must load the local CSS asset: %s", path, body)
		}
	}

	loginReq := mtlsRequest(http.MethodGet, "/web/login", "", "admin")
	loginRes := httptest.NewRecorder()
	handler.ServeHTTP(loginRes, loginReq)
	loginBody := loginRes.Body.String()
	if !strings.Contains(loginBody, `type="password" inputmode="numeric" autocomplete="one-time-code"`) {
		t.Fatalf("TOTP input must stay password typed: %s", loginBody)
	}

	css, err := os.ReadFile("web_assets/console.css")
	if err != nil {
		t.Fatalf("read console css: %v", err)
	}
	js, err := os.ReadFile("web_assets/console.js")
	if err != nil {
		t.Fatalf("read console js: %v", err)
	}
	for name, content := range map[string]string{"console.css": string(css), "console.js": string(js)} {
		for _, forbidden := range []string{"https://", "http://", "@import", "prefers-color-scheme", "console-login-brand"} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s contains forbidden asset token %q", name, forbidden)
			}
		}
	}
}

func TestWebLoginUsesSingleCardLayout(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/login", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected login page, got %d: %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	for _, expected := range []string{`/web/assets/console.css`, `class="console-auth-shell"`, `class="console-auth-card"`, `<div class="console-brand"><span class="console-logo" aria-hidden="true">C</span><span>Custodia</span></div>`, `<p class="console-kicker">Custodia Console</p>`, `<h1 id="auth-title">Verify Access</h1>`, `type="password" inputmode="numeric" autocomplete="one-time-code"`, `class="console-auth-form"`, `class="console-auth-actions"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected single-card login layout token %q, got: %s", expected, body)
		}
	}
	for _, unexpected := range []string{`class="console-login-brand"`, `class="console-auth-brand"`, `<h1>Custodia</h1>`, `class="console-error-card console-auth-card"`, `.console-auth-card h1 + p`, `.console-auth-card form button { width: 100%; }`, `.console-panel { display: grid; gap: 8px; padding: 18px; }`, `.console-grid + .console-panel { margin-top: 18px; }`, `<p class="console-kicker">Admin metadata console</p>`, `<p class="console-kicker">Security boundary</p>`, `Custodia Metadata Console`, `<style>`} {
		if strings.Contains(body, unexpected) {
			t.Fatalf("expected login layout to avoid stale split/auth styling token %q, got: %s", unexpected, body)
		}
	}
}

func TestWebConsoleRequiresTOTPWhenConfigured(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{
		Store:            memoryStore,
		Limiter:          ratelimit.NewMemoryLimiter(),
		AdminClientIDs:   map[string]bool{"admin": true},
		ClientRateLimit:  100,
		GlobalRateLimit:  100,
		WebMFARequired:   true,
		WebTOTPSecret:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		WebSessionSecret: "01234567890123456789012345678901",
		WebSessionTTL:    time.Minute,
		WebSessionSecure: false,
	})

	req := mtlsRequest(http.MethodGet, "/web/", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/web/login" {
		t.Fatalf("expected redirect to login, got %d location=%q body=%s", res.Code, res.Header().Get("Location"), res.Body.String())
	}
}

func TestWebTOTPLoginUnlocksConsole(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	handler := New(Options{
		Store:            memoryStore,
		Limiter:          ratelimit.NewMemoryLimiter(),
		AdminClientIDs:   map[string]bool{"admin": true},
		ClientRateLimit:  100,
		GlobalRateLimit:  100,
		WebMFARequired:   true,
		WebTOTPSecret:    secret,
		WebSessionSecret: "01234567890123456789012345678901",
		WebSessionTTL:    time.Minute,
		WebSessionSecure: false,
	})
	code, err := webauth.TOTPCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("TOTPCode() error = %v", err)
	}

	login := mtlsRequest(http.MethodPost, "/web/login", "totp="+code, "admin")
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRes := httptest.NewRecorder()
	handler.ServeHTTP(loginRes, login)
	if loginRes.Code != http.StatusSeeOther {
		t.Fatalf("expected login redirect, got %d: %s", loginRes.Code, loginRes.Body.String())
	}
	cookie := loginRes.Result().Cookies()[0]

	page := mtlsRequest(http.MethodGet, "/web/", "", "admin")
	page.AddCookie(cookie)
	pageRes := httptest.NewRecorder()
	handler.ServeHTTP(pageRes, page)
	pageBody := pageRes.Body.String()
	if pageRes.Code != http.StatusOK || !strings.Contains(pageBody, "Custodia Console") {
		t.Fatalf("expected unlocked console, got %d: %s", pageRes.Code, pageBody)
	}
	if strings.Contains(pageBody, "Admin metadata console") || strings.Contains(pageBody, "Custodia Metadata Console") {
		t.Fatalf("expected unified console branding, got: %s", pageBody)
	}
	for _, expected := range []string{`class="console-panel console-security-boundary"`, `<p class="console-panel-label">Security boundary</p>`} {
		if !strings.Contains(pageBody, expected) {
			t.Fatalf("expected dedicated security boundary panel token %q, got: %s", expected, pageBody)
		}
	}
	if !strings.Contains(pageBody, `method="post" action="/web/logout"`) || !strings.Contains(pageBody, "Logout") {
		t.Fatalf("expected authenticated console to render logout control: %s", pageBody)
	}
}

func TestWebLoginAllowsCrossOriginPreSessionHandoff(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	handler := New(Options{
		Store:            memoryStore,
		Limiter:          ratelimit.NewMemoryLimiter(),
		AdminClientIDs:   map[string]bool{"admin": true},
		ClientRateLimit:  100,
		GlobalRateLimit:  100,
		WebMFARequired:   true,
		WebTOTPSecret:    secret,
		WebSessionSecret: "01234567890123456789012345678901",
		WebSessionTTL:    time.Minute,
		WebSessionSecure: false,
	})
	code, err := webauth.TOTPCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("TOTPCode() error = %v", err)
	}

	login := mtlsRequest(http.MethodPost, "/web/login", "totp="+code, "admin")
	login.Host = "192.0.2.10:9443"
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	login.Header.Set("Origin", "https://192.0.2.10:9443")
	loginRes := httptest.NewRecorder()
	handler.ServeHTTP(loginRes, login)
	if loginRes.Code != http.StatusSeeOther {
		t.Fatalf("expected login redirect, got %d: %s", loginRes.Code, loginRes.Body.String())
	}
}

func TestWebLogoutClearsSessionCookie(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{
		Store:            memoryStore,
		Limiter:          ratelimit.NewMemoryLimiter(),
		AdminClientIDs:   map[string]bool{"admin": true},
		ClientRateLimit:  100,
		GlobalRateLimit:  100,
		WebMFARequired:   true,
		WebTOTPSecret:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		WebSessionSecret: "01234567890123456789012345678901",
		WebSessionTTL:    time.Minute,
		WebSessionSecure: false,
	})

	logout := mtlsRequest(http.MethodPost, "/web/logout", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, logout)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/web/login" {
		t.Fatalf("expected logout redirect to login, got %d location=%q body=%s", res.Code, res.Header().Get("Location"), res.Body.String())
	}
	cookies := res.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != webauth.SessionCookieName || cookies[0].MaxAge != -1 {
		t.Fatalf("expected expired web session cookie, got %#v", cookies)
	}
}

func TestWebTOTPLoginRejectsInvalidCode(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{
		Store:            memoryStore,
		Limiter:          ratelimit.NewMemoryLimiter(),
		AdminClientIDs:   map[string]bool{"admin": true},
		ClientRateLimit:  100,
		GlobalRateLimit:  100,
		WebMFARequired:   true,
		WebTOTPSecret:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		WebSessionSecret: "01234567890123456789012345678901",
		WebSessionTTL:    time.Minute,
	})

	login := mtlsRequest(http.MethodPost, "/web/login", "totp=000000", "admin")
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, login)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected invalid TOTP 401, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebPasskeyOptionsRequireEnablement(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/web/passkey/register/options", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("expected disabled passkey 404, got %d: %s", res.Code, res.Body.String())
	}
}

func TestWebPasskeyOptionsReturnMetadataOnlyChallenges(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{
		Store:                  memoryStore,
		Limiter:                ratelimit.NewMemoryLimiter(),
		AdminClientIDs:         map[string]bool{"admin": true},
		ClientRateLimit:        100,
		GlobalRateLimit:        100,
		WebPasskeyEnabled:      true,
		WebPasskeyRPID:         "vault.example.com",
		WebPasskeyRPName:       "Custodia Vault",
		WebPasskeyChallengeTTL: time.Minute,
	})

	for _, path := range []string{"/web/passkey/register/options", "/web/passkey/authenticate/options"} {
		req := mtlsRequest(http.MethodGet, path, "", "admin")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s expected 200, got %d: %s", path, res.Code, res.Body.String())
		}
		var payload webauth.PasskeyOptions
		if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
			t.Fatalf("decode passkey options: %v", err)
		}
		if payload.RPID != "vault.example.com" || payload.RPName != "Custodia Vault" || payload.UserID != "admin" || payload.Challenge == "" {
			t.Fatalf("unexpected passkey payload: %+v", payload)
		}
		body := res.Body.String()
		if strings.Contains(body, "ciphertext") || strings.Contains(body, "envelope") {
			t.Fatalf("passkey options leaked secret payload wording: %s", body)
		}
	}
}

func TestAdminCanReadUnconfiguredRevocationStatus(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	req := mtlsRequest(http.MethodGet, "/v1/revocation/status", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload model.RevocationStatus
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode revocation status: %v", err)
	}
	if payload.Configured || !payload.Valid {
		t.Fatalf("unexpected unconfigured revocation status: %+v", payload)
	}
	assertLastAudit(t, memoryStore, "revocation.status", "success", "")
}

func TestWebPasskeyAuthenticateVerifyConsumesChallengeOnce(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{
		Store:                  memoryStore,
		Limiter:                ratelimit.NewMemoryLimiter(),
		AdminClientIDs:         map[string]bool{"admin": true},
		ClientRateLimit:        100,
		GlobalRateLimit:        100,
		WebPasskeyEnabled:      true,
		WebPasskeyRPID:         "example.com",
		WebPasskeyRPName:       "Custodia Vault",
		WebPasskeyChallengeTTL: time.Minute,
	})

	registerPasskeyCredential(t, handler, "admin", "example.com", "credential-1")

	registerPasskeyCredential(t, handler, "admin", "example.com", "credential-1")

	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/authenticate/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	if optionsRes.Code != http.StatusOK {
		t.Fatalf("options status = %d: %s", optionsRes.Code, optionsRes.Body.String())
	}
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	payload := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.get", Challenge: options.Challenge, Origin: "https://example.com"})

	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/authenticate/verify", `{"client_data_json":"`+payload+`","credential_id":"credential-1"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusOK {
		t.Fatalf("verify status = %d: %s", verifyRes.Code, verifyRes.Body.String())
	}

	replayReq := mtlsRequest(http.MethodPost, "/web/passkey/authenticate/verify", `{"client_data_json":"`+payload+`","credential_id":"credential-1"}`, "admin")
	replayReq.Host = "example.com"
	replayReq.Header.Set("Content-Type", "application/json")
	replayRes := httptest.NewRecorder()
	handler.ServeHTTP(replayRes, replayReq)
	if replayRes.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want %d: %s", replayRes.Code, http.StatusUnauthorized, replayRes.Body.String())
	}
}

func TestWebPasskeyAuthenticateVerifyRejectsWrongOrigin(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, ClientRateLimit: 100, GlobalRateLimit: 100, WebPasskeyEnabled: true, WebPasskeyRPID: "example.com", WebPasskeyRPName: "Custodia Vault", WebPasskeyChallengeTTL: time.Minute})

	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/authenticate/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	payload := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.get", Challenge: options.Challenge, Origin: "https://evil.example.com"})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/authenticate/verify", `{"client_data_json":"`+payload+`","credential_id":"credential-1"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusUnauthorized {
		t.Fatalf("verify status = %d, want %d: %s", verifyRes.Code, http.StatusUnauthorized, verifyRes.Body.String())
	}
}

func registerPasskeyCredential(t *testing.T, handler http.Handler, clientID, host, credentialID string) {
	t.Helper()
	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/register/options", "", clientID)
	optionsReq.Host = host
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	if optionsRes.Code != http.StatusOK {
		t.Fatalf("register options status = %d: %s", optionsRes.Code, optionsRes.Body.String())
	}
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode register options: %v", err)
	}
	payload := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.create", Challenge: options.Challenge, Origin: "https://" + host})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/register/verify", `{"client_data_json":"`+payload+`","credential_id":"`+credentialID+`","credential_key_cose":"`+passkeyCredentialKeyCOSEPayload()+`"}`, clientID)
	verifyReq.Host = host
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusOK {
		t.Fatalf("register verify status = %d: %s", verifyRes.Code, verifyRes.Body.String())
	}
}

func TestWebPasskeyRegisterVerifyRequiresCredentialKeyCOSE(t *testing.T) {
	handler := newPasskeyCounterTestHandler(t)
	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/register/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsReq.Header.Set("X-Forwarded-Proto", "https")
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	if optionsRes.Code != http.StatusOK {
		t.Fatalf("options status = %d, body = %s", optionsRes.Code, optionsRes.Body.String())
	}
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	payload := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.create", Challenge: options.Challenge, Origin: "https://example.com"})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/register/verify", `{"client_data_json":"`+payload+`","credential_id":"credential-missing-cose"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("X-Forwarded-Proto", "https")
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusBadRequest {
		t.Fatalf("verify status = %d, want %d: %s", verifyRes.Code, http.StatusBadRequest, verifyRes.Body.String())
	}
}

func passkeyClientDataPayload(t *testing.T, data webauth.PasskeyClientData) string {
	t.Helper()
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func TestWebPasskeyRegisterVerifyRequiresCredentialID(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, ClientRateLimit: 100, GlobalRateLimit: 100, WebPasskeyEnabled: true, WebPasskeyRPID: "example.com", WebPasskeyRPName: "Custodia Vault", WebPasskeyChallengeTTL: time.Minute})
	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/register/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	payload := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.create", Challenge: options.Challenge, Origin: "https://example.com"})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/register/verify", `{"client_data_json":"`+payload+`"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusBadRequest {
		t.Fatalf("verify status = %d, want %d: %s", verifyRes.Code, http.StatusBadRequest, verifyRes.Body.String())
	}
}

func TestWebPasskeyAuthenticateVerifyRejectsUnknownCredential(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, ClientRateLimit: 100, GlobalRateLimit: 100, WebPasskeyEnabled: true, WebPasskeyRPID: "example.com", WebPasskeyRPName: "Custodia Vault", WebPasskeyChallengeTTL: time.Minute})
	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/authenticate/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	payload := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.get", Challenge: options.Challenge, Origin: "https://example.com"})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/authenticate/verify", `{"client_data_json":"`+payload+`","credential_id":"missing"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusUnauthorized {
		t.Fatalf("verify status = %d, want %d: %s", verifyRes.Code, http.StatusUnauthorized, verifyRes.Body.String())
	}
}

func TestStatusReportsPasskeyCredentialCount(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100, WebPasskeyEnabled: true, WebPasskeyRPID: "example.com", WebPasskeyRPName: "Custodia Vault", WebPasskeyChallengeTTL: time.Minute})
	registerPasskeyCredential(t, handler, "admin", "example.com", "credential-1")

	req := mtlsRequest(http.MethodGet, "/v1/status", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"web_passkey_credentials":1`) {
		t.Fatalf("missing passkey credential count: %s", res.Body.String())
	}
}

func TestWebPasskeyAuthenticateVerifyRejectsNonIncreasingSignCount(t *testing.T) {
	handler := newPasskeyCounterTestHandler(t)
	registerPasskeyCredentialWithAuthenticatorData(t, handler, "admin", "example.com", "credential-2", 7)

	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/authenticate/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsReq.Header.Set("X-Forwarded-Proto", "https")
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	if optionsRes.Code != http.StatusOK {
		t.Fatalf("options status = %d, body = %s", optionsRes.Code, optionsRes.Body.String())
	}
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	clientData := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.get", Challenge: options.Challenge, Origin: "https://example.com"})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/authenticate/verify", `{"client_data_json":"`+clientData+`","credential_id":"credential-2","authenticator_data":"`+passkeyAuthenticatorDataPayload(7)+`"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("X-Forwarded-Proto", "https")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusUnauthorized {
		t.Fatalf("verify status = %d, want %d: %s", verifyRes.Code, http.StatusUnauthorized, verifyRes.Body.String())
	}
	if !strings.Contains(verifyRes.Body.String(), "invalid_sign_count") {
		t.Fatalf("missing sign count error: %s", verifyRes.Body.String())
	}
}

func TestWebPasskeyAuthenticateVerifyAcceptsIncreasingSignCount(t *testing.T) {
	handler := newPasskeyCounterTestHandler(t)
	registerPasskeyCredentialWithAuthenticatorData(t, handler, "admin", "example.com", "credential-3", 7)

	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/authenticate/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsReq.Header.Set("X-Forwarded-Proto", "https")
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	if optionsRes.Code != http.StatusOK {
		t.Fatalf("options status = %d, body = %s", optionsRes.Code, optionsRes.Body.String())
	}
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	clientData := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.get", Challenge: options.Challenge, Origin: "https://example.com"})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/authenticate/verify", `{"client_data_json":"`+clientData+`","credential_id":"credential-3","authenticator_data":"`+passkeyAuthenticatorDataPayload(8)+`"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("X-Forwarded-Proto", "https")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want %d: %s", verifyRes.Code, http.StatusOK, verifyRes.Body.String())
	}
	if !strings.Contains(verifyRes.Body.String(), `"sign_count":8`) {
		t.Fatalf("missing sign count response: %s", verifyRes.Body.String())
	}
}

func newPasskeyCounterTestHandler(t *testing.T) http.Handler {
	t.Helper()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(context.Background(), model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	return New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100, WebPasskeyEnabled: true, WebPasskeyRPID: "example.com", WebPasskeyRPName: "Custodia"})
}

func TestWebPasskeyAuthenticateVerifyRejectsWrongRPIDHash(t *testing.T) {
	handler := newPasskeyCounterTestHandler(t)
	registerPasskeyCredentialWithAuthenticatorData(t, handler, "admin", "example.com", "credential-rpid", 7)

	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/authenticate/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsReq.Header.Set("X-Forwarded-Proto", "https")
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	if optionsRes.Code != http.StatusOK {
		t.Fatalf("options status = %d, body = %s", optionsRes.Code, optionsRes.Body.String())
	}
	var options webauth.PasskeyOptions
	if err := json.Unmarshal(optionsRes.Body.Bytes(), &options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	clientData := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.get", Challenge: options.Challenge, Origin: "https://example.com"})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/authenticate/verify", `{"client_data_json":"`+clientData+`","credential_id":"credential-rpid","authenticator_data":"`+passkeyAuthenticatorDataPayloadForRPID("evil.example.com", 0x05, 8)+`"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("X-Forwarded-Proto", "https")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusUnauthorized {
		t.Fatalf("verify status = %d, body = %s", verifyRes.Code, verifyRes.Body.String())
	}
}

func TestWebPasskeyAuthenticateVerifyRequiresUserVerificationFlag(t *testing.T) {
	handler := newPasskeyCounterTestHandler(t)
	registerPasskeyCredentialWithAuthenticatorData(t, handler, "admin", "example.com", "credential-uv", 7)

	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/authenticate/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsReq.Header.Set("X-Forwarded-Proto", "https")
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	if optionsRes.Code != http.StatusOK {
		t.Fatalf("options status = %d, body = %s", optionsRes.Code, optionsRes.Body.String())
	}
	var options webauth.PasskeyOptions
	if err := json.Unmarshal(optionsRes.Body.Bytes(), &options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	clientData := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.get", Challenge: options.Challenge, Origin: "https://example.com"})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/authenticate/verify", `{"client_data_json":"`+clientData+`","credential_id":"credential-uv","authenticator_data":"`+passkeyAuthenticatorDataPayloadForRPID("example.com", 0x01, 8)+`"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("X-Forwarded-Proto", "https")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusUnauthorized {
		t.Fatalf("verify status = %d, body = %s", verifyRes.Code, verifyRes.Body.String())
	}
}

func registerPasskeyCredentialWithAuthenticatorData(t *testing.T, handler http.Handler, clientID, host, credentialID string, signCount uint32) {
	t.Helper()
	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/register/options", "", clientID)
	optionsReq.Host = host
	optionsReq.Header.Set("X-Forwarded-Proto", "https")
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	if optionsRes.Code != http.StatusOK {
		t.Fatalf("register options status = %d, body = %s", optionsRes.Code, optionsRes.Body.String())
	}
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode register options: %v", err)
	}
	payload := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.create", Challenge: options.Challenge, Origin: "https://" + host})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/register/verify", `{"client_data_json":"`+payload+`","credential_id":"`+credentialID+`","authenticator_data":"`+passkeyAuthenticatorDataPayload(signCount)+`","credential_key_cose":"`+passkeyCredentialKeyCOSEPayload()+`"}`, clientID)
	verifyReq.Host = host
	verifyReq.Header.Set("X-Forwarded-Proto", "https")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusOK {
		t.Fatalf("register verify status = %d, body = %s", verifyRes.Code, verifyRes.Body.String())
	}
}

func passkeyCredentialKeyCOSEPayload() string {
	key := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	for i := 0; i < 32; i++ {
		key = append(key, byte(i+1))
	}
	key = append(key, 0x22, 0x58, 0x20)
	for i := 0; i < 32; i++ {
		key = append(key, byte(i+33))
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

func passkeyAuthenticatorDataPayload(signCount uint32) string {
	return passkeyAuthenticatorDataPayloadForRPID("example.com", 0x05, signCount)
}

func passkeyAuthenticatorDataPayloadForRPID(rpID string, flags byte, signCount uint32) string {
	raw := make([]byte, 37)
	digest := sha256.Sum256([]byte(rpID))
	copy(raw[:32], digest[:])
	raw[32] = flags
	raw[33] = byte(signCount >> 24)
	raw[34] = byte(signCount >> 16)
	raw[35] = byte(signCount >> 8)
	raw[36] = byte(signCount)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestWebPasskeyRegisterVerifyRejectsInvalidCredentialKeyCOSE(t *testing.T) {
	handler := newPasskeyCounterTestHandler(t)
	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/register/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsReq.Header.Set("X-Forwarded-Proto", "https")
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	if optionsRes.Code != http.StatusOK {
		t.Fatalf("register options status = %d", optionsRes.Code)
	}
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode register options: %v", err)
	}
	payload := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.create", Challenge: options.Challenge, Origin: "https://example.com"})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/register/verify", `{"client_data_json":"`+payload+`","credential_id":"credential-invalid-cose","credential_key_cose":"oA"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("X-Forwarded-Proto", "https")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusBadRequest {
		t.Fatalf("register verify status = %d, body = %s", verifyRes.Code, verifyRes.Body.String())
	}
}

func TestWebPasskeyAuthenticateVerifyUsesExternalAssertionVerifier(t *testing.T) {
	command := writePasskeyAssertionVerifierScript(t, `#!/usr/bin/env sh
cat >/dev/null
printf '{"valid":true}
'
`)
	handler := newPasskeyAssertionVerifierTestHandler(t, command)
	registerPasskeyCredentialWithAuthenticatorData(t, handler, "admin", "example.com", "credential-external", 7)

	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/authenticate/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsReq.Header.Set("X-Forwarded-Proto", "https")
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	if optionsRes.Code != http.StatusOK {
		t.Fatalf("options status = %d, body = %s", optionsRes.Code, optionsRes.Body.String())
	}
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	clientData := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.get", Challenge: options.Challenge, Origin: "https://example.com"})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/authenticate/verify", `{"client_data_json":"`+clientData+`","credential_id":"credential-external","authenticator_data":"`+passkeyAuthenticatorDataPayload(8)+`","signature":"c2lnbmF0dXJl"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("X-Forwarded-Proto", "https")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", verifyRes.Code, verifyRes.Body.String())
	}
}

func TestWebPasskeyAuthenticateVerifyRequiresSignatureWhenExternalVerifierConfigured(t *testing.T) {
	command := writePasskeyAssertionVerifierScript(t, `#!/usr/bin/env sh
cat >/dev/null
printf '{"valid":true}
'
`)
	handler := newPasskeyAssertionVerifierTestHandler(t, command)
	registerPasskeyCredentialWithAuthenticatorData(t, handler, "admin", "example.com", "credential-no-signature", 7)

	optionsReq := mtlsRequest(http.MethodGet, "/web/passkey/authenticate/options", "", "admin")
	optionsReq.Host = "example.com"
	optionsReq.Header.Set("X-Forwarded-Proto", "https")
	optionsRes := httptest.NewRecorder()
	handler.ServeHTTP(optionsRes, optionsReq)
	var options webauth.PasskeyOptions
	if err := json.NewDecoder(optionsRes.Body).Decode(&options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	clientData := passkeyClientDataPayload(t, webauth.PasskeyClientData{Type: "webauthn.get", Challenge: options.Challenge, Origin: "https://example.com"})
	verifyReq := mtlsRequest(http.MethodPost, "/web/passkey/authenticate/verify", `{"client_data_json":"`+clientData+`","credential_id":"credential-no-signature","authenticator_data":"`+passkeyAuthenticatorDataPayload(8)+`"}`, "admin")
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("X-Forwarded-Proto", "https")
	verifyRes := httptest.NewRecorder()
	handler.ServeHTTP(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusUnauthorized {
		t.Fatalf("verify status = %d, want %d: %s", verifyRes.Code, http.StatusUnauthorized, verifyRes.Body.String())
	}
	if !strings.Contains(verifyRes.Body.String(), "missing_assertion_signature_material") {
		t.Fatalf("missing assertion signature error: %s", verifyRes.Body.String())
	}
}

func newPasskeyAssertionVerifierTestHandler(t *testing.T, command string) http.Handler {
	t.Helper()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(context.Background(), model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	return New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100, WebPasskeyEnabled: true, WebPasskeyRPID: "example.com", WebPasskeyRPName: "Custodia", WebPasskeyAssertionVerifyCommand: command})
}

func writePasskeyAssertionVerifierScript(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/verify-passkey"
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func TestStatusReportsExternalPasskeyAssertionVerifier(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100, WebPasskeyAssertionVerifyCommand: "/usr/local/bin/verify-passkey"})
	req := mtlsRequest(http.MethodGet, "/v1/status", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"web_passkey_assertion_verifier":"external_command"`) {
		t.Fatalf("missing external verifier status: %s", res.Body.String())
	}
}

func TestDedicatedListenerRouteFilters(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	apiReq := mtlsRequest(http.MethodGet, "/v1/status", "", "admin")
	apiRes := httptest.NewRecorder()
	APIOnly(handler).ServeHTTP(apiRes, apiReq)
	if apiRes.Code != http.StatusOK {
		t.Fatalf("expected API listener to serve API route, got %d: %s", apiRes.Code, apiRes.Body.String())
	}

	blockedWebReq := mtlsRequest(http.MethodGet, "/web/status", "", "admin")
	blockedWebRes := httptest.NewRecorder()
	APIOnly(handler).ServeHTTP(blockedWebRes, blockedWebReq)
	if blockedWebRes.Code != http.StatusNotFound {
		t.Fatalf("expected API listener to hide web route, got %d", blockedWebRes.Code)
	}

	webReq := mtlsRequest(http.MethodGet, "/web/status", "", "admin")
	webRes := httptest.NewRecorder()
	WebOnly(handler).ServeHTTP(webRes, webReq)
	if webRes.Code != http.StatusOK {
		t.Fatalf("expected web listener to serve web route, got %d: %s", webRes.Code, webRes.Body.String())
	}

	faviconReq := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	faviconRes := httptest.NewRecorder()
	WebOnly(handler).ServeHTTP(faviconRes, faviconReq)
	if faviconRes.Code != http.StatusOK {
		t.Fatalf("expected web listener to serve favicon route, got %d: %s", faviconRes.Code, faviconRes.Body.String())
	}

	blockedAPIReq := mtlsRequest(http.MethodGet, "/v1/status", "", "admin")
	blockedAPIRes := httptest.NewRecorder()
	WebOnly(handler).ServeHTTP(blockedAPIRes, blockedAPIReq)
	if blockedAPIRes.Code != http.StatusNotFound {
		t.Fatalf("expected web listener to hide API route, got %d", blockedAPIRes.Code)
	}
	if !strings.Contains(blockedAPIRes.Body.String(), ">404</h1>") || !strings.Contains(blockedAPIRes.Body.String(), "The requested Custodia Console page does not exist.") {
		t.Fatalf("expected web listener to render a styled 404 page, got: %s", blockedAPIRes.Body.String())
	}
}
