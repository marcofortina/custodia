package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"custodia/internal/model"
	"custodia/internal/ratelimit"
	"custodia/internal/store"
)

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
	ref, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Name: "secret", Ciphertext: "Y2lwaGVydGV4dA==", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}}, Permissions: int(model.PermissionAll)})
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
	ref, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Name: "secret", Ciphertext: "Y2lwaGVydGV4dA==", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}}, Permissions: int(model.PermissionAll)})
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

	createBody := `{"name":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_bob","envelope":"ZW52ZWxvcGUtZm9yLWJvYg=="}],"permissions":7}`
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
	createBody := `{"name":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
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

func TestAPIRejectsInvalidPermissionBits(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	body := `{"name":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":8}`
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

	body := `{"name":"secret","ciphertext":"not base64","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
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

	req := httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(`{"name":"secret"}`))
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

	body := `{"name":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}{}`
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

	body := `{"name":"` + strings.Repeat("a", maxJSONBodyBytes+1) + `"}`
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

	body := `{"name":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
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

	body := `{"name":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"},{"client_id":"client_bob","envelope":"ZW52ZWxvcGUtZm9yLWJvYg=="}],"permissions":7}`
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

	createBody := `{"name":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
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

	createBody := `{"name":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
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

	createBody := `{"name":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
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

	createBody := `{"name":"secret","ciphertext":"Y2lwaGVydGV4dC12MQ==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtYWxpY2UtdjE="}],"permissions":7}`
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

	createBody := `{"name":"visible","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
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
	if len(payload.Secrets) != 1 || payload.Secrets[0].Name != "visible" || payload.Secrets[0].VersionID == "" || payload.Secrets[0].CreatedByClientID != "client_alice" {
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

	createBody := `{"name":"secret","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"}],"permissions":7}`
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

func TestAPIListsSecretAccessMetadataOnlyForShareClient(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	createBody := `{"name":"shared","ciphertext":"Y2lwaGVydGV4dA==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtZm9yLWFsaWNl"},{"client_id":"client_bob","envelope":"ZW52ZWxvcGUtZm9yLWJvYg=="}],"permissions":7}`
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

	createBody := `{"name":"rotated","ciphertext":"Y2lwaGVydGV4dC12MQ==","envelopes":[{"client_id":"client_alice","envelope":"ZW52ZWxvcGUtdjE="}],"permissions":7}`
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
	lines := strings.Split(strings.TrimSpace(res.Body.String()), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], `"action":"audit.list"`) {
		t.Fatalf("expected exported audit JSONL, got %q", res.Body.String())
	}
	assertLastAudit(t, memoryStore, "audit.export", "success", "")
}

func TestAdminCanReadOperationalStatus(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 5000, StoreBackend: "memory", RateLimitBackend: "memory"})

	req := mtlsRequest(http.MethodGet, "/v1/status", "", "admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	for _, token := range []string{`"status":"success"`, `"store":"ok"`, `"store_backend":"memory"`, `"rate_limiter":"ok"`, `"rate_limit_backend":"memory"`, `"max_envelopes_per_secret":100`} {
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
		Name:        "secret",
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
		Name:        "secret",
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

func TestAPIAdminAccessRequestsRejectsInvalidSecretIDFilter(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})
	req := mtlsRequest(http.MethodGet, "/v1/access-requests?secret_id=not-a-uuid", "", "admin")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "invalid_secret_id_filter") {
		t.Fatalf("expected invalid secret id filter error, got %s", res.Body.String())
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
		if _, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Name: name, Ciphertext: "Y2lwaGVydGV4dA==", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}}, Permissions: int(model.PermissionAll)}); err != nil {
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
	ref, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Name: "secret", Ciphertext: "Y2lwaGVydGV4dA==", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}}, Permissions: int(model.PermissionAll)})
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
	ref, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Name: "secret", Ciphertext: "Y2lwaGVydGV4dA==", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}, {ClientID: "client_bob", Envelope: "ZW52ZWxvcGUy"}}, Permissions: int(model.PermissionAll)})
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

func TestWebConsoleRendersMetadataOnlyPages(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	for _, clientID := range []string{"admin", "client_alice", "client_bob"} {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
			t.Fatalf("create client %s: %v", clientID, err)
		}
	}
	ref, err := memoryStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{Name: "db password", Ciphertext: "c2VjcmV0LWNpcGhlcnRleHQ=", Envelopes: []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "c2VjcmV0LWVudmVsb3Bl"}}, Permissions: int(model.PermissionAll)})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := memoryStore.RequestAccessGrant(ctx, "admin", ref.SecretID, model.AccessGrantRequest{TargetClientID: "client_bob", Permissions: int(model.PermissionRead)}); err != nil {
		t.Fatalf("request grant: %v", err)
	}
	handler := New(Options{Store: memoryStore, Limiter: ratelimit.NewMemoryLimiter(), AdminClientIDs: map[string]bool{"admin": true}, MaxEnvelopesPerSecret: 100, ClientRateLimit: 100, GlobalRateLimit: 100})

	for _, path := range []string{"/web/", "/web/status", "/web/clients", "/web/access-requests", "/web/audit", "/web/audit/verify"} {
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
	}
}
