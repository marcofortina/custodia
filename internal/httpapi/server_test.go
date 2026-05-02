package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"custodia/internal/model"
	"custodia/internal/ratelimit"
	"custodia/internal/store"
)

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
	if read.Ciphertext != "Y2lwaGVydGV4dA==" || read.Envelope != "ZW52ZWxvcGUtZm9yLWFsaWNl" {
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
