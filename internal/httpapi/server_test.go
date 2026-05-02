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
	if len(payload.Secrets) != 1 || payload.Secrets[0].Name != "visible" || payload.Secrets[0].VersionID == "" {
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
