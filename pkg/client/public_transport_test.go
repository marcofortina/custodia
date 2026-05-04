package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"custodia/internal/model"
)

func TestPublicGoTransportMethodsAvoidInternalTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.EscapedPath() {
		case "GET /v1/me":
			_ = json.NewEncoder(w).Encode(model.Client{ClientID: "client_alice", MTLSSubject: "client_alice", IsActive: true})
		case "POST /v1/secrets":
			_ = json.NewEncoder(w).Encode(model.SecretVersionRef{SecretID: "secret-id", VersionID: "version-id"})
		case "GET /v1/secrets/secret-id":
			_ = json.NewEncoder(w).Encode(model.SecretReadResponse{SecretID: "secret-id", VersionID: "version-id", Ciphertext: "Y2lwaGVy", Envelope: "ZW52", Permissions: PermissionRead})
		case "POST /v1/secrets/secret-id/share":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "shared"})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
	}))
	defer server.Close()

	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	current, err := custodiaClient.CurrentClientInfo()
	if err != nil || current.ClientID != "client_alice" {
		t.Fatalf("CurrentClientInfo() = %+v err=%v", current, err)
	}
	created, err := custodiaClient.CreateSecretPayload(CreateSecretPayload{
		Name:        "secret",
		Ciphertext:  "Y2lwaGVy",
		Envelopes:   []RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52"}},
		Permissions: PermissionRead,
	})
	if err != nil || created.SecretID != "secret-id" || created.VersionID != "version-id" {
		t.Fatalf("CreateSecretPayload() = %+v err=%v", created, err)
	}
	read, err := custodiaClient.GetSecretPayload("secret-id")
	if err != nil || read.Ciphertext != "Y2lwaGVy" || read.Envelope != "ZW52" {
		t.Fatalf("GetSecretPayload() = %+v err=%v", read, err)
	}
	if err := custodiaClient.ShareSecretPayload("secret-id", ShareSecretPayload{VersionID: "version-id", TargetClientID: "client_bob", Envelope: "ZW52", Permissions: PermissionRead}); err != nil {
		t.Fatalf("ShareSecretPayload() error = %v", err)
	}
}
