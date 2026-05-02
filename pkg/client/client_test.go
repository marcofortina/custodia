package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"custodia/internal/model"
)

func TestClientAccessGrantMethodsUseDocumentedAPIPaths(t *testing.T) {
	requests := make([]string, 0, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.EscapedPath())
		switch r.URL.EscapedPath() {
		case "/v1/secrets/secret%2Fid/access-requests":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected grant request method: %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(model.AccessGrantRef{SecretID: "secret/id", VersionID: "version", ClientID: "client/bob", Status: "pending"})
		case "/v1/secrets/secret%2Fid/access/client%2Fbob/activate":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected activate method: %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "activated"})
		case "/v1/secrets/secret%2Fid/access/client%2Fbob":
			if r.Method != http.MethodDelete {
				t.Fatalf("unexpected revoke method: %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
		default:
			t.Fatalf("unexpected path: %s", r.URL.EscapedPath())
		}
	}))
	defer server.Close()

	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	ref, err := custodiaClient.RequestAccessGrant("secret/id", model.AccessGrantRequest{TargetClientID: "client/bob", Permissions: int(model.PermissionRead)})
	if err != nil {
		t.Fatalf("request grant: %v", err)
	}
	if ref.Status != "pending" {
		t.Fatalf("unexpected grant ref: %+v", ref)
	}
	if err := custodiaClient.ActivateAccessGrant("secret/id", "client/bob", model.ActivateAccessRequest{Envelope: "ZW52ZWxvcGU="}); err != nil {
		t.Fatalf("activate grant: %v", err)
	}
	if err := custodiaClient.RevokeAccess("secret/id", "client/bob"); err != nil {
		t.Fatalf("revoke access: %v", err)
	}

	expected := []string{
		"POST /v1/secrets/secret%2Fid/access-requests",
		"POST /v1/secrets/secret%2Fid/access/client%2Fbob/activate",
		"DELETE /v1/secrets/secret%2Fid/access/client%2Fbob",
	}
	if len(requests) != len(expected) {
		t.Fatalf("expected %d requests, got %d: %+v", len(expected), len(requests), requests)
	}
	for idx := range expected {
		if requests[idx] != expected[idx] {
			t.Fatalf("request %d: expected %q, got %q", idx, expected[idx], requests[idx])
		}
	}
}

func TestClientMetadataMethodsUseDocumentedAPIPaths(t *testing.T) {
	requests := make([]string, 0, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.EscapedPath())
		switch r.URL.EscapedPath() {
		case "/v1/secrets/secret%2Fid/versions":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected versions method: %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"versions": []model.SecretVersionMetadata{{SecretID: "secret/id", VersionID: "version"}}})
		case "/v1/secrets/secret%2Fid/access":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected access method: %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access": []model.SecretAccessMetadata{{SecretID: "secret/id", VersionID: "version", ClientID: "client/bob"}}})
		case "/v1/status":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected status method: %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(model.OperationalStatus{Status: "success", Store: "ok", RateLimiter: "ok"})
		default:
			t.Fatalf("unexpected path: %s", r.URL.EscapedPath())
		}
	}))
	defer server.Close()

	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	versions, err := custodiaClient.ListSecretVersions("secret/id")
	if err != nil || len(versions) != 1 || versions[0].VersionID != "version" {
		t.Fatalf("unexpected versions response: %+v err=%v", versions, err)
	}
	access, err := custodiaClient.ListSecretAccess("secret/id")
	if err != nil || len(access) != 1 || access[0].ClientID != "client/bob" {
		t.Fatalf("unexpected access response: %+v err=%v", access, err)
	}
	status, err := custodiaClient.Status()
	if err != nil || status.Status != "success" {
		t.Fatalf("unexpected status response: %+v err=%v", status, err)
	}

	expected := []string{
		"GET /v1/secrets/secret%2Fid/versions",
		"GET /v1/secrets/secret%2Fid/access",
		"GET /v1/status",
	}
	if len(requests) != len(expected) {
		t.Fatalf("expected %d requests, got %d: %+v", len(expected), len(requests), requests)
	}
	for idx := range expected {
		if requests[idx] != expected[idx] {
			t.Fatalf("request %d: expected %q, got %q", idx, expected[idx], requests[idx])
		}
	}
}

func TestClientAdminClientMethodsUseDocumentedAPIPaths(t *testing.T) {
	requests := make([]string, 0, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.EscapedPath())
		switch r.URL.EscapedPath() {
		case "/v1/clients":
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(map[string]any{"clients": []model.Client{{ClientID: "client/alice"}}})
				return
			}
			if r.Method == http.MethodPost {
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "created"})
				return
			}
		case "/v1/clients/client%2Falice":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected get client method: %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(model.Client{ClientID: "client/alice"})
			return
		case "/v1/clients/revoke":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected revoke client method: %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
			return
		}
		t.Fatalf("unexpected path: %s", r.URL.EscapedPath())
	}))
	defer server.Close()

	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	clients, err := custodiaClient.ListClients()
	if err != nil || len(clients) != 1 || clients[0].ClientID != "client/alice" {
		t.Fatalf("unexpected clients response: %+v err=%v", clients, err)
	}
	client, err := custodiaClient.GetClient("client/alice")
	if err != nil || client.ClientID != "client/alice" {
		t.Fatalf("unexpected client response: %+v err=%v", client, err)
	}
	if err := custodiaClient.CreateClient(model.CreateClientRequest{ClientID: "client/alice", MTLSSubject: "client/alice"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := custodiaClient.RevokeClient(model.RevokeClientRequest{ClientID: "client/alice", Reason: "rotation"}); err != nil {
		t.Fatalf("revoke client: %v", err)
	}

	expected := []string{
		"GET /v1/clients",
		"GET /v1/clients/client%2Falice",
		"POST /v1/clients",
		"POST /v1/clients/revoke",
	}
	if len(requests) != len(expected) {
		t.Fatalf("expected %d requests, got %d: %+v", len(expected), len(requests), requests)
	}
	for idx := range expected {
		if requests[idx] != expected[idx] {
			t.Fatalf("request %d: expected %q, got %q", idx, expected[idx], requests[idx])
		}
	}
}

func TestClientMeUsesDocumentedAPIPath(t *testing.T) {
	requests := make([]string, 0, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.EscapedPath())
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/v1/me" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		_ = json.NewEncoder(w).Encode(model.Client{ClientID: "client/alice"})
	}))
	defer server.Close()

	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	client, err := custodiaClient.Me()
	if err != nil || client.ClientID != "client/alice" {
		t.Fatalf("unexpected me response: %+v err=%v", client, err)
	}
	if len(requests) != 1 || requests[0] != "GET /v1/me" {
		t.Fatalf("unexpected paths: %v", requests)
	}
}

func TestClientListAccessGrantRequestsUsesDocumentedAPIPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/v1/access-requests" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		if got := r.URL.Query().Get("client_id"); got != "client/bob" {
			t.Fatalf("unexpected client filter: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_requests": []model.AccessGrantMetadata{{ClientID: "client/bob", Status: "pending"}}})
	}))
	defer server.Close()

	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	requests, err := custodiaClient.ListAccessGrantRequests(AccessGrantRequestFilters{Limit: 25, ClientID: "client/bob", Status: "pending"})
	if err != nil || len(requests) != 1 || requests[0].ClientID != "client/bob" {
		t.Fatalf("unexpected requests response: %+v err=%v", requests, err)
	}
}
