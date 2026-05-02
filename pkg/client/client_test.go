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
			if r.URL.Query().Get("limit") != "5" {
				t.Fatalf("unexpected versions limit: %q", r.URL.RawQuery)
			}
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected versions method: %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"versions": []model.SecretVersionMetadata{{SecretID: "secret/id", VersionID: "version"}}})
		case "/v1/secrets/secret%2Fid/access":
			if r.URL.Query().Get("limit") != "7" {
				t.Fatalf("unexpected access limit: %q", r.URL.RawQuery)
			}
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
	versions, err := custodiaClient.ListSecretVersionsWithLimit("secret/id", 5)
	if err != nil || len(versions) != 1 || versions[0].VersionID != "version" {
		t.Fatalf("unexpected versions response: %+v err=%v", versions, err)
	}
	access, err := custodiaClient.ListSecretAccessWithLimit("secret/id", 7)
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
				if len(requests) == 1 && r.URL.Query().Get("limit") != "25" {
					t.Fatalf("unexpected client limit: %q", r.URL.RawQuery)
				}
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
	clients, err := custodiaClient.ListClientsWithLimit(25)
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
		if got := r.URL.Query().Get("client_id"); got != "client_bob" {
			t.Fatalf("unexpected client filter: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_requests": []model.AccessGrantMetadata{{ClientID: "client_bob", Status: "pending"}}})
	}))
	defer server.Close()

	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	requests, err := custodiaClient.ListAccessGrantRequests(AccessGrantRequestFilters{Limit: 25, ClientID: "client_bob", Status: "pending"})
	if err != nil || len(requests) != 1 || requests[0].ClientID != "client_bob" {
		t.Fatalf("unexpected requests response: %+v err=%v", requests, err)
	}
}

func TestClientListSecretsWithLimitUsesQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/v1/secrets" || r.URL.Query().Get("limit") != "10" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []model.SecretMetadata{{SecretID: "secret"}}})
	}))
	defer server.Close()

	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	secrets, err := custodiaClient.ListSecretsWithLimit(10)
	if err != nil || len(secrets) != 1 || secrets[0].SecretID != "secret" {
		t.Fatalf("unexpected secrets response: %+v err=%v", secrets, err)
	}
}

func TestClientListClientsFilteredUsesActiveQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/v1/clients" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		if got := r.URL.Query().Get("active"); got != "false" {
			t.Fatalf("unexpected active filter: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"clients": []model.Client{{ClientID: "client_old", IsActive: false}}})
	}))
	defer server.Close()

	active := false
	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	clients, err := custodiaClient.ListClientsFiltered(ClientListFilters{Limit: 10, Active: &active})
	if err != nil || len(clients) != 1 || clients[0].IsActive {
		t.Fatalf("unexpected clients response: %+v err=%v", clients, err)
	}
}

func TestClientListAuditEventsUsesFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/v1/audit-events" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		if got := r.URL.Query().Get("actor_client_id"); got != "client_alice" {
			t.Fatalf("unexpected actor filter: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"audit_events": []model.AuditEvent{{Action: "secret.read", ActorClientID: "client_alice"}}})
	}))
	defer server.Close()

	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	events, err := custodiaClient.ListAuditEvents(AuditEventFilters{Limit: 25, ActorClientID: "client_alice", Action: "secret.read"})
	if err != nil || len(events) != 1 || events[0].ActorClientID != "client_alice" {
		t.Fatalf("unexpected audit response: %+v err=%v", events, err)
	}
}

func TestClientRejectsInvalidListLimits(t *testing.T) {
	custodiaClient := &Client{baseURL: "http://example.test", http: http.DefaultClient}
	if _, err := custodiaClient.ListClientsWithLimit(501); err == nil {
		t.Fatal("expected client list limit error")
	}
	if _, err := custodiaClient.ListSecretsWithLimit(-1); err == nil {
		t.Fatal("expected secret list limit error")
	}
	if _, err := custodiaClient.ListSecretVersionsWithLimit("550e8400-e29b-41d4-a716-446655440000", 501); err == nil {
		t.Fatal("expected version list limit error")
	}
	if _, err := custodiaClient.ListSecretAccessWithLimit("550e8400-e29b-41d4-a716-446655440000", 501); err == nil {
		t.Fatal("expected access list limit error")
	}
	if _, err := custodiaClient.ListAuditEvents(AuditEventFilters{Limit: 501}); err == nil {
		t.Fatal("expected audit list limit error")
	}
	if _, err := custodiaClient.ListAccessGrantRequests(AccessGrantRequestFilters{Limit: 501}); err == nil {
		t.Fatal("expected access request list limit error")
	}
}

func TestClientExportAuditEventsUsesFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/v1/audit-events/export" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		if got := r.URL.Query().Get("outcome"); got != "failure" {
			t.Fatalf("unexpected outcome filter: %q", got)
		}
		_, _ = w.Write([]byte("{}\n"))
	}))
	defer server.Close()

	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	payload, err := custodiaClient.ExportAuditEvents(AuditEventFilters{Limit: 10, Outcome: "failure"})
	if err != nil {
		t.Fatalf("export audit: %v", err)
	}
	if string(payload) != "{}\n" {
		t.Fatalf("unexpected export payload: %q", string(payload))
	}
}

func TestClientAuditFiltersRejectInvalidValues(t *testing.T) {
	custodiaClient := &Client{}
	if _, err := custodiaClient.ListAuditEvents(AuditEventFilters{Outcome: "maybe"}); err == nil {
		t.Fatal("expected invalid outcome error")
	}
	if _, err := custodiaClient.ListAuditEvents(AuditEventFilters{Action: "bad action"}); err == nil {
		t.Fatal("expected invalid action error")
	}
	if _, err := custodiaClient.ExportAuditEvents(AuditEventFilters{ActorClientID: "client bad"}); err == nil {
		t.Fatal("expected invalid actor client id error")
	}
	if _, err := custodiaClient.ExportAuditEvents(AuditEventFilters{ResourceType: "bad type"}); err == nil {
		t.Fatal("expected invalid resource type error")
	}
	if _, err := custodiaClient.ExportAuditEvents(AuditEventFilters{ResourceID: "bad\nresource"}); err == nil {
		t.Fatal("expected invalid resource id error")
	}
}

func TestClientAccessRequestFiltersRejectInvalidValues(t *testing.T) {
	custodiaClient := &Client{}
	if _, err := custodiaClient.ListAccessGrantRequests(AccessGrantRequestFilters{Limit: 501}); err == nil {
		t.Fatal("expected invalid limit error")
	}
	if _, err := custodiaClient.ListAccessGrantRequests(AccessGrantRequestFilters{SecretID: "not-a-uuid"}); err == nil {
		t.Fatal("expected invalid secret id error")
	}
	if _, err := custodiaClient.ListAccessGrantRequests(AccessGrantRequestFilters{Status: "done"}); err == nil {
		t.Fatal("expected invalid status error")
	}
	if _, err := custodiaClient.ListAccessGrantRequests(AccessGrantRequestFilters{ClientID: "client bad"}); err == nil {
		t.Fatal("expected invalid client id error")
	}
	if _, err := custodiaClient.ListAccessGrantRequests(AccessGrantRequestFilters{RequestedByClientID: "client bad"}); err == nil {
		t.Fatal("expected invalid requester id error")
	}
}
