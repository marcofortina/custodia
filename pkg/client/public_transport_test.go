// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

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
		case "GET /v1/secrets/by-key":
			if got := r.URL.Query().Get("namespace"); got != "db01" {
				t.Fatalf("namespace = %q", got)
			}
			if got := r.URL.Query().Get("key"); got != "user:sys" {
				t.Fatalf("key = %q", got)
			}
			_ = json.NewEncoder(w).Encode(SecretReadResponse{SecretID: "secret-id", Namespace: "db01", Key: "user:sys", VersionID: "version-id", Ciphertext: "Y2lwaGVy", Envelope: "ZW52", Permissions: PermissionRead})
		case "POST /v1/secrets/by-key/share":
			if got := r.URL.Query().Get("namespace"); got != "db01" {
				t.Fatalf("namespace = %q", got)
			}
			if got := r.URL.Query().Get("key"); got != "user:sys" {
				t.Fatalf("key = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "shared"})
		case "POST /v1/secrets/by-key/access-requests":
			if got := r.URL.Query().Get("namespace"); got != "db01" {
				t.Fatalf("namespace = %q", got)
			}
			if got := r.URL.Query().Get("key"); got != "user:sys" {
				t.Fatalf("key = %q", got)
			}
			_ = json.NewEncoder(w).Encode(AccessGrantRef{SecretID: "secret-id", VersionID: "version-id", ClientID: "client_bob", Status: "pending"})
		case "POST /v1/secrets/by-key/access/client_bob/activate":
			if got := r.URL.Query().Get("namespace"); got != "db01" {
				t.Fatalf("namespace = %q", got)
			}
			if got := r.URL.Query().Get("key"); got != "user:sys" {
				t.Fatalf("key = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "activated"})
		case "POST /v1/secrets/by-key/versions":
			if got := r.URL.Query().Get("namespace"); got != "db01" {
				t.Fatalf("namespace = %q", got)
			}
			if got := r.URL.Query().Get("key"); got != "user:sys" {
				t.Fatalf("key = %q", got)
			}
			_ = json.NewEncoder(w).Encode(SecretVersionRef{SecretID: "secret-id", VersionID: "version-id-2"})
		case "GET /v1/secrets/by-key/versions":
			if got := r.URL.Query().Get("namespace"); got != "db01" {
				t.Fatalf("namespace = %q", got)
			}
			if got := r.URL.Query().Get("key"); got != "user:sys" {
				t.Fatalf("key = %q", got)
			}
			if got := r.URL.Query().Get("limit"); got != "5" {
				t.Fatalf("limit = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string][]SecretVersionMetadata{"versions": []SecretVersionMetadata{{SecretID: "secret-id", VersionID: "version-id"}}})
		case "GET /v1/secrets/by-key/access":
			if got := r.URL.Query().Get("namespace"); got != "db01" {
				t.Fatalf("namespace = %q", got)
			}
			if got := r.URL.Query().Get("key"); got != "user:sys" {
				t.Fatalf("key = %q", got)
			}
			if got := r.URL.Query().Get("limit"); got != "7" {
				t.Fatalf("limit = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string][]SecretAccessMetadata{"access": []SecretAccessMetadata{{SecretID: "secret-id", VersionID: "version-id", ClientID: "client_bob"}}})
		case "DELETE /v1/secrets/by-key":
			if got := r.URL.Query().Get("namespace"); got != "db01" {
				t.Fatalf("namespace = %q", got)
			}
			if got := r.URL.Query().Get("key"); got != "user:sys" {
				t.Fatalf("key = %q", got)
			}
			if got := r.URL.Query().Get("cascade"); got != "true" {
				t.Fatalf("cascade = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
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
		Key:         "secret",
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
	readByKey, err := custodiaClient.GetSecretPayloadByKey("db01", "user:sys")
	if err != nil || readByKey.Namespace != "db01" || readByKey.Key != "user:sys" {
		t.Fatalf("GetSecretPayloadByKey() = %+v err=%v", readByKey, err)
	}
	if err := custodiaClient.ShareSecretPayloadByKey("db01", "user:sys", ShareSecretPayload{VersionID: "version-id", TargetClientID: "client_bob", Envelope: "ZW52", Permissions: PermissionRead}); err != nil {
		t.Fatalf("ShareSecretPayloadByKey() error = %v", err)
	}
	grantByKey, err := custodiaClient.CreateAccessGrantByKey("db01", "user:sys", AccessGrantPayload{TargetClientID: "client_bob", Permissions: PermissionRead})
	if err != nil || grantByKey.ClientID != "client_bob" || grantByKey.Status != "pending" {
		t.Fatalf("CreateAccessGrantByKey() = %+v err=%v", grantByKey, err)
	}
	if err := custodiaClient.ActivateAccessGrantPayloadByKey("db01", "user:sys", "client_bob", ActivateAccessPayload{Envelope: "ZW52"}); err != nil {
		t.Fatalf("ActivateAccessGrantPayloadByKey() error = %v", err)
	}
	versionByKey, err := custodiaClient.CreateSecretVersionPayloadByKey("db01", "user:sys", CreateSecretVersionPayload{Ciphertext: "Y2lwaGVy", Envelopes: []RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52"}}, Permissions: PermissionRead})
	if err != nil || versionByKey.VersionID != "version-id-2" {
		t.Fatalf("CreateSecretVersionPayloadByKey() = %+v err=%v", versionByKey, err)
	}
	versionsByKey, err := custodiaClient.ListSecretVersionMetadataByKey("db01", "user:sys", 5)
	if err != nil || len(versionsByKey) != 1 || versionsByKey[0].VersionID != "version-id" {
		t.Fatalf("ListSecretVersionMetadataByKey() = %+v err=%v", versionsByKey, err)
	}
	accessByKey, err := custodiaClient.ListSecretAccessMetadataByKey("db01", "user:sys", 7)
	if err != nil || len(accessByKey) != 1 || accessByKey[0].ClientID != "client_bob" {
		t.Fatalf("ListSecretAccessMetadataByKey() = %+v err=%v", accessByKey, err)
	}
	if err := custodiaClient.DeleteSecretByKey("db01", "user:sys", true); err != nil {
		t.Fatalf("DeleteSecretByKey() error = %v", err)
	}
}

func TestPublicGoOperationalMethodsAvoidInternalTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.EscapedPath() {
		case "GET /v1/status":
			_ = json.NewEncoder(w).Encode(OperationalStatus{Status: "ok", StoreBackend: "memory", Build: BuildInfo{Version: "1.2.3"}})
		case "GET /v1/version":
			_ = json.NewEncoder(w).Encode(BuildInfo{Version: "1.2.3", Commit: "abc"})
		case "GET /v1/diagnostics":
			_ = json.NewEncoder(w).Encode(RuntimeDiagnostics{Goroutines: 3})
		case "GET /v1/revocation/status":
			_ = json.NewEncoder(w).Encode(RevocationStatus{Configured: true, Valid: true, RevokedCount: 2})
		case "GET /v1/revocation/serial":
			if got := r.URL.Query().Get("serial_hex"); got != "0xCAFE" {
				t.Fatalf("serial_hex = %q", got)
			}
			_ = json.NewEncoder(w).Encode(RevocationSerialStatus{SerialHex: "cafe", Status: "good"})
		case "GET /v1/audit-events":
			if got := r.URL.Query().Get("action"); got != "secret.read" {
				t.Fatalf("action = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"audit_events": []AuditEvent{{Action: "secret.read", ActorClientID: "client_alice"}}})
		case "GET /v1/audit-events/export":
			if got := r.URL.Query().Get("outcome"); got != "failure" {
				t.Fatalf("outcome = %q", got)
			}
			w.Header().Set("X-Custodia-Audit-Export-SHA256", "abc123")
			w.Header().Set("X-Custodia-Audit-Export-Events", "1")
			_, _ = w.Write([]byte("{\"event_id\":\"event-1\"}\n"))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
	}))
	defer server.Close()

	custodiaClient := &Client{baseURL: server.URL, http: server.Client()}
	status, err := custodiaClient.StatusInfo()
	if err != nil || status.Status != "ok" || status.Build.Version != "1.2.3" {
		t.Fatalf("StatusInfo() = %+v err=%v", status, err)
	}
	version, err := custodiaClient.VersionInfo()
	if err != nil || version.Version != "1.2.3" || version.Commit != "abc" {
		t.Fatalf("VersionInfo() = %+v err=%v", version, err)
	}
	diagnostics, err := custodiaClient.DiagnosticsInfo()
	if err != nil || diagnostics.Goroutines != 3 {
		t.Fatalf("DiagnosticsInfo() = %+v err=%v", diagnostics, err)
	}
	revocation, err := custodiaClient.RevocationStatusInfo()
	if err != nil || !revocation.Configured || !revocation.Valid || revocation.RevokedCount != 2 {
		t.Fatalf("RevocationStatusInfo() = %+v err=%v", revocation, err)
	}
	serial, err := custodiaClient.RevocationSerialStatusInfo(" 0xCAFE ")
	if err != nil || serial.SerialHex != "cafe" || serial.Status != "good" {
		t.Fatalf("RevocationSerialStatusInfo() = %+v err=%v", serial, err)
	}
	events, err := custodiaClient.ListAuditEventMetadata(AuditEventFilters{Limit: 25, ActorClientID: "client_alice", Action: "secret.read"})
	if err != nil || len(events) != 1 || events[0].Action != "secret.read" {
		t.Fatalf("ListAuditEventMetadata() = %+v err=%v", events, err)
	}
	artifact, err := custodiaClient.ExportAuditEventArtifact(AuditEventFilters{Limit: 10, Outcome: "failure"})
	if err != nil || string(artifact.Body) != "{\"event_id\":\"event-1\"}\n" || artifact.SHA256 != "abc123" || artifact.EventCount != "1" {
		t.Fatalf("ExportAuditEventArtifact() = %+v err=%v", artifact, err)
	}
}
