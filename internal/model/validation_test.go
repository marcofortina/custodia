// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package model

import (
	"encoding/base64"
	"testing"
)

func TestValidClientID(t *testing.T) {
	for _, value := range []string{"client_alice", "tenant-1.client:prod", "A09"} {
		if !ValidClientID(value) {
			t.Fatalf("expected %q to be valid", value)
		}
	}
	for _, value := range []string{"", "client alice", "client/alice", "client\n"} {
		if ValidClientID(value) {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}

func TestNormalizeSecretName(t *testing.T) {
	if got := NormalizeSecretName("  db password  "); got != "db password" {
		t.Fatalf("unexpected normalized secret name: %q", got)
	}
}

func TestValidSecretName(t *testing.T) {
	for _, value := range []string{"db password", "tenant/prod/api-key"} {
		if !ValidSecretName(value) {
			t.Fatalf("expected %q to be valid", value)
		}
	}
	for _, value := range []string{"", "   ", "secret\nname"} {
		if ValidSecretName(value) {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}

func TestValidCryptoMetadata(t *testing.T) {
	if !ValidCryptoMetadata(make([]byte, MaxCryptoMetadataBytes)) {
		t.Fatal("expected max-sized crypto metadata to be valid")
	}
	if ValidCryptoMetadata(make([]byte, MaxCryptoMetadataBytes+1)) {
		t.Fatal("expected oversized crypto metadata to be invalid")
	}
}

func TestValidMTLSSubject(t *testing.T) {
	for _, value := range []string{"client_alice", "spiffe://custodia/client/alice", "CN=client_alice"} {
		if !ValidMTLSSubject(value) {
			t.Fatalf("expected %q to be valid", value)
		}
	}
	for _, value := range []string{"", "   ", "client\nsubject"} {
		if ValidMTLSSubject(value) {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}

func TestValidUUIDID(t *testing.T) {
	if !ValidUUIDID("550e8400-e29b-41d4-a716-446655440000") {
		t.Fatal("expected generated uuid id to be valid")
	}
	for _, value := range []string{"", "not-a-uuid", "550e8400e29b41d4a716446655440000"} {
		if ValidUUIDID(value) {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}

func TestValidOptionalUUIDID(t *testing.T) {
	if !ValidOptionalUUIDID("") || !ValidOptionalUUIDID("550e8400-e29b-41d4-a716-446655440000") {
		t.Fatal("expected empty and uuid values to be valid optional ids")
	}
	if ValidOptionalUUIDID("latest") {
		t.Fatal("expected non-uuid optional id to be invalid")
	}
}

func TestValidAuditAction(t *testing.T) {
	for _, value := range []string{"secret.read", "client-revoke", "audit:list"} {
		if !ValidAuditAction(value) {
			t.Fatalf("expected audit action %q to be valid", value)
		}
	}
	for _, value := range []string{"", "secret read", "secret/read", "secret\nread"} {
		if ValidAuditAction(value) {
			t.Fatalf("expected audit action %q to be invalid", value)
		}
	}
}

func TestValidAuditResourceType(t *testing.T) {
	for _, value := range []string{"secret", "audit_event", "client-type"} {
		if !ValidAuditResourceType(value) {
			t.Fatalf("expected audit resource type %q to be valid", value)
		}
	}
	for _, value := range []string{"", "audit event", "secret/type", "secret\ntype"} {
		if ValidAuditResourceType(value) {
			t.Fatalf("expected audit resource type %q to be invalid", value)
		}
	}
}

func TestValidAuditResourceID(t *testing.T) {
	for _, value := range []string{"550e8400-e29b-41d4-a716-446655440000", "client_alice", "secret:prod"} {
		if !ValidAuditResourceID(value) {
			t.Fatalf("expected audit resource id %q to be valid", value)
		}
	}
	for _, value := range []string{"", "secret\nid"} {
		if ValidAuditResourceID(value) {
			t.Fatalf("expected audit resource id %q to be invalid", value)
		}
	}
}

func TestValidOpaqueBlobBoundsDecodedPayloads(t *testing.T) {
	if !ValidOpaqueBlob("YQ==") {
		t.Fatal("expected non-empty base64 blob to be valid")
	}
	if ValidOpaqueBlob("") || ValidOpaqueBlob("!!!!") {
		t.Fatal("expected empty and malformed base64 blobs to be invalid")
	}
	oversized := make([]byte, MaxOpaqueBlobBytes+1)
	for idx := range oversized {
		oversized[idx] = 'a'
	}
	if ValidOpaqueBlob(base64.StdEncoding.EncodeToString(oversized)) {
		t.Fatal("expected oversized decoded blob to be invalid")
	}
}

func TestValidRevocationReason(t *testing.T) {
	if !ValidRevocationReason("") || !ValidRevocationReason("planned rotation") {
		t.Fatal("expected empty and printable revocation reasons to be valid")
	}
	if ValidRevocationReason("bad\nreason") {
		t.Fatal("expected control characters to be rejected")
	}
	oversized := make([]byte, MaxRevocationReasonLength+1)
	for idx := range oversized {
		oversized[idx] = 'a'
	}
	if ValidRevocationReason(string(oversized)) {
		t.Fatal("expected oversized revocation reason to be rejected")
	}
}

func TestValidAccessRequestStatus(t *testing.T) {
	for _, value := range []string{"pending", "activated", "revoked", "expired"} {
		if !ValidAccessRequestStatus(value) {
			t.Fatalf("expected status %q to be valid", value)
		}
	}
	if ValidAccessRequestStatus("done") || ValidAccessRequestStatus("") {
		t.Fatal("expected unknown status values to be invalid")
	}
}
