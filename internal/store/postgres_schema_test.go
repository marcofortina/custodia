// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostgresSchemaRejectsZeroPermissionGrants(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join("..", "..", "migrations", "postgres", "001_init.sql")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read postgres schema: %v", err)
	}
	schema := string(schemaBytes)

	if strings.Contains(schema, "CHECK (permissions >= 0") {
		t.Fatal("postgres schema must not allow zero permission grants")
	}
	if count := strings.Count(schema, "CHECK (permissions > 0 AND permissions <= 7)"); count != 2 {
		t.Fatalf("expected non-zero permission checks on active and pending grants, got %d", count)
	}
}

func TestPostgresSchemaStoresPendingGrantExpiration(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join("..", "..", "migrations", "postgres", "001_init.sql")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read postgres schema: %v", err)
	}
	schema := string(schemaBytes)

	if !strings.Contains(schema, "CREATE TABLE IF NOT EXISTS secret_access_requests") || !strings.Contains(schema, "expires_at             TIMESTAMPTZ") {
		t.Fatal("pending grant requests must preserve optional access expiration")
	}
}

func TestPostgresSchemaIncludesMetadataOnlyWebUsers(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join("..", "..", "migrations", "postgres", "001_init.sql")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read postgres schema: %v", err)
	}
	schema := string(schemaBytes)

	for _, expected := range []string{
		"CREATE TABLE IF NOT EXISTS web_users",
		"password_hash BYTEA NOT NULL",
		"mfa_secret    TEXT",
		"passkey_id    BYTEA",
		"CHECK (role IN ('admin', 'operator', 'auditor'))",
		"CREATE TABLE IF NOT EXISTS web_user_mappings",
		"client_id TEXT NOT NULL REFERENCES clients(client_id)",
	} {
		if !strings.Contains(schema, expected) {
			t.Fatalf("postgres schema missing web metadata token %q", expected)
		}
	}
}

func TestPostgresAuditListingUsesChronologicalOrderForHashVerification(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join("postgres_pgx.go")
	storeBytes, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read postgres store: %v", err)
	}
	postgresStore := string(storeBytes)

	for _, expected := range []string{
		"ORDER BY occurred_at DESC, event_id DESC",
		"LIMIT $1",
		"ORDER BY occurred_at ASC, event_id ASC",
	} {
		if !strings.Contains(postgresStore, expected) {
			t.Fatalf("postgres audit listing must select latest events and return them chronologically; missing %q", expected)
		}
	}
}

func TestPostgresSchemaRejectsExpiredAccessRows(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join("..", "..", "migrations", "postgres", "001_init.sql")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read postgres schema: %v", err)
	}
	schema := string(schemaBytes)

	for _, expected := range []string{
		"CHECK (expires_at IS NULL OR expires_at > granted_at)",
		"CHECK (expires_at IS NULL OR expires_at > requested_at)",
	} {
		if !strings.Contains(schema, expected) {
			t.Fatalf("postgres schema missing expiration guardrail %q", expected)
		}
	}
}

func TestPostgresSchemaRejectsEmptyOpaqueBlobs(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join("..", "..", "migrations", "postgres", "001_init.sql")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read postgres schema: %v", err)
	}
	schema := string(schemaBytes)

	for _, expected := range []string{
		"CHECK (octet_length(ciphertext) > 0)",
		"CHECK (octet_length(envelope) > 0)",
	} {
		if !strings.Contains(schema, expected) {
			t.Fatalf("postgres schema missing opaque blob guardrail %q", expected)
		}
	}
}

func TestPostgresSchemaDefinesVisibleSecretKeyspace(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join("..", "..", "migrations", "postgres", "001_init.sql")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read postgres schema: %v", err)
	}
	schema := string(schemaBytes)

	for _, expected := range []string{
		"namespace            TEXT NOT NULL DEFAULT 'default'",
		"key                  TEXT NOT NULL",
		"CREATE TABLE IF NOT EXISTS secret_visibility",
		"PRIMARY KEY (client_id, namespace, key)",
		"UNIQUE (client_id, secret_id)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_owner_key_active",
	} {
		if !strings.Contains(schema, expected) {
			t.Fatalf("postgres schema missing visible keyspace token %q", expected)
		}
	}
}

func TestPostgresStoreMaintainsVisibleSecretKeyspace(t *testing.T) {
	t.Parallel()

	storeBytes, err := os.ReadFile("postgres_pgx.go")
	if err != nil {
		t.Fatalf("read postgres store: %v", err)
	}
	postgresStore := string(storeBytes)

	for _, expected := range []string{
		"normalizeSecretIdentity(&req)",
		"INSERT INTO secrets (namespace, key, name, created_by_client_id)",
		"activeVisibleSecretIDByKey(ctx, tx, envelope.ClientID, req.Namespace, req.Key)",
		"insertSecretVisibility(ctx, tx, envelope.ClientID, req.Namespace, req.Key, ref.SecretID, visibilityType)",
		"activeVisibleSecretIDByKey(ctx, tx, req.TargetClientID, namespace, key)",
		"DELETE FROM secret_visibility WHERE secret_id = $1::uuid AND client_id = $2",
		"JOIN secret_visibility sv ON sv.secret_id = s.secret_id AND sv.client_id = $2",
	} {
		if !strings.Contains(postgresStore, expected) {
			t.Fatalf("postgres store missing visible keyspace token %q", expected)
		}
	}
}
