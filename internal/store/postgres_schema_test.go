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

	if !strings.Contains(postgresStore, "ORDER BY occurred_at ASC, event_id ASC") {
		t.Fatal("postgres audit listing must return chronological events for hash-chain verification")
	}
}
