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
