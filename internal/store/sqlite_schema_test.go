package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLiteSchemaUsesWALBusyTimeoutAndForeignKeys(t *testing.T) {
	t.Parallel()

	schemaBytes, err := os.ReadFile(filepath.Join("..", "..", "migrations", "sqlite", "001_init.sql"))
	if err != nil {
		t.Fatalf("read sqlite schema: %v", err)
	}
	schema := string(schemaBytes)

	for _, expected := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"CREATE TABLE IF NOT EXISTS custodia_state",
		"CHECK (length(payload) > 0)",
	} {
		if !strings.Contains(schema, expected) {
			t.Fatalf("sqlite schema missing %q", expected)
		}
	}
}

func TestSQLiteSchemaDoesNotIntroduceReducedLiteTables(t *testing.T) {
	t.Parallel()

	schemaBytes, err := os.ReadFile(filepath.Join("..", "..", "migrations", "sqlite", "001_init.sql"))
	if err != nil {
		t.Fatalf("read sqlite schema: %v", err)
	}
	schema := string(schemaBytes)

	for _, forbidden := range []string{
		"CREATE TABLE clients",
		"CREATE TABLE secrets",
		"CREATE TABLE secret_access",
	} {
		if strings.Contains(schema, forbidden) {
			t.Fatalf("sqlite Lite store must not introduce a reduced schema table %q", forbidden)
		}
	}
}
