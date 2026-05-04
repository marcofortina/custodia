package clientcrypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestClientCryptoVectorScaffoldIsVersioned(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "client-crypto", "v1", "*.json"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(paths) < 9 {
		t.Fatalf("expected vector scaffold files, got %d", len(paths))
	}
	for _, path := range paths {
		if filepath.Base(path) == "schema.json" {
			assertSchemaVersion(t, path)
			continue
		}
		if _, err := LoadVector(path); err != nil {
			t.Fatalf("LoadVector(%s) error = %v", path, err)
		}
	}
}

func assertSchemaVersion(t *testing.T, path string) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v", path, err)
	}
	if doc["version"] != VersionV1 {
		t.Fatalf("schema version mismatch in %s", path)
	}
}
