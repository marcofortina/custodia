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
	if len(paths) < 4 {
		t.Fatalf("expected vector scaffold files, got %d", len(paths))
	}
	for _, path := range paths {
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(payload, &doc); err != nil {
			t.Fatalf("Unmarshal(%s) error = %v", path, err)
		}
		metadata, _ := doc["crypto_metadata"].(map[string]any)
		if filepath.Base(path) == "schema.json" {
			if doc["version"] != "custodia.client-crypto.v1" {
				t.Fatalf("schema version mismatch in %s", path)
			}
			continue
		}
		if metadata["version"] != "custodia.client-crypto.v1" {
			t.Fatalf("missing crypto version in %s: %#v", path, metadata)
		}
		if metadata["content_cipher"] == "" || metadata["envelope_scheme"] == "" {
			t.Fatalf("missing crypto scheme fields in %s: %#v", path, metadata)
		}
	}
}
