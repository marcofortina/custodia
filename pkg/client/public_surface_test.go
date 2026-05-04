package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicTransportSurfaceAvoidsInternalImports(t *testing.T) {
	for _, path := range []string{"types.go", "public_transport.go"} {
		payload, err := os.ReadFile(filepath.Join(".", path))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		if strings.Contains(string(payload), "custodia/internal/") {
			t.Fatalf("public SDK surface file %s must not import custodia/internal/*", path)
		}
	}
}
