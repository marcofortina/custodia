package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerDoesNotExposeKeyDirectoryOrWrappedDEKRoutes(t *testing.T) {
	t.Parallel()

	paths := []string{
		filepath.Join("server.go"),
		filepath.Join("..", "..", "docs", "API.md"),
		filepath.Join("..", "..", "docs", "SECURITY_MODEL.md"),
	}
	for _, path := range paths {
		contentBytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		content := strings.ToLower(string(contentBytes))
		for _, forbidden := range []string{"public_key", "wrapped_dek", "wrapped dek"} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s must not contain server-side crypto trust token %q", path, forbidden)
			}
		}
	}
}
