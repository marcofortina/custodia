// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

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
