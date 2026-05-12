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

func TestServerDoesNotExposeWrappedDEKOrPrivateKeyRoutes(t *testing.T) {
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
		for _, forbidden := range []string{"wrapped_dek", "wrapped dek", "private_key_b64"} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s must not contain server-side decryptable key material token %q", path, forbidden)
			}
		}
	}
}
