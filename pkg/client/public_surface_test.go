// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

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

func TestPublicSDKSurfaceAvoidsSecretIDWorkflowHelpers(t *testing.T) {
	for _, tc := range []struct {
		path      string
		forbidden []string
	}{
		{
			path: "public_transport.go",
			forbidden: []string{
				"func (c *Client) GetSecretPayload(",
				"func (c *Client) ShareSecretPayload(",
				"func (c *Client) CreateSecretVersionPayload(",
				"func (c *Client) ListSecretVersionMetadata(",
				"func (c *Client) ListSecretAccessMetadata(",
			},
		},
		{
			path: "crypto_client.go",
			forbidden: []string{
				"func (c *CryptoClient) ReadDecryptedSecret(",
				"func (c *CryptoClient) ShareEncryptedSecret(",
				"func (c *CryptoClient) CreateEncryptedSecretVersion(",
			},
		},
	} {
		payload, err := os.ReadFile(filepath.Join(".", tc.path))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", tc.path, err)
		}
		content := string(payload)
		for _, token := range tc.forbidden {
			if strings.Contains(content, token) {
				t.Fatalf("public SDK surface file %s must not reintroduce secret-id workflow helper %q", tc.path, token)
			}
		}
	}
}
