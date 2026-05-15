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

func TestKeyspaceWorkflowDoesNotExposeSecretIDFlags(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	for _, path := range []string{
		"README.md",
		"docs/CUSTODIA_CLIENT_CLI.md",
		"docs/man/custodia-admin.1.in",
		"docs/man/custodia-client.1.in",
		"cmd/custodia-admin/main.go",
		"cmd/custodia-client/main.go",
	} {
		payload, err := os.ReadFile(filepath.Join(repoRoot, path))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		if strings.Contains(string(payload), "--secret-id") {
			t.Fatalf("keyspace workflow file %s must not expose --secret-id", path)
		}
	}
}

func TestPublicSDKSurfaceAvoidsSecretIDTransportHelpersAcrossLanguages(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	for _, tc := range []struct {
		path      string
		forbidden []string
	}{
		{
			path: "clients/python/custodia_client/__init__.py",
			forbidden: []string{
				"def get_secret(",
				"def share_secret(",
				"def create_secret_version(",
				"def delete_secret(",
				"def request_access_grant(",
				"def activate_access_grant(",
			},
		},
		{
			path: "clients/node/src/index.js",
			forbidden: []string{
				"getSecretPayload(secretID",
				"shareSecretPayload(secretID",
				"createSecretVersionPayload(secretID",
				"deleteSecretPayload(secretID",
				"createAccessGrant(secretID",
				"activateAccessGrantPayload(secretID",
			},
		},
		{
			path: "clients/cpp/include/custodia/client.hpp",
			forbidden: []string{
				"get_secret_payload(const std::string& secret_id",
				"share_secret_payload(const std::string& secret_id",
				"create_secret_version_payload(const std::string& secret_id",
				"create_access_grant(const std::string& secret_id",
			},
		},
		{
			path: "clients/java/src/main/java/dev/custodia/client/CustodiaClient.java",
			forbidden: []string{
				"getSecretPayload(String secretId",
				"shareSecretPayload(String secretId",
				"createSecretVersionPayload(String secretId",
				"createAccessGrant(String secretId",
			},
		},
		{
			path: "clients/rust/src/lib.rs",
			forbidden: []string{
				"pub fn get_secret_payload(&self, secret_id",
				"pub fn share_secret_payload(&self, secret_id",
				"pub fn create_secret_version_payload(&self, secret_id",
				"pub fn create_access_grant(&self, secret_id",
			},
		},
	} {
		payload, err := os.ReadFile(filepath.Join(repoRoot, tc.path))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", tc.path, err)
		}
		content := string(payload)
		for _, token := range tc.forbidden {
			if strings.Contains(content, token) {
				t.Fatalf("public SDK surface file %s must not reintroduce secret-id helper %q", tc.path, token)
			}
		}
	}
}

func TestSDKCapabilityMatrixDocumentsKeyspaceParity(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	payload, err := os.ReadFile(filepath.Join(repoRoot, "docs", "CLIENT_LIBRARIES.md"))
	if err != nil {
		t.Fatalf("ReadFile(docs/CLIENT_LIBRARIES.md) error = %v", err)
	}
	content := string(payload)
	for _, token := range []string{
		"## Keyspace parity matrix",
		"| Feature | Go | Python | Node.js / TypeScript | C++ | Java | Rust |",
		"| Create secret by `namespace/key` | Yes | Yes | Yes | Yes | Yes | Yes |",
		"| Read secret by `namespace/key` | Yes | Yes | Yes | Yes | Yes | Yes |",
		"| Create new version by `namespace/key` | Yes | Yes | Yes | Yes | Yes | Yes |",
		"| Share by `namespace/key` | Yes | Yes | Yes | Yes | Yes | Yes |",
		"| Revoke access by `namespace/key` | Yes | Yes | Yes | Yes | Yes | Yes |",
		"| Delete by `namespace/key` | Yes | Yes | Yes | Yes | Yes | Yes |",
		"| List versions by `namespace/key` | Yes | Yes | Yes | Yes | Yes | Yes |",
		"| List access by `namespace/key` | Yes | Yes | Yes | Yes | Yes | Yes |",
		"| Request access by `namespace/key` | Yes | Yes | Yes | Yes | Yes | Yes |",
		"| Activate access by `namespace/key` | Yes | Yes | Yes | Yes | Yes | Yes |",
		"| High-level crypto AAD binds `namespace/key/secret_version` | Yes | Yes | Yes | Yes | Yes | Yes |",
	} {
		if !strings.Contains(content, token) {
			t.Fatalf("SDK capability matrix is missing %q", token)
		}
	}
}

func TestGoSDKIssue40DocsAndExamplesStayWired(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	checks := []struct {
		path   string
		tokens []string
	}{
		{
			path: filepath.Join("docs", "GO_CLIENT_SDK.md"),
			tokens: []string{
				"## Import and transport configuration",
				"pkg/client/examples_test.go",
				"Compatibility expectations for publishing are captured by [`SDK_PUBLISHING_READINESS.md`](SDK_PUBLISHING_READINESS.md)",
			},
		},
		{
			path: filepath.Join("docs", "SDK_PUBLISHING_READINESS.md"),
			tokens: []string{
				"Go public SDK surface is stable enough for external consumers, ships package-level documentation",
				"Go SDK examples compile against current `namespace/key` transport semantics",
			},
		},
		{
			path: filepath.Join("pkg", "client", "doc.go"),
			tokens: []string{
				"Package client is the Go SDK surface",
				"Custodia servers remain metadata-only",
			},
		},
		{
			path: filepath.Join("pkg", "client", "examples_test.go"),
			tokens: []string{
				"func ExampleClient_CreateSecretPayload()",
				"func ExampleClient_GetSecretPayloadByKey()",
				"func ExampleClient_CreateSecretVersionPayloadByKey()",
				"func ExampleClient_ShareSecretPayloadByKey()",
				"func ExampleClient_DeleteSecretByKey()",
				"func ExampleCryptoClient_CreateEncryptedSecret()",
				"func ExampleCryptoClient_ReadDecryptedSecretByKey()",
			},
		},
	}

	for _, check := range checks {
		payload, err := os.ReadFile(filepath.Join(repoRoot, check.path))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", check.path, err)
		}
		content := string(payload)
		for _, token := range check.tokens {
			if !strings.Contains(content, token) {
				t.Fatalf("%s is missing %q", check.path, token)
			}
		}
	}
}

func TestClientCryptoThreatModelIsDocumented(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	for _, path := range []string{
		"README.md",
		"docs/CLIENT_CRYPTO_SPEC.md",
		"docs/CLIENT_LIBRARIES.md",
	} {
		payload, err := os.ReadFile(filepath.Join(repoRoot, path))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		if !strings.Contains(string(payload), "CLIENT_CRYPTO_THREAT_MODEL.md") {
			t.Fatalf("%s must link the client crypto threat model", path)
		}
	}

	payload, err := os.ReadFile(filepath.Join(repoRoot, "docs", "CLIENT_CRYPTO_THREAT_MODEL.md"))
	if err != nil {
		t.Fatalf("ReadFile(docs/CLIENT_CRYPTO_THREAT_MODEL.md) error = %v", err)
	}
	content := string(payload)
	for _, token := range []string{
		"server remains a metadata-only control plane",
		"secret_id is intentionally not part of client crypto AAD",
		"fresh 96-bit random nonce",
		"Revocation prevents future server-authorized reads",
		"Use non-sensitive namespace/key names",
	} {
		if !strings.Contains(content, token) {
			t.Fatalf("client crypto threat model is missing %q", token)
		}
	}
}
