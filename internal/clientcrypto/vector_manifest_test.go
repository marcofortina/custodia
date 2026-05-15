// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package clientcrypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vectorManifest struct {
	Schema         string                  `json:"schema"`
	CurrentVersion string                  `json:"current_version"`
	Versions       []vectorManifestVersion `json:"versions"`
}

type vectorManifestVersion struct {
	Version              string                   `json:"version"`
	Directory            string                   `json:"directory"`
	SchemaFile           string                   `json:"schema_file"`
	Cases                []string                 `json:"cases"`
	Semantics            []string                 `json:"semantics"`
	MetadataOnlyBoundary metadataOnlyBoundary     `json:"metadata_only_boundary"`
	Consumers            []vectorManifestConsumer `json:"consumers"`
}

type metadataOnlyBoundary struct {
	ServerVisible []string `json:"server_visible"`
	ClientOnly    []string `json:"client_only"`
}

type vectorManifestConsumer struct {
	SDK     string `json:"sdk"`
	Command string `json:"command"`
}

func TestClientCryptoManifestDocumentsVersionedVectors(t *testing.T) {
	manifest := loadManifest(t)
	if manifest.Schema != "custodia.client-crypto.manifest.v1" {
		t.Fatalf("manifest schema = %q", manifest.Schema)
	}
	if manifest.CurrentVersion != VersionV1 {
		t.Fatalf("current version = %q, want %q", manifest.CurrentVersion, VersionV1)
	}
	if len(manifest.Versions) != 1 {
		t.Fatalf("expected one manifest version, got %d", len(manifest.Versions))
	}

	version := manifest.Versions[0]
	if version.Version != VersionV1 {
		t.Fatalf("manifest version = %q, want %q", version.Version, VersionV1)
	}
	if version.Directory != "testdata/client-crypto/v1" {
		t.Fatalf("manifest directory = %q", version.Directory)
	}
	if len(version.Cases) < 8 {
		t.Fatalf("expected at least eight v1 cases, got %d", len(version.Cases))
	}

	for _, name := range version.Cases {
		path := filepath.Join("..", "..", version.Directory, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("manifest case %s is missing: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join("..", "..", version.SchemaFile)); err != nil {
		t.Fatalf("manifest schema file is missing: %v", err)
	}
}

func TestClientCryptoManifestDocumentsSDKConsumers(t *testing.T) {
	manifest := loadManifest(t)
	version := manifest.Versions[0]
	seen := make(map[string]string)
	for _, consumer := range version.Consumers {
		seen[consumer.SDK] = consumer.Command
	}

	for _, sdk := range []string{"python", "node", "rust"} {
		if seen[sdk] == "" {
			t.Fatalf("manifest does not document %s vector consumer", sdk)
		}
	}
	if len(seen) < 3 {
		t.Fatalf("expected at least three documented vector consumers, got %d", len(seen))
	}
}

func TestClientCryptoManifestDocumentsMetadataOnlyBoundary(t *testing.T) {
	manifest := loadManifest(t)
	boundary := manifest.Versions[0].MetadataOnlyBoundary

	for _, field := range []string{"ciphertext", "recipient envelopes", "crypto_metadata"} {
		if !containsString(boundary.ServerVisible, field) {
			t.Fatalf("server-visible boundary does not include %q", field)
		}
	}
	for _, field := range []string{"plaintext", "content DEK", "recipient private keys"} {
		if !containsString(boundary.ClientOnly, field) {
			t.Fatalf("client-only boundary does not include %q", field)
		}
	}
}

func loadManifest(t *testing.T) vectorManifest {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "testdata", "client-crypto", "manifest.json"))
	if err != nil {
		t.Fatalf("ReadFile(manifest.json) error = %v", err)
	}
	var manifest vectorManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatalf("Unmarshal(manifest.json) error = %v", err)
	}
	return manifest
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
