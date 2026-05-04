// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package clientcrypto

import (
	"bytes"
	"encoding/base64"
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

func TestValidateVectorRejectsAADHashMismatch(t *testing.T) {
	vector := validTestVector()
	vector.CanonicalAADSHA256 = "deadbeef"
	if err := ValidateVector(vector); err == nil {
		t.Fatal("ValidateVector() error = nil, want hash mismatch")
	}
}

func TestValidateVectorRejectsCanonicalAADMismatch(t *testing.T) {
	vector := validTestVector()
	vector.CanonicalAAD = `{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1","secret_name":"other"}`
	vector.CanonicalAADSHA256 = "1bbd5afc1f716833d8864c90ab8f5f0b3d3342d7c91e604e3f2988d57947d4fb"
	if err := ValidateVector(vector); err == nil {
		t.Fatal("ValidateVector() error = nil, want canonical AAD mismatch")
	}
}

func TestValidateVectorRequiresExpectedErrorForUnsupportedVersion(t *testing.T) {
	vector := validTestVector()
	vector.CryptoMetadata.Version = "custodia.client-crypto.v2"
	if err := ValidateVector(vector); err == nil {
		t.Fatal("ValidateVector() error = nil, want unsupported version")
	}
	vector.ExpectedError = "unsupported_crypto_version"
	if err := ValidateVector(vector); err != nil {
		t.Fatalf("ValidateVector() error = %v", err)
	}
}

func TestValidateVectorRejectsCiphertextMismatch(t *testing.T) {
	vector := mustLoadVectorFixture(t, "create_secret_single_recipient.json")
	vector.Ciphertext = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, len(vector.Ciphertext)))
	if err := ValidateVector(vector); err == nil {
		t.Fatal("ValidateVector() error = nil, want ciphertext mismatch")
	}
}

func TestValidateVectorRejectsEnvelopeMismatch(t *testing.T) {
	vector := mustLoadVectorFixture(t, "create_secret_single_recipient.json")
	vector.Envelopes[0].Envelope = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 80))
	if err := ValidateVector(vector); err == nil {
		t.Fatal("ValidateVector() error = nil, want envelope mismatch")
	}
}

func TestValidateVectorAcceptsNegativeCryptoFailures(t *testing.T) {
	for _, name := range []string{"tamper_ciphertext_fails.json", "aad_mismatch_fails.json", "wrong_recipient_fails.json"} {
		if _, err := LoadVector(filepath.Join("..", "..", "testdata", "client-crypto", "v1", name)); err != nil {
			t.Fatalf("LoadVector(%s) error = %v", name, err)
		}
	}
}

func mustLoadVectorFixture(t *testing.T, name string) Vector {
	t.Helper()
	vector, err := LoadVector(filepath.Join("..", "..", "testdata", "client-crypto", "v1", name))
	if err != nil {
		t.Fatalf("LoadVector(%s) error = %v", name, err)
	}
	return vector
}

func validTestVector() Vector {
	return Vector{
		Case:   "create_secret_single_recipient",
		Status: "deterministic-aad-only",
		CryptoMetadata: Metadata{
			Version:        VersionV1,
			ContentCipher:  ContentCipherV1,
			EnvelopeScheme: EnvelopeHPKEV1,
		},
		AADInputs:          CanonicalAADInputs{SecretName: "database-password"},
		CanonicalAAD:       `{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1","secret_name":"database-password"}`,
		CanonicalAADSHA256: "32f7c1471093f0a85a963d5cfeaf3aeec8edcd52577175c6b4a826c5063144bf",
	}
}
