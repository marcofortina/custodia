// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package clientcrypto

import (
	"errors"
	"testing"
)

func TestParseMetadataAcceptsSupportedV1(t *testing.T) {
	metadata, err := ParseMetadata([]byte(`{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1"}`))
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
	if metadata.Version != VersionV1 || metadata.ContentCipher != ContentCipherV1 || metadata.EnvelopeScheme != EnvelopeHPKEV1 {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
}

func TestParseMetadataRejectsUnsupportedVersion(t *testing.T) {
	_, err := ParseMetadata([]byte(`{"version":"custodia.client-crypto.v2","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1"}`))
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("ParseMetadata() error = %v, want %v", err, ErrUnsupportedVersion)
	}
}

func TestParseMetadataRejectsUnsupportedContentCipher(t *testing.T) {
	_, err := ParseMetadata([]byte(`{"version":"custodia.client-crypto.v1","content_cipher":"xchacha20-poly1305","envelope_scheme":"hpke-v1"}`))
	if !errors.Is(err, ErrUnsupportedContentCipher) {
		t.Fatalf("ParseMetadata() error = %v, want %v", err, ErrUnsupportedContentCipher)
	}
}

func TestParseMetadataRejectsUnsupportedEnvelopeScheme(t *testing.T) {
	_, err := ParseMetadata([]byte(`{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"rsa-unsupported"}`))
	if !errors.Is(err, ErrUnsupportedEnvelopeScheme) {
		t.Fatalf("ParseMetadata() error = %v, want %v", err, ErrUnsupportedEnvelopeScheme)
	}
}

func TestBuildCanonicalAADUsesStableJSONOrder(t *testing.T) {
	aad, err := BuildCanonicalAAD(Metadata{
		Version:        VersionV1,
		ContentCipher:  ContentCipherV1,
		EnvelopeScheme: EnvelopeHPKEV1,
	}, CanonicalAADInputs{SecretName: "database-password"})
	if err != nil {
		t.Fatalf("BuildCanonicalAAD() error = %v", err)
	}
	want := `{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1","secret_name":"database-password"}`
	if string(aad) != want {
		t.Fatalf("BuildCanonicalAAD() = %s, want %s", aad, want)
	}
}

func TestBuildCanonicalAADIncludesPersistedResourceIDs(t *testing.T) {
	aad, err := BuildCanonicalAAD(Metadata{
		Version:        VersionV1,
		ContentCipher:  ContentCipherV1,
		EnvelopeScheme: EnvelopeHPKEV1,
	}, CanonicalAADInputs{SecretID: "550e8400-e29b-41d4-a716-446655440000", VersionID: "660e8400-e29b-41d4-a716-446655440000"})
	if err != nil {
		t.Fatalf("BuildCanonicalAAD() error = %v", err)
	}
	want := `{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1","secret_id":"550e8400-e29b-41d4-a716-446655440000","version_id":"660e8400-e29b-41d4-a716-446655440000"}`
	if string(aad) != want {
		t.Fatalf("BuildCanonicalAAD() = %s, want %s", aad, want)
	}
}

func TestBuildCanonicalAADRejectsMissingResourceBinding(t *testing.T) {
	_, err := BuildCanonicalAAD(Metadata{
		Version:        VersionV1,
		ContentCipher:  ContentCipherV1,
		EnvelopeScheme: EnvelopeHPKEV1,
	}, CanonicalAADInputs{})
	if !errors.Is(err, ErrMalformedAAD) {
		t.Fatalf("BuildCanonicalAAD() error = %v, want %v", err, ErrMalformedAAD)
	}
}

func TestBuildCanonicalAADRejectsUnsupportedMetadata(t *testing.T) {
	_, err := BuildCanonicalAAD(Metadata{
		Version:        "custodia.client-crypto.v2",
		ContentCipher:  ContentCipherV1,
		EnvelopeScheme: EnvelopeHPKEV1,
	}, CanonicalAADInputs{SecretName: "database-password"})
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("BuildCanonicalAAD() error = %v, want %v", err, ErrUnsupportedVersion)
	}
}

func TestParseMetadataAcceptsPersistedAADBindingAndNonce(t *testing.T) {
	payload := []byte(`{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1","content_nonce_b64":"bm9uY2U=","aad":{"secret_name":"database-password"}}`)
	metadata, err := ParseMetadata(payload)
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
	if metadata.ContentNonce != "bm9uY2U=" {
		t.Fatalf("ContentNonce = %q", metadata.ContentNonce)
	}
	if metadata.AAD == nil || metadata.AAD.SecretName != "database-password" {
		t.Fatalf("AAD = %+v", metadata.AAD)
	}
	fallback := CanonicalAADInputs{SecretID: "fallback"}
	if got := metadata.CanonicalAADInputs(fallback); got.SecretName != "database-password" {
		t.Fatalf("CanonicalAADInputs() = %+v", got)
	}
}

func TestMetadataV1PersistsAADBindingAndNonce(t *testing.T) {
	metadata := MetadataV1(CanonicalAADInputs{SecretID: "secret-id", VersionID: "version-id"}, "bm9uY2U=")
	if err := ValidateMetadata(metadata); err != nil {
		t.Fatalf("ValidateMetadata() error = %v", err)
	}
	if metadata.AAD == nil || metadata.AAD.SecretID != "secret-id" || metadata.AAD.VersionID != "version-id" {
		t.Fatalf("AAD = %+v", metadata.AAD)
	}
	if metadata.ContentNonce != "bm9uY2U=" {
		t.Fatalf("ContentNonce = %q", metadata.ContentNonce)
	}
}
