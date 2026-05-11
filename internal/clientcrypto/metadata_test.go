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

func TestParseMetadataRejectsEmptyPayload(t *testing.T) {
	if _, err := ParseMetadata(nil); !errors.Is(err, ErrMalformedMetadata) {
		t.Fatalf("ParseMetadata(nil) error = %v, want %v", err, ErrMalformedMetadata)
	}
}

func TestParseMetadataValidatesRequiredAlgorithms(t *testing.T) {
	payload := []byte(`{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1"}`)
	metadata, err := ParseMetadata(payload)
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
	if metadata.Version != VersionV1 || metadata.ContentCipher != ContentCipherV1 || metadata.EnvelopeScheme != EnvelopeHPKEV1 {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
}

func TestParseMetadataRejectsUnsupportedValues(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    error
	}{
		{"version", `{"version":"v2","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1"}`, ErrUnsupportedVersion},
		{"cipher", `{"version":"custodia.client-crypto.v1","content_cipher":"aes-128-gcm","envelope_scheme":"hpke-v1"}`, ErrUnsupportedContentCipher},
		{"envelope", `{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"rsa"}`, ErrUnsupportedEnvelopeScheme},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseMetadata([]byte(tc.payload)); !errors.Is(err, tc.want) {
				t.Fatalf("ParseMetadata() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestBuildCanonicalAADUsesStableJSONOrder(t *testing.T) {
	aad, err := BuildCanonicalAAD(Metadata{
		Version:        VersionV1,
		ContentCipher:  ContentCipherV1,
		EnvelopeScheme: EnvelopeHPKEV1,
	}, CanonicalAADInputs{Namespace: "default", Key: "database-password"})
	if err != nil {
		t.Fatalf("BuildCanonicalAAD() error = %v", err)
	}
	want := `{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1","namespace":"default","key":"database-password"}`
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
		Version:        "v2",
		ContentCipher:  ContentCipherV1,
		EnvelopeScheme: EnvelopeHPKEV1,
	}, CanonicalAADInputs{Namespace: "default", Key: "database-password"})
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("BuildCanonicalAAD() error = %v, want %v", err, ErrUnsupportedVersion)
	}
}

func TestMetadataAADOverridesFallback(t *testing.T) {
	payload := []byte(`{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1","content_nonce_b64":"bm9uY2U=","aad":{"namespace":"db01","key":"user:sys"}}`)
	metadata, err := ParseMetadata(payload)
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
	if metadata.AAD == nil || metadata.AAD.Namespace != "db01" || metadata.AAD.Key != "user:sys" {
		t.Fatalf("metadata AAD = %+v", metadata.AAD)
	}
	fallback := CanonicalAADInputs{Namespace: "default", Key: "fallback"}
	if got := metadata.CanonicalAADInputs(fallback); got.Namespace != "db01" || got.Key != "user:sys" {
		t.Fatalf("CanonicalAADInputs() = %+v", got)
	}
}

func TestMetadataV1IncludesAADBinding(t *testing.T) {
	metadata := MetadataV1(CanonicalAADInputs{Namespace: "db01", Key: "user:sys"}, "bm9uY2U=")
	if metadata.Version != VersionV1 || metadata.ContentCipher != ContentCipherV1 || metadata.EnvelopeScheme != EnvelopeHPKEV1 || metadata.ContentNonce != "bm9uY2U=" {
		t.Fatalf("MetadataV1() = %+v", metadata)
	}
	if metadata.AAD == nil || metadata.AAD.Namespace != "db01" || metadata.AAD.Key != "user:sys" {
		t.Fatalf("MetadataV1() AAD = %+v", metadata.AAD)
	}
}
