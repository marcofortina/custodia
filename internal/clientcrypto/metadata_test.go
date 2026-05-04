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
	_, err := ParseMetadata([]byte(`{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"rsa-legacy"}`))
	if !errors.Is(err, ErrUnsupportedEnvelopeScheme) {
		t.Fatalf("ParseMetadata() error = %v, want %v", err, ErrUnsupportedEnvelopeScheme)
	}
}
