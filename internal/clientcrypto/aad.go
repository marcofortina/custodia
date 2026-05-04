package clientcrypto

import (
	"encoding/json"
	"errors"
)

var ErrMalformedAAD = errors.New("malformed client crypto aad")

// CanonicalAADInputs identifies the stable resource metadata bound into client-side AEAD AAD.
type CanonicalAADInputs struct {
	SecretID   string `json:"secret_id,omitempty"`
	SecretName string `json:"secret_name,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
}

type canonicalAADDocument struct {
	Version        string `json:"version"`
	ContentCipher  string `json:"content_cipher"`
	EnvelopeScheme string `json:"envelope_scheme"`
	SecretID       string `json:"secret_id,omitempty"`
	SecretName     string `json:"secret_name,omitempty"`
	VersionID      string `json:"version_id,omitempty"`
}

// BuildCanonicalAAD returns the deterministic JSON AAD bytes shared by all future crypto clients.
func BuildCanonicalAAD(metadata Metadata, inputs CanonicalAADInputs) ([]byte, error) {
	if err := ValidateMetadata(metadata); err != nil {
		return nil, err
	}
	if inputs.SecretID == "" && inputs.SecretName == "" {
		return nil, ErrMalformedAAD
	}
	return json.Marshal(canonicalAADDocument{
		Version:        metadata.Version,
		ContentCipher:  metadata.ContentCipher,
		EnvelopeScheme: metadata.EnvelopeScheme,
		SecretID:       inputs.SecretID,
		SecretName:     inputs.SecretName,
		VersionID:      inputs.VersionID,
	})
}
