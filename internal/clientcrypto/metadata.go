package clientcrypto

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	VersionV1       = "custodia.client-crypto.v1"
	ContentCipherV1 = "aes-256-gcm"
	EnvelopeHPKEV1  = "hpke-v1"
)

var (
	ErrUnsupportedVersion        = errors.New("unsupported client crypto version")
	ErrUnsupportedContentCipher  = errors.New("unsupported client content cipher")
	ErrUnsupportedEnvelopeScheme = errors.New("unsupported client envelope scheme")
	ErrMalformedMetadata         = errors.New("malformed client crypto metadata")
)

type Metadata struct {
	Version        string `json:"version"`
	ContentCipher  string `json:"content_cipher"`
	EnvelopeScheme string `json:"envelope_scheme"`
}

func ParseMetadata(payload []byte) (Metadata, error) {
	if len(payload) == 0 {
		return Metadata{}, ErrMalformedMetadata
	}
	var metadata Metadata
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return Metadata{}, fmt.Errorf("%w: %v", ErrMalformedMetadata, err)
	}
	if err := ValidateMetadata(metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func ValidateMetadata(metadata Metadata) error {
	if metadata.Version != VersionV1 {
		return ErrUnsupportedVersion
	}
	if metadata.ContentCipher != ContentCipherV1 {
		return ErrUnsupportedContentCipher
	}
	if metadata.EnvelopeScheme != EnvelopeHPKEV1 {
		return ErrUnsupportedEnvelopeScheme
	}
	return nil
}
