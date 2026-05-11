// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package clientcrypto

// This package intentionally contains the shared, language-neutral crypto
// building blocks used by SDK test vectors. Keep changes here conservative:
// any drift must be reflected in every SDK and in testdata/client-crypto/v1.

import (
	"encoding/json"
	"errors"
)

var ErrMalformedAAD = errors.New("malformed client crypto aad")

// CanonicalAADInputs identifies the stable resource metadata bound into client-side AEAD AAD.
type CanonicalAADInputs struct {
	Namespace string `json:"namespace,omitempty"`
	Key       string `json:"key,omitempty"`
}

type canonicalAADDocument struct {
	Version        string `json:"version"`
	ContentCipher  string `json:"content_cipher"`
	EnvelopeScheme string `json:"envelope_scheme"`
	Namespace      string `json:"namespace"`
	Key            string `json:"key"`
}

// BuildCanonicalAAD returns the deterministic JSON AAD bytes shared by all crypto clients.
//
// The serialized field order is part of the wire contract. Do not replace this
// with a map-based encoder unless all language fixtures are regenerated.
func BuildCanonicalAAD(metadata Metadata, inputs CanonicalAADInputs) ([]byte, error) {
	if err := ValidateMetadata(metadata); err != nil {
		return nil, err
	}
	if inputs.Namespace == "" || inputs.Key == "" {
		return nil, ErrMalformedAAD
	}
	return json.Marshal(canonicalAADDocument{
		Version:        metadata.Version,
		ContentCipher:  metadata.ContentCipher,
		EnvelopeScheme: metadata.EnvelopeScheme,
		Namespace:      inputs.Namespace,
		Key:            inputs.Key,
	})
}
