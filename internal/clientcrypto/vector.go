// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package clientcrypto

// Vector loading and validation keeps SDK compatibility concrete: a new client
// is not considered compatible until it passes the same metadata, AAD, content
// and envelope fixtures as the existing implementations.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

var ErrMalformedVector = errors.New("malformed client crypto vector")

// Vector describes a shared client-crypto fixture.
type Vector struct {
	Case               string             `json:"case"`
	Status             string             `json:"status"`
	CryptoMetadata     Metadata           `json:"crypto_metadata"`
	AADInputs          CanonicalAADInputs `json:"aad_inputs"`
	MismatchAADInputs  CanonicalAADInputs `json:"mismatch_aad_inputs,omitempty"`
	CanonicalAAD       string             `json:"canonical_aad"`
	CanonicalAADSHA256 string             `json:"canonical_aad_sha256"`
	Plaintext          string             `json:"plaintext_b64,omitempty"`
	ContentDEK         string             `json:"content_dek_b64,omitempty"`
	ContentNonce       string             `json:"content_nonce_b64,omitempty"`
	Ciphertext         string             `json:"ciphertext,omitempty"`
	TamperedCiphertext string             `json:"tampered_ciphertext,omitempty"`
	Envelopes          []VectorEnvelope   `json:"envelopes,omitempty"`
	Envelope           json.RawMessage    `json:"envelope,omitempty"`
	TargetClientID     string             `json:"target_client_id,omitempty"`
	Failure            string             `json:"failure,omitempty"`
	ExpectedError      string             `json:"expected_error"`
	Expected           string             `json:"expected,omitempty"`
}

// VectorEnvelope describes one deterministic HPKE recipient envelope fixture.
type VectorEnvelope struct {
	ClientID                  string `json:"client_id"`
	RecipientPrivateKey       string `json:"recipient_private_key_b64,omitempty"`
	RecipientPublicKey        string `json:"recipient_public_key_b64,omitempty"`
	SenderEphemeralPrivateKey string `json:"sender_ephemeral_private_key_b64,omitempty"`
	SenderEphemeralPublicKey  string `json:"sender_ephemeral_public_key_b64,omitempty"`
	WrongRecipientPrivateKey  string `json:"wrong_recipient_private_key_b64,omitempty"`
	Envelope                  string `json:"envelope"`
}

// LoadVector reads and validates a client-crypto fixture file.
func LoadVector(path string) (Vector, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return Vector{}, err
	}
	var vector Vector
	if err := json.Unmarshal(payload, &vector); err != nil {
		return Vector{}, fmt.Errorf("%w: %v", ErrMalformedVector, err)
	}
	if err := ValidateVector(vector); err != nil {
		return Vector{}, err
	}
	return vector, nil
}

// ValidateVector validates deterministic metadata, canonical AAD, ciphertext and envelope fields shared by SDK tests.
func ValidateVector(vector Vector) error {
	if vector.Case == "" || vector.Status == "" {
		return fmt.Errorf("%w: case and status are required", ErrMalformedVector)
	}
	if vector.CanonicalAAD == "" || vector.CanonicalAADSHA256 == "" {
		return fmt.Errorf("%w: canonical_aad and canonical_aad_sha256 are required", ErrMalformedVector)
	}
	if err := validateCanonicalAADHash(vector); err != nil {
		return err
	}
	metadataErr := ValidateMetadata(vector.CryptoMetadata)
	if metadataErr != nil {
		return validateExpectedMetadataError(vector.ExpectedError, metadataErr)
	}
	aad, err := BuildCanonicalAAD(vector.CryptoMetadata, vector.AADInputs)
	if err != nil {
		return err
	}
	if string(aad) != vector.CanonicalAAD {
		return fmt.Errorf("%w: canonical_aad mismatch", ErrMalformedVector)
	}
	if vector.requiresCryptoValidation() {
		return validateVectorCryptoPayload(vector, aad)
	}
	return nil
}

func (vector Vector) requiresCryptoValidation() bool {
	switch vector.Status {
	case "deterministic-crypto", "deterministic-crypto-negative":
		return true
	default:
		return false
	}
}

func validateVectorCryptoPayload(vector Vector, aad []byte) error {
	plaintext, err := decodeVectorBase64("plaintext_b64", vector.Plaintext)
	if err != nil {
		return err
	}
	dek, err := decodeVectorBase64("content_dek_b64", vector.ContentDEK)
	if err != nil {
		return err
	}
	nonce, err := decodeVectorBase64("content_nonce_b64", vector.ContentNonce)
	if err != nil {
		return err
	}
	ciphertext, err := decodeVectorBase64("ciphertext", vector.Ciphertext)
	if err != nil {
		return err
	}
	sealed, err := SealContentAES256GCM(dek, nonce, plaintext, aad)
	if err != nil {
		return err
	}
	if !bytes.Equal(sealed, ciphertext) {
		return fmt.Errorf("%w: ciphertext mismatch", ErrMalformedVector)
	}
	opened, err := OpenContentAES256GCM(dek, nonce, ciphertext, aad)
	if err != nil {
		return err
	}
	if !bytes.Equal(opened, plaintext) {
		return fmt.Errorf("%w: plaintext mismatch", ErrMalformedVector)
	}
	for _, envelope := range vector.allEnvelopes() {
		if err := validateVectorEnvelope(envelope, dek, aad); err != nil {
			return err
		}
	}
	return validateVectorExpectedCryptoError(vector, dek, nonce, ciphertext, aad)
}

func validateVectorEnvelope(envelope VectorEnvelope, dek []byte, aad []byte) error {
	if envelope.ClientID == "" {
		return fmt.Errorf("%w: envelope client_id is required", ErrMalformedVector)
	}
	recipientPrivateKey, err := decodeVectorBase64("recipient_private_key_b64", envelope.RecipientPrivateKey)
	if err != nil {
		return err
	}
	recipientPublicKey, err := decodeVectorBase64("recipient_public_key_b64", envelope.RecipientPublicKey)
	if err != nil {
		return err
	}
	senderEphemeralPrivateKey, err := decodeVectorBase64("sender_ephemeral_private_key_b64", envelope.SenderEphemeralPrivateKey)
	if err != nil {
		return err
	}
	senderEphemeralPublicKey, err := decodeVectorBase64("sender_ephemeral_public_key_b64", envelope.SenderEphemeralPublicKey)
	if err != nil {
		return err
	}
	derivedRecipientPublicKey, err := DeriveX25519PublicKey(recipientPrivateKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(derivedRecipientPublicKey, recipientPublicKey) {
		return fmt.Errorf("%w: recipient public key mismatch", ErrMalformedVector)
	}
	derivedEphemeralPublicKey, err := DeriveX25519PublicKey(senderEphemeralPrivateKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(derivedEphemeralPublicKey, senderEphemeralPublicKey) {
		return fmt.Errorf("%w: sender ephemeral public key mismatch", ErrMalformedVector)
	}
	encoded, err := SealHPKEV1Envelope(recipientPublicKey, senderEphemeralPrivateKey, dek, aad)
	if err != nil {
		return err
	}
	actualEnvelope, err := decodeVectorBase64("envelope", envelope.Envelope)
	if err != nil {
		return err
	}
	if !bytes.Equal(encoded, actualEnvelope) {
		return fmt.Errorf("%w: envelope mismatch", ErrMalformedVector)
	}
	opened, err := OpenHPKEV1Envelope(recipientPrivateKey, actualEnvelope, aad)
	if err != nil {
		return err
	}
	if !bytes.Equal(opened, dek) {
		return fmt.Errorf("%w: envelope DEK mismatch", ErrMalformedVector)
	}
	return nil
}

func validateVectorExpectedCryptoError(vector Vector, dek, nonce, ciphertext, aad []byte) error {
	switch vector.ExpectedError {
	case "":
		return nil
	case "ciphertext_authentication_failed":
		tampered, err := decodeVectorBase64("tampered_ciphertext", vector.TamperedCiphertext)
		if err != nil {
			return err
		}
		if _, err := OpenContentAES256GCM(dek, nonce, tampered, aad); !errors.Is(err, ErrContentAuthFailed) {
			return fmt.Errorf("%w: expected ciphertext authentication failure", ErrMalformedVector)
		}
		return nil
	case "aad_mismatch":
		mismatchedAAD, err := BuildCanonicalAAD(vector.CryptoMetadata, vector.MismatchAADInputs)
		if err != nil {
			return err
		}
		if _, err := OpenContentAES256GCM(dek, nonce, ciphertext, mismatchedAAD); !errors.Is(err, ErrContentAuthFailed) {
			return fmt.Errorf("%w: expected AAD mismatch failure", ErrMalformedVector)
		}
		return nil
	case "wrong_recipient":
		recipientEnvelope, err := vector.singleEnvelope()
		if err != nil {
			return err
		}
		wrongRecipientPrivateKey, err := decodeVectorBase64("wrong_recipient_private_key_b64", recipientEnvelope.WrongRecipientPrivateKey)
		if err != nil {
			return err
		}
		envelope, err := decodeVectorBase64("envelope", recipientEnvelope.Envelope)
		if err != nil {
			return err
		}
		if _, err := OpenHPKEV1Envelope(wrongRecipientPrivateKey, envelope, aad); !errors.Is(err, ErrEnvelopeAuthFailed) {
			return fmt.Errorf("%w: expected wrong recipient failure", ErrMalformedVector)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported expected_error %q", ErrMalformedVector, vector.ExpectedError)
	}
}

func (vector Vector) allEnvelopes() []VectorEnvelope {
	envelopes := append([]VectorEnvelope{}, vector.Envelopes...)
	if envelope, err := vector.singleEnvelope(); err == nil {
		envelopes = append(envelopes, envelope)
	}
	return envelopes
}

func (vector Vector) singleEnvelope() (VectorEnvelope, error) {
	if len(vector.Envelope) == 0 {
		return VectorEnvelope{}, fmt.Errorf("%w: envelope is required", ErrMalformedVector)
	}
	var envelope VectorEnvelope
	if err := json.Unmarshal(vector.Envelope, &envelope); err != nil {
		return VectorEnvelope{}, fmt.Errorf("%w: envelope object is required: %v", ErrMalformedVector, err)
	}
	return envelope, nil
}

func decodeVectorBase64(field string, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrMalformedVector, field)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not base64: %v", ErrMalformedVector, field, err)
	}
	return decoded, nil
}

func validateCanonicalAADHash(vector Vector) error {
	sum := sha256.Sum256([]byte(vector.CanonicalAAD))
	actual := hex.EncodeToString(sum[:])
	if actual != vector.CanonicalAADSHA256 {
		return fmt.Errorf("%w: canonical_aad_sha256 mismatch", ErrMalformedVector)
	}
	return nil
}

func validateExpectedMetadataError(expected string, err error) error {
	switch {
	case errors.Is(err, ErrUnsupportedVersion):
		if expected == "unsupported_crypto_version" {
			return nil
		}
	case errors.Is(err, ErrUnsupportedContentCipher):
		if expected == "unsupported_content_cipher" {
			return nil
		}
	case errors.Is(err, ErrUnsupportedEnvelopeScheme):
		if expected == "unsupported_envelope_scheme" {
			return nil
		}
	case errors.Is(err, ErrMalformedMetadata):
		if expected == "malformed_metadata" {
			return nil
		}
	}
	return err
}
