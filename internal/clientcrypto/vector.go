package clientcrypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

var ErrMalformedVector = errors.New("malformed client crypto vector")

// Vector describes a shared client-crypto fixture. Current fixtures are deterministic-AAD only.
type Vector struct {
	Case               string             `json:"case"`
	Status             string             `json:"status"`
	CryptoMetadata     Metadata           `json:"crypto_metadata"`
	AADInputs          CanonicalAADInputs `json:"aad_inputs"`
	CanonicalAAD       string             `json:"canonical_aad"`
	CanonicalAADSHA256 string             `json:"canonical_aad_sha256"`
	ExpectedError      string             `json:"expected_error"`
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

// ValidateVector validates deterministic metadata and canonical-AAD fields shared by SDK tests.
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
	return nil
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
