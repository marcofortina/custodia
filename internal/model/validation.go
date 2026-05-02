package model

import (
	"regexp"
	"strings"
	"unicode"
)

const (
	MaxClientIDLength      = 128
	MaxSecretNameLength    = 255
	MaxCryptoMetadataBytes = 16 * 1024
	MaxMTLSSubjectLength   = 512
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// ValidClientID validates transport and storage identifiers without assigning any crypto meaning to them.
func ValidClientID(value string) bool {
	return value != "" && len(value) <= MaxClientIDLength && clientIDPattern.MatchString(value)
}

// ValidMTLSSubject keeps certificate subject mappings bounded and printable.
func ValidMTLSSubject(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > MaxMTLSSubjectLength {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// NormalizeSecretName trims surrounding whitespace without changing the caller-defined secret name body.
func NormalizeSecretName(value string) string {
	return strings.TrimSpace(value)
}

// ValidSecretName keeps secret metadata bounded and printable while leaving ciphertext opaque.
func ValidSecretName(value string) bool {
	value = NormalizeSecretName(value)
	if value == "" || len(value) > MaxSecretNameLength {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ValidCryptoMetadata keeps opaque client-selected metadata bounded for storage and audit safety.
func ValidCryptoMetadata(value []byte) bool {
	return len(value) <= MaxCryptoMetadataBytes
}
