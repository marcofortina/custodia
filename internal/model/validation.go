package model

import (
	"regexp"
	"strings"
	"unicode"
)

const (
	MaxClientIDLength          = 128
	MaxSecretNameLength        = 255
	MaxCryptoMetadataBytes     = 16 * 1024
	MaxOpaqueBlobBytes         = 768 * 1024
	MaxMTLSSubjectLength       = 512
	MaxAuditActionLength       = 128
	MaxAuditResourceTypeLength = 64
	MaxAuditResourceIDLength   = 256
	MaxRevocationReasonLength  = 512
)

var (
	clientIDPattern          = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
	auditActionPattern       = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
	auditResourceTypePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
	uuidIDPattern            = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// ValidClientID validates transport and storage identifiers without assigning any crypto meaning to them.
func ValidClientID(value string) bool {
	return value != "" && len(value) <= MaxClientIDLength && clientIDPattern.MatchString(value)
}

// ValidUUIDID validates server-generated resource identifiers.
func ValidUUIDID(value string) bool {
	return uuidIDPattern.MatchString(strings.ToLower(strings.TrimSpace(value)))
}

func ValidOptionalUUIDID(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || ValidUUIDID(value)
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

// ValidAuditAction validates audit action filters without interpreting business semantics.
func ValidAuditAction(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= MaxAuditActionLength && auditActionPattern.MatchString(value)
}

// ValidAuditResourceType validates audit resource type filters without exposing resource data.
func ValidAuditResourceType(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= MaxAuditResourceTypeLength && auditResourceTypePattern.MatchString(value)
}

// ValidAuditResourceID keeps audit resource filters bounded and printable.
func ValidAuditResourceID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > MaxAuditResourceIDLength {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ValidRevocationReason keeps operator-supplied revocation metadata bounded and printable.
func ValidRevocationReason(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) > MaxRevocationReasonLength {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
