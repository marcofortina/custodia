package model

import (
	"regexp"
	"strings"
	"unicode"
)

const (
	MaxClientIDLength   = 128
	MaxSecretNameLength = 255
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// ValidClientID validates transport and storage identifiers without assigning any crypto meaning to them.
func ValidClientID(value string) bool {
	return value != "" && len(value) <= MaxClientIDLength && clientIDPattern.MatchString(value)
}

// ValidSecretName keeps secret metadata bounded and printable while leaving ciphertext opaque.
func ValidSecretName(value string) bool {
	value = strings.TrimSpace(value)
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
