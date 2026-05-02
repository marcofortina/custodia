package model

import "regexp"

const MaxClientIDLength = 128

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// ValidClientID validates transport and storage identifiers without assigning any crypto meaning to them.
func ValidClientID(value string) bool {
	return value != "" && len(value) <= MaxClientIDLength && clientIDPattern.MatchString(value)
}
