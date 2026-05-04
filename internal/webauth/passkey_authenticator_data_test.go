// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package webauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestParsePasskeyAuthenticatorData(t *testing.T) {
	raw := make([]byte, 37)
	raw[32] = 0x45
	raw[36] = 7
	data, err := ParsePasskeyAuthenticatorData(raw)
	if err != nil {
		t.Fatalf("ParsePasskeyAuthenticatorData() error = %v", err)
	}
	if data.SignCount != 7 || !data.UserPresent || !data.UserVerified || !data.AttestedData || data.ExtensionData {
		t.Fatalf("unexpected authenticator data: %+v", data)
	}
}

func TestParsePasskeyAuthenticatorDataRejectsShortPayload(t *testing.T) {
	if _, err := ParsePasskeyAuthenticatorData([]byte{1, 2, 3}); err != ErrInvalidPasskeyAuthenticatorData {
		t.Fatalf("ParsePasskeyAuthenticatorData() error = %v", err)
	}
}

func TestParsePasskeyAuthenticatorDataBase64URL(t *testing.T) {
	raw := make([]byte, 37)
	raw[32] = 0x01
	raw[33] = 0
	raw[34] = 0
	raw[35] = 1
	raw[36] = 2
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	data, err := ParsePasskeyAuthenticatorDataBase64URL(encoded)
	if err != nil {
		t.Fatalf("ParsePasskeyAuthenticatorDataBase64URL() error = %v", err)
	}
	if data.SignCount != 258 || !data.UserPresent {
		t.Fatalf("unexpected authenticator data: %+v", data)
	}
}

func TestValidatePasskeySignCount(t *testing.T) {
	if err := ValidatePasskeySignCount(0, 0); err != nil {
		t.Fatalf("zero previous counter should be accepted: %v", err)
	}
	if err := ValidatePasskeySignCount(7, 8); err != nil {
		t.Fatalf("increasing counter should be accepted: %v", err)
	}
	if err := ValidatePasskeySignCount(7, 7); err != ErrInvalidPasskeyAuthenticatorData {
		t.Fatalf("non-increasing counter error = %v", err)
	}
}

func TestValidatePasskeyAuthenticatorData(t *testing.T) {
	raw := authenticatorDataForRPID("example.com", 0x05, 9)
	data, err := ParsePasskeyAuthenticatorData(raw)
	if err != nil {
		t.Fatalf("ParsePasskeyAuthenticatorData() error = %v", err)
	}
	if err := ValidatePasskeyAuthenticatorData(data, "example.com", true); err != nil {
		t.Fatalf("ValidatePasskeyAuthenticatorData() error = %v", err)
	}
}

func TestValidatePasskeyAuthenticatorDataRejectsWrongRPID(t *testing.T) {
	data, err := ParsePasskeyAuthenticatorData(authenticatorDataForRPID("example.com", 0x05, 9))
	if err != nil {
		t.Fatalf("ParsePasskeyAuthenticatorData() error = %v", err)
	}
	if err := ValidatePasskeyAuthenticatorData(data, "evil.example.com", true); err != ErrInvalidPasskeyAuthenticatorData {
		t.Fatalf("ValidatePasskeyAuthenticatorData() error = %v, want %v", err, ErrInvalidPasskeyAuthenticatorData)
	}
}

func TestValidatePasskeyAuthenticatorDataRejectsMissingUserVerification(t *testing.T) {
	data, err := ParsePasskeyAuthenticatorData(authenticatorDataForRPID("example.com", 0x01, 9))
	if err != nil {
		t.Fatalf("ParsePasskeyAuthenticatorData() error = %v", err)
	}
	if err := ValidatePasskeyAuthenticatorData(data, "example.com", true); err != ErrInvalidPasskeyAuthenticatorData {
		t.Fatalf("ValidatePasskeyAuthenticatorData() error = %v, want %v", err, ErrInvalidPasskeyAuthenticatorData)
	}
}

func authenticatorDataForRPID(rpID string, flags byte, signCount uint32) []byte {
	raw := make([]byte, 37)
	digest := sha256.Sum256([]byte(rpID))
	copy(raw[:32], digest[:])
	raw[32] = flags
	raw[33] = byte(signCount >> 24)
	raw[34] = byte(signCount >> 16)
	raw[35] = byte(signCount >> 8)
	raw[36] = byte(signCount)
	return raw
}
