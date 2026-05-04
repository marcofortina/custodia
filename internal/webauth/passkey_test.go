// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package webauth

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestNewPasskeyChallenge(t *testing.T) {
	challenge, err := NewPasskeyChallenge()
	if err != nil {
		t.Fatalf("NewPasskeyChallenge() error = %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		t.Fatalf("challenge is not base64url: %v", err)
	}
	if len(decoded) != PasskeyChallengeBytes {
		t.Fatalf("challenge bytes = %d", len(decoded))
	}
}

func TestNewPasskeyOptions(t *testing.T) {
	options, err := NewPasskeyOptions("vault.example.com", "Custodia", "admin", "admin", 5*time.Minute, true)
	if err != nil {
		t.Fatalf("NewPasskeyOptions() error = %v", err)
	}
	if options.RPID != "vault.example.com" || options.RPName != "Custodia" || options.UserID != "admin" || options.UserVerification != "required" || options.Attestation != "none" {
		t.Fatalf("unexpected options: %+v", options)
	}
	if options.TimeoutMS != int64((5 * time.Minute).Milliseconds()) {
		t.Fatalf("timeout = %d", options.TimeoutMS)
	}
}

func TestNewPasskeyOptionsRejectsInvalidConfig(t *testing.T) {
	_, err := NewPasskeyOptions("", "Custodia", "admin", "admin", time.Minute, false)
	if !errors.Is(err, ErrInvalidPasskeyConfig) {
		t.Fatalf("NewPasskeyOptions() error = %v, want %v", err, ErrInvalidPasskeyConfig)
	}
	_, err = NewPasskeyOptions("vault.example.com", "Custodia", "admin", "admin", 0, false)
	if !errors.Is(err, ErrInvalidPasskeyConfig) {
		t.Fatalf("NewPasskeyOptions() error = %v, want %v", err, ErrInvalidPasskeyConfig)
	}
}
