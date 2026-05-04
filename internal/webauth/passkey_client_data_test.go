// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package webauth

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestVerifyPasskeyClientDataJSON(t *testing.T) {
	challenge, err := NewPasskeyChallenge()
	if err != nil {
		t.Fatalf("NewPasskeyChallenge() error = %v", err)
	}
	payload, err := json.Marshal(PasskeyClientData{Type: "webauthn.get", Challenge: challenge, Origin: "https://vault.example.com"})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	data, err := VerifyPasskeyClientDataJSON(payload, "webauthn.get", challenge, "https://vault.example.com")
	if err != nil {
		t.Fatalf("VerifyPasskeyClientDataJSON() error = %v", err)
	}
	if data.Challenge != challenge {
		t.Fatalf("challenge = %q", data.Challenge)
	}
}

func TestVerifyPasskeyClientDataJSONRejectsMismatch(t *testing.T) {
	challenge, err := NewPasskeyChallenge()
	if err != nil {
		t.Fatalf("NewPasskeyChallenge() error = %v", err)
	}
	payload, err := json.Marshal(PasskeyClientData{Type: "webauthn.get", Challenge: challenge, Origin: "https://evil.example.com"})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	_, err = VerifyPasskeyClientDataJSON(payload, "webauthn.get", challenge, "https://vault.example.com")
	if !errors.Is(err, ErrInvalidPasskeyClientData) {
		t.Fatalf("VerifyPasskeyClientDataJSON() error = %v, want %v", err, ErrInvalidPasskeyClientData)
	}
}
