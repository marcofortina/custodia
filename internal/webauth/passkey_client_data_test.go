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
