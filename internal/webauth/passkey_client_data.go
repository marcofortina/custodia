package webauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var ErrInvalidPasskeyClientData = errors.New("invalid passkey client data")

type PasskeyClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func VerifyPasskeyClientDataJSON(raw []byte, expectedType, expectedChallenge, expectedOrigin string) (*PasskeyClientData, error) {
	var data PasskeyClientData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, ErrInvalidPasskeyClientData
	}
	if strings.TrimSpace(data.Type) != strings.TrimSpace(expectedType) || strings.TrimSpace(data.Challenge) != strings.TrimSpace(expectedChallenge) || strings.TrimSpace(data.Origin) != strings.TrimSpace(expectedOrigin) {
		return nil, ErrInvalidPasskeyClientData
	}
	if _, err := base64.RawURLEncoding.DecodeString(data.Challenge); err != nil {
		return nil, ErrInvalidPasskeyClientData
	}
	return &data, nil
}
