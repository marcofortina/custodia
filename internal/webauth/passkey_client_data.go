// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

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

// VerifyPasskeyClientDataJSON checks the browser-supplied ceremony metadata before
// signature verification, binding type, challenge, and origin to this session.
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
