// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package webauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

const PasskeyChallengeBytes = 32

var ErrInvalidPasskeyConfig = errors.New("invalid passkey config")

type PasskeyOptions struct {
	Challenge        string `json:"challenge"`
	RPID             string `json:"rp_id"`
	RPName           string `json:"rp_name"`
	UserID           string `json:"user_id"`
	UserName         string `json:"user_name"`
	TimeoutMS        int64  `json:"timeout_ms"`
	Attestation      string `json:"attestation,omitempty"`
	UserVerification string `json:"user_verification"`
}

func NewPasskeyChallenge() (string, error) {
	buf := make([]byte, PasskeyChallengeBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func NewPasskeyOptions(rpID, rpName, userID, userName string, timeout time.Duration, registration bool) (*PasskeyOptions, error) {
	rpID = strings.TrimSpace(rpID)
	rpName = strings.TrimSpace(rpName)
	userID = strings.TrimSpace(userID)
	userName = strings.TrimSpace(userName)
	if rpID == "" || rpName == "" || userID == "" || userName == "" || timeout <= 0 {
		return nil, ErrInvalidPasskeyConfig
	}
	challenge, err := NewPasskeyChallenge()
	if err != nil {
		return nil, err
	}
	options := &PasskeyOptions{
		Challenge:        challenge,
		RPID:             rpID,
		RPName:           rpName,
		UserID:           userID,
		UserName:         userName,
		TimeoutMS:        timeout.Milliseconds(),
		UserVerification: "required",
	}
	if registration {
		options.Attestation = "none"
	}
	return options, nil
}
