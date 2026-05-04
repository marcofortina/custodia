// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package client

import (
	"encoding/json"
	"time"
)

// CryptoClient wraps the transport client with local content encryption and envelope management.
type CryptoClient struct {
	transport *Client
	options   CryptoOptions
}

type CreateEncryptedSecretRequest struct {
	Name        string
	Plaintext   []byte
	Recipients  []string
	Permissions int
	ExpiresAt   *time.Time
}

type CreateEncryptedSecretVersionRequest struct {
	Plaintext   []byte
	Recipients  []string
	Permissions int
	ExpiresAt   *time.Time
}

type ShareEncryptedSecretRequest struct {
	TargetClientID string
	Permissions    int
	ExpiresAt      *time.Time
}

// DecryptedSecret is intentionally returned only by the high-level crypto client, never by raw transport methods.
type DecryptedSecret struct {
	SecretID        string
	VersionID       string
	Plaintext       []byte
	CryptoMetadata  json.RawMessage
	Permissions     int
	GrantedAt       time.Time
	AccessExpiresAt *time.Time
}
