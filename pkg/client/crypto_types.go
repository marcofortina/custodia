package client

import (
	"encoding/json"
	"time"
)

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

type DecryptedSecret struct {
	SecretID        string
	VersionID       string
	Plaintext       []byte
	CryptoMetadata  json.RawMessage
	Permissions     int
	GrantedAt       time.Time
	AccessExpiresAt *time.Time
}
