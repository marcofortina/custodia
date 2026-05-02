package model

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

type Permission int

const (
	PermissionShare Permission = 1
	PermissionWrite Permission = 2
	PermissionRead  Permission = 4

	PermissionAll = PermissionShare | PermissionWrite | PermissionRead
)

func HasPermission(bits int, permission Permission) bool {
	return bits&int(permission) == int(permission)
}

func ValidPermissionBits(bits int) bool {
	return bits > 0 && bits&^int(PermissionAll) == 0
}

func ValidOpaqueBlob(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if _, err := base64.StdEncoding.DecodeString(value); err == nil {
		return true
	}
	_, err := base64.RawStdEncoding.DecodeString(value)
	return err == nil
}

type Client struct {
	ClientID    string     `json:"client_id"`
	MTLSSubject string     `json:"mtls_subject"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

type RecipientEnvelope struct {
	ClientID string `json:"client_id"`
	Envelope string `json:"envelope"`
}

type CreateSecretRequest struct {
	Name           string              `json:"name"`
	Ciphertext     string              `json:"ciphertext"`
	CryptoMetadata json.RawMessage     `json:"crypto_metadata,omitempty"`
	Envelopes      []RecipientEnvelope `json:"envelopes"`
	Permissions    int                 `json:"permissions"`
}

type CreateSecretVersionRequest struct {
	Ciphertext     string              `json:"ciphertext"`
	CryptoMetadata json.RawMessage     `json:"crypto_metadata,omitempty"`
	Envelopes      []RecipientEnvelope `json:"envelopes"`
	Permissions    int                 `json:"permissions"`
}

type ShareSecretRequest struct {
	VersionID      string `json:"version_id"`
	TargetClientID string `json:"target_client_id"`
	Envelope       string `json:"envelope"`
	Permissions    int    `json:"permissions"`
}

type SecretVersionRef struct {
	SecretID  string `json:"secret_id"`
	VersionID string `json:"version_id"`
}

type SecretReadResponse struct {
	SecretID       string          `json:"secret_id"`
	VersionID      string          `json:"version_id"`
	Ciphertext     string          `json:"ciphertext"`
	CryptoMetadata json.RawMessage `json:"crypto_metadata,omitempty"`
	Envelope       string          `json:"envelope"`
	Permissions    int             `json:"permissions"`
}

type RevokeClientRequest struct {
	ClientID string `json:"client_id"`
	Reason   string `json:"reason,omitempty"`
}

type AuditEvent struct {
	EventID       string          `json:"event_id"`
	OccurredAt    time.Time       `json:"occurred_at"`
	ActorClientID string          `json:"actor_client_id,omitempty"`
	Action        string          `json:"action"`
	ResourceType  string          `json:"resource_type"`
	ResourceID    string          `json:"resource_id,omitempty"`
	Outcome       string          `json:"outcome"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	PreviousHash  []byte          `json:"previous_hash,omitempty"`
	EventHash     []byte          `json:"event_hash"`
}
