package client

import (
	"encoding/json"
	"time"

	"custodia/internal/model"
)

// Permission bits mirror the server-side authorization model without requiring external SDK users to import internal packages.
const (
	PermissionShare = 1
	PermissionWrite = 2
	PermissionRead  = 4
	PermissionAll   = PermissionShare | PermissionWrite | PermissionRead
)

type ClientInfo struct {
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

type CreateClientPayload struct {
	ClientID    string `json:"client_id"`
	MTLSSubject string `json:"mtls_subject"`
}

type RevokeClientPayload struct {
	ClientID string `json:"client_id"`
	Reason   string `json:"reason,omitempty"`
}

type CreateSecretPayload struct {
	Name           string              `json:"name"`
	Ciphertext     string              `json:"ciphertext"`
	CryptoMetadata json.RawMessage     `json:"crypto_metadata,omitempty"`
	Envelopes      []RecipientEnvelope `json:"envelopes"`
	Permissions    int                 `json:"permissions"`
	ExpiresAt      *time.Time          `json:"expires_at,omitempty"`
}

type CreateSecretVersionPayload struct {
	Ciphertext     string              `json:"ciphertext"`
	CryptoMetadata json.RawMessage     `json:"crypto_metadata,omitempty"`
	Envelopes      []RecipientEnvelope `json:"envelopes"`
	Permissions    int                 `json:"permissions"`
	ExpiresAt      *time.Time          `json:"expires_at,omitempty"`
}

type ShareSecretPayload struct {
	VersionID      string     `json:"version_id"`
	TargetClientID string     `json:"target_client_id"`
	Envelope       string     `json:"envelope"`
	Permissions    int        `json:"permissions"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

type AccessGrantPayload struct {
	VersionID      string     `json:"version_id,omitempty"`
	TargetClientID string     `json:"target_client_id"`
	Permissions    int        `json:"permissions"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

type ActivateAccessPayload struct {
	Envelope string `json:"envelope"`
}

type SecretVersionRef struct {
	SecretID  string `json:"secret_id"`
	VersionID string `json:"version_id"`
}

type AccessGrantRef struct {
	SecretID  string `json:"secret_id"`
	VersionID string `json:"version_id"`
	ClientID  string `json:"client_id"`
	Status    string `json:"status"`
}

type SecretMetadata struct {
	SecretID          string     `json:"secret_id"`
	Name              string     `json:"name"`
	VersionID         string     `json:"version_id"`
	Permissions       int        `json:"permissions"`
	CreatedAt         time.Time  `json:"created_at"`
	CreatedByClientID string     `json:"created_by_client_id"`
	AccessExpiresAt   *time.Time `json:"access_expires_at,omitempty"`
}

type SecretVersionMetadata struct {
	SecretID          string     `json:"secret_id"`
	VersionID         string     `json:"version_id"`
	CreatedAt         time.Time  `json:"created_at"`
	CreatedByClientID string     `json:"created_by_client_id"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}

type SecretAccessMetadata struct {
	SecretID    string     `json:"secret_id"`
	VersionID   string     `json:"version_id"`
	ClientID    string     `json:"client_id"`
	Permissions int        `json:"permissions"`
	GrantedAt   time.Time  `json:"granted_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type AccessGrantMetadata struct {
	SecretID            string     `json:"secret_id"`
	VersionID           string     `json:"version_id"`
	ClientID            string     `json:"client_id"`
	RequestedByClientID string     `json:"requested_by_client_id"`
	Permissions         int        `json:"permissions"`
	RequestedAt         time.Time  `json:"requested_at"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	Status              string     `json:"status"`
}

type SecretReadResponse struct {
	SecretID        string          `json:"secret_id"`
	VersionID       string          `json:"version_id"`
	Ciphertext      string          `json:"ciphertext"`
	CryptoMetadata  json.RawMessage `json:"crypto_metadata,omitempty"`
	Envelope        string          `json:"envelope"`
	Permissions     int             `json:"permissions"`
	GrantedAt       time.Time       `json:"granted_at"`
	AccessExpiresAt *time.Time      `json:"access_expires_at,omitempty"`
}

func toModelEnvelopes(envelopes []RecipientEnvelope) []model.RecipientEnvelope {
	converted := make([]model.RecipientEnvelope, 0, len(envelopes))
	for _, envelope := range envelopes {
		converted = append(converted, model.RecipientEnvelope{ClientID: envelope.ClientID, Envelope: envelope.Envelope})
	}
	return converted
}

func fromModelClient(value model.Client) ClientInfo {
	return ClientInfo(value)
}

func fromModelSecretRef(value model.SecretVersionRef) SecretVersionRef {
	return SecretVersionRef(value)
}

func fromModelAccessGrantRef(value model.AccessGrantRef) AccessGrantRef {
	return AccessGrantRef(value)
}

func fromModelSecretMetadata(value model.SecretMetadata) SecretMetadata {
	return SecretMetadata(value)
}

func fromModelSecretVersionMetadata(value model.SecretVersionMetadata) SecretVersionMetadata {
	return SecretVersionMetadata(value)
}

func fromModelSecretAccessMetadata(value model.SecretAccessMetadata) SecretAccessMetadata {
	return SecretAccessMetadata(value)
}

func fromModelAccessGrantMetadata(value model.AccessGrantMetadata) AccessGrantMetadata {
	return AccessGrantMetadata(value)
}

func fromModelSecretReadResponse(value model.SecretReadResponse) SecretReadResponse {
	return SecretReadResponse(value)
}
