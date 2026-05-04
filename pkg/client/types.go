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

type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

type RevocationStatus struct {
	Configured       bool      `json:"configured"`
	Valid            bool      `json:"valid"`
	Source           string    `json:"source,omitempty"`
	Issuer           string    `json:"issuer,omitempty"`
	ThisUpdate       time.Time `json:"this_update,omitempty"`
	NextUpdate       time.Time `json:"next_update,omitempty"`
	RevokedCount     int       `json:"revoked_count"`
	ExpiresInSeconds int64     `json:"expires_in_seconds,omitempty"`
	Error            string    `json:"error,omitempty"`
}

type RuntimeDiagnostics struct {
	StartedAt       time.Time `json:"started_at"`
	UptimeSeconds   int64     `json:"uptime_seconds"`
	Goroutines      int       `json:"goroutines"`
	AllocBytes      uint64    `json:"alloc_bytes"`
	TotalAllocBytes uint64    `json:"total_alloc_bytes"`
	SysBytes        uint64    `json:"sys_bytes"`
}

type OperationalStatus struct {
	Status                         string    `json:"status"`
	Store                          string    `json:"store"`
	StoreBackend                   string    `json:"store_backend,omitempty"`
	RateLimiter                    string    `json:"rate_limiter"`
	RateLimitBackend               string    `json:"rate_limit_backend,omitempty"`
	MaxEnvelopesPerSecret          int       `json:"max_envelopes_per_secret"`
	ClientRateLimitPerSec          int       `json:"client_rate_limit_per_sec"`
	GlobalRateLimitPerSec          int       `json:"global_rate_limit_per_sec"`
	IPRateLimitPerSec              int       `json:"ip_rate_limit_per_sec"`
	Build                          BuildInfo `json:"build"`
	WebMFARequired                 bool      `json:"web_mfa_required"`
	WebPasskeyEnabled              bool      `json:"web_passkey_enabled"`
	WebPasskeyCredentials          int       `json:"web_passkey_credentials"`
	WebPasskeyUserVerification     string    `json:"web_passkey_user_verification,omitempty"`
	WebPasskeyCredentialKeyStorage string    `json:"web_passkey_credential_key_storage,omitempty"`
	WebPasskeyCredentialKeyParser  string    `json:"web_passkey_credential_key_parser,omitempty"`
	WebPasskeyAssertionVerifier    string    `json:"web_passkey_assertion_verifier,omitempty"`
	DeploymentMode                 string    `json:"deployment_mode,omitempty"`
	DatabaseHATarget               string    `json:"database_ha_target,omitempty"`
	AuditShipmentSink              string    `json:"audit_shipment_sink,omitempty"`
}

type RevocationSerialStatus struct {
	SerialHex    string     `json:"serial_hex"`
	Status       string     `json:"status"`
	ThisUpdate   time.Time  `json:"this_update"`
	NextUpdate   time.Time  `json:"next_update"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokedCount int        `json:"revoked_count"`
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

type AuditExportArtifact struct {
	Body       []byte
	SHA256     string
	EventCount string
}
