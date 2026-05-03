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
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return len(decoded) > 0 && len(decoded) <= MaxOpaqueBlobBytes
	}
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	return err == nil && len(decoded) > 0 && len(decoded) <= MaxOpaqueBlobBytes
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
	ExpiresAt      *time.Time          `json:"expires_at,omitempty"`
}

type CreateSecretVersionRequest struct {
	Ciphertext     string              `json:"ciphertext"`
	CryptoMetadata json.RawMessage     `json:"crypto_metadata,omitempty"`
	Envelopes      []RecipientEnvelope `json:"envelopes"`
	Permissions    int                 `json:"permissions"`
	ExpiresAt      *time.Time          `json:"expires_at,omitempty"`
}

type ShareSecretRequest struct {
	VersionID      string     `json:"version_id"`
	TargetClientID string     `json:"target_client_id"`
	Envelope       string     `json:"envelope"`
	Permissions    int        `json:"permissions"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

type AccessGrantRequest struct {
	VersionID      string     `json:"version_id,omitempty"`
	TargetClientID string     `json:"target_client_id"`
	Permissions    int        `json:"permissions"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

type ActivateAccessRequest struct {
	Envelope string `json:"envelope"`
}

type AccessGrantRef struct {
	SecretID  string `json:"secret_id"`
	VersionID string `json:"version_id"`
	ClientID  string `json:"client_id"`
	Status    string `json:"status"`
}

type SecretVersionRef struct {
	SecretID  string `json:"secret_id"`
	VersionID string `json:"version_id"`
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

// SecretVersionMetadata exposes version lifecycle metadata only. It deliberately omits ciphertext and crypto metadata.
type SecretVersionMetadata struct {
	SecretID          string     `json:"secret_id"`
	VersionID         string     `json:"version_id"`
	CreatedAt         time.Time  `json:"created_at"`
	CreatedByClientID string     `json:"created_by_client_id"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}

// SecretAccessMetadata exposes authorization metadata only. It deliberately omits envelopes.
type SecretAccessMetadata struct {
	SecretID    string     `json:"secret_id"`
	VersionID   string     `json:"version_id"`
	ClientID    string     `json:"client_id"`
	Permissions int        `json:"permissions"`
	GrantedAt   time.Time  `json:"granted_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// AccessGrantMetadata exposes pending grant metadata only. It deliberately omits envelopes.
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

type CreateClientRequest struct {
	ClientID    string `json:"client_id"`
	MTLSSubject string `json:"mtls_subject"`
}

type RevokeClientRequest struct {
	ClientID string `json:"client_id"`
	Reason   string `json:"reason,omitempty"`
}

type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
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
	Status                string    `json:"status"`
	Store                 string    `json:"store"`
	StoreBackend          string    `json:"store_backend,omitempty"`
	RateLimiter           string    `json:"rate_limiter"`
	RateLimitBackend      string    `json:"rate_limit_backend,omitempty"`
	MaxEnvelopesPerSecret int       `json:"max_envelopes_per_secret"`
	ClientRateLimitPerSec int       `json:"client_rate_limit_per_sec"`
	GlobalRateLimitPerSec int       `json:"global_rate_limit_per_sec"`
	IPRateLimitPerSec     int       `json:"ip_rate_limit_per_sec"`
	Build                 BuildInfo `json:"build"`
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
