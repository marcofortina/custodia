package store

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"custodia/internal/audit"
	"custodia/internal/id"
	"custodia/internal/model"
)

type MemoryStore struct {
	mu              sync.RWMutex
	clients         map[string]model.Client
	subjectToClient map[string]string
	secrets         map[string]*memorySecret
	auditEvents     []model.AuditEvent
	lastAuditHash   []byte
}

type memorySecret struct {
	SecretID          string
	Name              string
	CreatedByClientID string
	CreatedAt         time.Time
	DeletedAt         *time.Time
	Versions          []*memoryVersion
}

type memoryVersion struct {
	VersionID         string
	Ciphertext        string
	CryptoMetadata    json.RawMessage
	CreatedAt         time.Time
	CreatedByClientID string
	RevokedAt         *time.Time
	Access            map[string]*memoryAccess
}

type memoryAccess struct {
	ClientID    string
	Envelope    string
	Permissions int
	GrantedAt   time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:         make(map[string]model.Client),
		subjectToClient: make(map[string]string),
		secrets:         make(map[string]*memorySecret),
	}
}

func (s *MemoryStore) Health(context.Context) error { return nil }

func (s *MemoryStore) CreateClient(_ context.Context, client model.Client) error {
	if strings.TrimSpace(client.ClientID) == "" || strings.TrimSpace(client.MTLSSubject) == "" {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[client.ClientID]; exists {
		return ErrConflict
	}
	if _, exists := s.subjectToClient[client.MTLSSubject]; exists {
		return ErrConflict
	}
	if client.CreatedAt.IsZero() {
		client.CreatedAt = time.Now().UTC()
	}
	client.IsActive = true
	s.clients[client.ClientID] = client
	s.subjectToClient[client.MTLSSubject] = client.ClientID
	return nil
}

func (s *MemoryStore) GetActiveClientBySubject(_ context.Context, mtlsSubject string) (model.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clientID, ok := s.subjectToClient[mtlsSubject]
	if !ok {
		return model.Client{}, ErrNotFound
	}
	client := s.clients[clientID]
	if !client.IsActive || client.RevokedAt != nil {
		return model.Client{}, ErrForbidden
	}
	return client, nil
}

func (s *MemoryStore) ListClients(context.Context) ([]model.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clients := make([]model.Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	return clients, nil
}

func (s *MemoryStore) RevokeClient(_ context.Context, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.clients[clientID]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	client.IsActive = false
	client.RevokedAt = &now
	s.clients[clientID] = client
	return nil
}

func (s *MemoryStore) CreateSecret(_ context.Context, actorClientID string, req model.CreateSecretRequest) (model.SecretVersionRef, error) {
	if strings.TrimSpace(req.Name) == "" {
		return model.SecretVersionRef{}, ErrInvalidInput
	}
	if err := validateOpaqueSecretPayload(req.Ciphertext, req.Envelopes); err != nil {
		return model.SecretVersionRef{}, err
	}
	if !model.ValidPermissionBits(req.Permissions) {
		return model.SecretVersionRef{}, ErrInvalidInput
	}
	if !containsEnvelopeFor(req.Envelopes, actorClientID) {
		return model.SecretVersionRef{}, ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.clientActiveLocked(actorClientID) {
		return model.SecretVersionRef{}, ErrForbidden
	}
	for _, envelope := range req.Envelopes {
		if !s.clientActiveLocked(envelope.ClientID) {
			return model.SecretVersionRef{}, ErrInvalidInput
		}
	}
	secretID := id.New()
	versionID := id.New()
	now := time.Now().UTC()
	version := &memoryVersion{
		VersionID:         versionID,
		Ciphertext:        req.Ciphertext,
		CryptoMetadata:    cloneRaw(req.CryptoMetadata),
		CreatedAt:         now,
		CreatedByClientID: actorClientID,
		Access:            make(map[string]*memoryAccess),
	}
	for _, envelope := range req.Envelopes {
		version.Access[envelope.ClientID] = &memoryAccess{
			ClientID:    envelope.ClientID,
			Envelope:    envelope.Envelope,
			Permissions: req.Permissions,
			GrantedAt:   now,
		}
	}
	s.secrets[secretID] = &memorySecret{
		SecretID:          secretID,
		Name:              req.Name,
		CreatedByClientID: actorClientID,
		CreatedAt:         now,
		Versions:          []*memoryVersion{version},
	}
	return model.SecretVersionRef{SecretID: secretID, VersionID: versionID}, nil
}

func (s *MemoryStore) GetSecret(_ context.Context, actorClientID, secretID string) (model.SecretReadResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	secret, version, access, err := s.visibleSecretLocked(actorClientID, secretID, model.PermissionRead)
	if err != nil {
		return model.SecretReadResponse{}, err
	}
	return model.SecretReadResponse{
		SecretID:       secret.SecretID,
		VersionID:      version.VersionID,
		Ciphertext:     version.Ciphertext,
		CryptoMetadata: cloneRaw(version.CryptoMetadata),
		Envelope:       access.Envelope,
		Permissions:    access.Permissions,
	}, nil
}

func (s *MemoryStore) DeleteSecret(_ context.Context, actorClientID, secretID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, _, _, err := s.visibleSecretLocked(actorClientID, secretID, model.PermissionWrite)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	secret.DeletedAt = &now
	return nil
}

func (s *MemoryStore) ShareSecret(_ context.Context, actorClientID, secretID string, req model.ShareSecretRequest) error {
	if strings.TrimSpace(req.TargetClientID) == "" || !model.ValidOpaqueBlob(req.Envelope) {
		return ErrInvalidInput
	}
	if !model.ValidPermissionBits(req.Permissions) {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, ok := s.secrets[secretID]
	if !ok || secret.DeletedAt != nil {
		return ErrNotFound
	}
	version := s.versionLocked(secret, req.VersionID)
	if version == nil {
		return ErrNotFound
	}
	actorAccess, ok := version.Access[actorClientID]
	if !ok || !activeAccess(actorAccess) || !model.HasPermission(actorAccess.Permissions, model.PermissionShare) {
		return ErrForbidden
	}
	if !s.clientActiveLocked(req.TargetClientID) {
		return ErrInvalidInput
	}
	if existing, ok := version.Access[req.TargetClientID]; ok && activeAccess(existing) {
		return ErrConflict
	}
	version.Access[req.TargetClientID] = &memoryAccess{
		ClientID:    req.TargetClientID,
		Envelope:    req.Envelope,
		Permissions: req.Permissions,
		GrantedAt:   time.Now().UTC(),
	}
	return nil
}

func (s *MemoryStore) RevokeAccess(_ context.Context, actorClientID, secretID, targetClientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, _, _, err := s.visibleSecretLocked(actorClientID, secretID, model.PermissionShare)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	revoked := false
	for _, version := range secret.Versions {
		if access, ok := version.Access[targetClientID]; ok && activeAccess(access) {
			access.RevokedAt = &now
			revoked = true
		}
	}
	if !revoked {
		return ErrNotFound
	}
	return nil
}

func (s *MemoryStore) CreateSecretVersion(_ context.Context, actorClientID, secretID string, req model.CreateSecretVersionRequest) (model.SecretVersionRef, error) {
	if err := validateOpaqueSecretPayload(req.Ciphertext, req.Envelopes); err != nil {
		return model.SecretVersionRef{}, err
	}
	if !model.ValidPermissionBits(req.Permissions) {
		return model.SecretVersionRef{}, ErrInvalidInput
	}
	if !containsEnvelopeFor(req.Envelopes, actorClientID) {
		return model.SecretVersionRef{}, ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, _, _, err := s.visibleSecretLocked(actorClientID, secretID, model.PermissionWrite)
	if err != nil {
		return model.SecretVersionRef{}, err
	}
	for _, envelope := range req.Envelopes {
		if !s.clientActiveLocked(envelope.ClientID) {
			return model.SecretVersionRef{}, ErrInvalidInput
		}
	}
	versionID := id.New()
	now := time.Now().UTC()
	version := &memoryVersion{
		VersionID:         versionID,
		Ciphertext:        req.Ciphertext,
		CryptoMetadata:    cloneRaw(req.CryptoMetadata),
		CreatedAt:         now,
		CreatedByClientID: actorClientID,
		Access:            make(map[string]*memoryAccess),
	}
	for _, envelope := range req.Envelopes {
		version.Access[envelope.ClientID] = &memoryAccess{
			ClientID:    envelope.ClientID,
			Envelope:    envelope.Envelope,
			Permissions: req.Permissions,
			GrantedAt:   now,
		}
	}
	secret.Versions = append(secret.Versions, version)
	return model.SecretVersionRef{SecretID: secretID, VersionID: versionID}, nil
}

func (s *MemoryStore) AppendAudit(_ context.Context, event model.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	event.PreviousHash = cloneBytes(s.lastAuditHash)
	event.EventHash = audit.ComputeHash(s.lastAuditHash, event)
	s.lastAuditHash = cloneBytes(event.EventHash)
	s.auditEvents = append(s.auditEvents, event)
	return nil
}

func (s *MemoryStore) AuditEvents() []model.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := make([]model.AuditEvent, len(s.auditEvents))
	copy(events, s.auditEvents)
	return events
}

func (s *MemoryStore) visibleSecretLocked(actorClientID, secretID string, permission model.Permission) (*memorySecret, *memoryVersion, *memoryAccess, error) {
	secret, ok := s.secrets[secretID]
	if !ok || secret.DeletedAt != nil {
		return nil, nil, nil, ErrNotFound
	}
	version := s.versionLocked(secret, "")
	if version == nil {
		return nil, nil, nil, ErrNotFound
	}
	access, ok := version.Access[actorClientID]
	if !ok || !activeAccess(access) || !model.HasPermission(access.Permissions, permission) {
		return nil, nil, nil, ErrForbidden
	}
	return secret, version, access, nil
}

func (s *MemoryStore) versionLocked(secret *memorySecret, versionID string) *memoryVersion {
	if secret == nil {
		return nil
	}
	if versionID != "" {
		for _, version := range secret.Versions {
			if version.VersionID == versionID && version.RevokedAt == nil {
				return version
			}
		}
		return nil
	}
	for i := len(secret.Versions) - 1; i >= 0; i-- {
		if secret.Versions[i].RevokedAt == nil {
			return secret.Versions[i]
		}
	}
	return nil
}

func (s *MemoryStore) clientActiveLocked(clientID string) bool {
	client, ok := s.clients[clientID]
	return ok && client.IsActive && client.RevokedAt == nil
}

func validateOpaqueSecretPayload(ciphertext string, envelopes []model.RecipientEnvelope) error {
	if !model.ValidOpaqueBlob(ciphertext) || len(envelopes) == 0 {
		return ErrInvalidInput
	}
	seen := make(map[string]bool, len(envelopes))
	for _, envelope := range envelopes {
		clientID := strings.TrimSpace(envelope.ClientID)
		if clientID == "" || seen[clientID] || !model.ValidOpaqueBlob(envelope.Envelope) {
			return ErrInvalidInput
		}
		seen[clientID] = true
	}
	return nil
}

func activeAccess(access *memoryAccess) bool {
	if access == nil || access.RevokedAt != nil {
		return false
	}
	return access.ExpiresAt == nil || access.ExpiresAt.After(time.Now().UTC())
}

func containsEnvelopeFor(envelopes []model.RecipientEnvelope, clientID string) bool {
	for _, envelope := range envelopes {
		if envelope.ClientID == clientID && strings.TrimSpace(envelope.Envelope) != "" {
			return true
		}
	}
	return false
}

func cloneRaw(value json.RawMessage) json.RawMessage {
	if value == nil {
		return nil
	}
	copyValue := make([]byte, len(value))
	copy(copyValue, value)
	return copyValue
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	copyValue := make([]byte, len(value))
	copy(copyValue, value)
	return copyValue
}
