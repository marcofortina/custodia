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
	pendingAccess   map[string]*memoryPendingAccess
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

type memoryPendingAccess struct {
	SecretID            string
	VersionID           string
	ClientID            string
	RequestedByClientID string
	Permissions         int
	ExpiresAt           *time.Time
	RequestedAt         time.Time
	ActivatedAt         *time.Time
	RevokedAt           *time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:         make(map[string]model.Client),
		subjectToClient: make(map[string]string),
		secrets:         make(map[string]*memorySecret),
		pendingAccess:   make(map[string]*memoryPendingAccess),
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
	for _, secret := range s.secrets {
		for _, version := range secret.Versions {
			if access, ok := version.Access[clientID]; ok && access.RevokedAt == nil {
				access.RevokedAt = &now
			}
		}
	}
	for _, pending := range s.pendingAccess {
		if (pending.ClientID == clientID || pending.RequestedByClientID == clientID) && pending.RevokedAt == nil {
			pending.RevokedAt = &now
		}
	}
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
	if !validFutureExpiry(req.ExpiresAt) {
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
			ExpiresAt:   cloneTimePtr(req.ExpiresAt),
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

func (s *MemoryStore) ListSecrets(_ context.Context, actorClientID string) ([]model.SecretMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.clientActiveLocked(actorClientID) {
		return nil, ErrForbidden
	}
	secrets := make([]model.SecretMetadata, 0)
	for _, secret := range s.secrets {
		if secret.DeletedAt != nil {
			continue
		}
		version := s.versionLocked(secret, "")
		if version == nil {
			continue
		}
		access, ok := version.Access[actorClientID]
		if !ok || !activeAccess(access) || !model.HasPermission(access.Permissions, model.PermissionRead) {
			continue
		}
		secrets = append(secrets, model.SecretMetadata{
			SecretID:    secret.SecretID,
			Name:        secret.Name,
			VersionID:   version.VersionID,
			Permissions: access.Permissions,
			CreatedAt:   secret.CreatedAt,
		})
	}
	return secrets, nil
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
	if !validFutureExpiry(req.ExpiresAt) {
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
		ExpiresAt:   cloneTimePtr(req.ExpiresAt),
	}
	return nil
}

func (s *MemoryStore) RequestAccessGrant(_ context.Context, actorClientID, secretID string, req model.AccessGrantRequest) (model.AccessGrantRef, error) {
	if strings.TrimSpace(req.TargetClientID) == "" || !model.ValidPermissionBits(req.Permissions) {
		return model.AccessGrantRef{}, ErrInvalidInput
	}
	if !validFutureExpiry(req.ExpiresAt) {
		return model.AccessGrantRef{}, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, ok := s.secrets[secretID]
	if !ok || secret.DeletedAt != nil {
		return model.AccessGrantRef{}, ErrNotFound
	}
	version := s.versionLocked(secret, req.VersionID)
	if version == nil {
		return model.AccessGrantRef{}, ErrNotFound
	}
	if !s.clientActiveLocked(actorClientID) || !s.clientActiveLocked(req.TargetClientID) {
		return model.AccessGrantRef{}, ErrInvalidInput
	}
	if existing, ok := version.Access[req.TargetClientID]; ok && activeAccess(existing) {
		return model.AccessGrantRef{}, ErrConflict
	}
	key := pendingAccessKey(secretID, version.VersionID, req.TargetClientID)
	if pending, ok := s.pendingAccess[key]; ok && activePendingAccess(pending) {
		return model.AccessGrantRef{}, ErrConflict
	}
	s.pendingAccess[key] = &memoryPendingAccess{
		SecretID:            secretID,
		VersionID:           version.VersionID,
		ClientID:            req.TargetClientID,
		RequestedByClientID: actorClientID,
		Permissions:         req.Permissions,
		ExpiresAt:           cloneTimePtr(req.ExpiresAt),
		RequestedAt:         time.Now().UTC(),
	}
	return model.AccessGrantRef{SecretID: secretID, VersionID: version.VersionID, ClientID: req.TargetClientID, Status: "pending"}, nil
}

func (s *MemoryStore) ActivateAccessGrant(_ context.Context, actorClientID, secretID, targetClientID string, req model.ActivateAccessRequest) error {
	if strings.TrimSpace(targetClientID) == "" || !model.ValidOpaqueBlob(req.Envelope) {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, ok := s.secrets[secretID]
	if !ok || secret.DeletedAt != nil {
		return ErrNotFound
	}
	pending, err := s.pendingAccessLocked(secretID, targetClientID)
	if err != nil {
		return err
	}
	version := s.versionLocked(secret, pending.VersionID)
	if version == nil {
		return ErrNotFound
	}
	actorAccess, ok := version.Access[actorClientID]
	if !ok || !activeAccess(actorAccess) || !model.HasPermission(actorAccess.Permissions, model.PermissionShare) {
		return ErrForbidden
	}
	if !s.clientActiveLocked(targetClientID) {
		return ErrInvalidInput
	}
	if existing, ok := version.Access[targetClientID]; ok && activeAccess(existing) {
		return ErrConflict
	}
	now := time.Now().UTC()
	version.Access[targetClientID] = &memoryAccess{
		ClientID:    targetClientID,
		Envelope:    req.Envelope,
		Permissions: pending.Permissions,
		GrantedAt:   now,
		ExpiresAt:   cloneTimePtr(pending.ExpiresAt),
	}
	pending.ActivatedAt = &now
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
	for _, pending := range s.pendingAccess {
		if pending.SecretID == secretID && pending.ClientID == targetClientID && activePendingAccess(pending) {
			pending.RevokedAt = &now
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
	if !validFutureExpiry(req.ExpiresAt) {
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
	s.retireActiveVersionsLocked(secret, now)
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
			ExpiresAt:   cloneTimePtr(req.ExpiresAt),
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

func (s *MemoryStore) ListAuditEvents(_ context.Context, limit int) ([]model.AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.auditEvents) {
		limit = len(s.auditEvents)
	}
	start := len(s.auditEvents) - limit
	events := make([]model.AuditEvent, 0, limit)
	for _, event := range s.auditEvents[start:] {
		events = append(events, cloneAuditEvent(event))
	}
	return events, nil
}

func (s *MemoryStore) AuditEvents() []model.AuditEvent {
	events, _ := s.ListAuditEvents(context.Background(), 0)
	return events
}

func (s *MemoryStore) visibleSecretLocked(actorClientID, secretID string, permission model.Permission) (*memorySecret, *memoryVersion, *memoryAccess, error) {
	if !s.clientActiveLocked(actorClientID) {
		return nil, nil, nil, ErrForbidden
	}
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

func (s *MemoryStore) retireActiveVersionsLocked(secret *memorySecret, retiredAt time.Time) {
	if secret == nil {
		return
	}
	retiredVersionIDs := make(map[string]bool)
	for _, version := range secret.Versions {
		if version.RevokedAt == nil {
			version.RevokedAt = &retiredAt
			retiredVersionIDs[version.VersionID] = true
		}
	}
	for _, pending := range s.pendingAccess {
		if pending.SecretID == secret.SecretID && retiredVersionIDs[pending.VersionID] && activePendingAccess(pending) {
			pending.RevokedAt = &retiredAt
		}
	}
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

func (s *MemoryStore) pendingAccessLocked(secretID, targetClientID string) (*memoryPendingAccess, error) {
	var found *memoryPendingAccess
	for _, pending := range s.pendingAccess {
		if pending.SecretID != secretID || pending.ClientID != targetClientID || !activePendingAccess(pending) {
			continue
		}
		if found != nil {
			return nil, ErrConflict
		}
		found = pending
	}
	if found == nil {
		return nil, ErrNotFound
	}
	return found, nil
}

func pendingAccessKey(secretID, versionID, clientID string) string {
	return secretID + "\x00" + versionID + "\x00" + clientID
}

func activePendingAccess(pending *memoryPendingAccess) bool {
	return pending != nil && pending.ActivatedAt == nil && pending.RevokedAt == nil
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

func validFutureExpiry(expiresAt *time.Time) bool {
	return expiresAt == nil || expiresAt.After(time.Now().UTC())
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := value.UTC()
	return &copyValue
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

func cloneAuditEvent(event model.AuditEvent) model.AuditEvent {
	event.Metadata = cloneRaw(event.Metadata)
	event.PreviousHash = cloneBytes(event.PreviousHash)
	event.EventHash = cloneBytes(event.EventHash)
	return event
}
