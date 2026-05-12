// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"custodia/internal/audit"
	"custodia/internal/id"
	"custodia/internal/model"
)

// MemoryStore is the reference implementation of Custodia authorization semantics used by tests and lightweight runs.
// Persistence stores must preserve these versioning, pending grant and audit-chain rules.
type MemoryStore struct {
	mu               sync.RWMutex
	clients          map[string]model.Client
	subjectToClient  map[string]string
	clientPublicKeys map[string]model.ClientPublicKey
	secrets          map[string]*memorySecret
	visibleKeyspace  map[string]string
	pendingAccess    map[string]*memoryPendingAccess
	auditEvents      []model.AuditEvent
	lastAuditHash    []byte
}

type memorySecret struct {
	SecretID          string
	Namespace         string
	Key               string
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
		clients:          make(map[string]model.Client),
		subjectToClient:  make(map[string]string),
		clientPublicKeys: make(map[string]model.ClientPublicKey),
		secrets:          make(map[string]*memorySecret),
		visibleKeyspace:  make(map[string]string),
		pendingAccess:    make(map[string]*memoryPendingAccess),
	}
}

func (s *MemoryStore) Health(context.Context) error { return nil }

func (s *MemoryStore) CreateClient(_ context.Context, client model.Client) error {
	if !model.ValidClientID(client.ClientID) || !model.ValidMTLSSubject(client.MTLSSubject) {
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
	sort.Slice(clients, func(i, j int) bool { return clients[i].ClientID < clients[j].ClientID })
	return clients, nil
}

func (s *MemoryStore) GetClient(_ context.Context, clientID string) (model.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, ok := s.clients[clientID]
	if !ok {
		return model.Client{}, ErrNotFound
	}
	return client, nil
}

func (s *MemoryStore) UpsertClientPublicKey(_ context.Context, actorClientID string, req model.PublishClientPublicKeyRequest) (model.ClientPublicKey, error) {
	actorClientID = strings.TrimSpace(actorClientID)
	if !model.ValidClientID(actorClientID) || !model.ValidPublishClientPublicKeyRequest(req) {
		return model.ClientPublicKey{}, ErrInvalidInput
	}
	publicKey, _ := model.DecodeClientPublicKey(req.PublicKeyB64)
	fingerprint := strings.ToLower(strings.TrimSpace(req.Fingerprint))
	if fingerprint == "" {
		fingerprint = model.ClientPublicKeyFingerprint(publicKey)
	}
	published := model.ClientPublicKey{
		ClientID:     actorClientID,
		Scheme:       strings.TrimSpace(req.Scheme),
		PublicKeyB64: strings.TrimSpace(req.PublicKeyB64),
		Fingerprint:  fingerprint,
		PublishedAt:  time.Now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.clientActiveLocked(actorClientID) {
		return model.ClientPublicKey{}, ErrForbidden
	}
	s.clientPublicKeys[actorClientID] = published
	return published, nil
}

func (s *MemoryStore) GetClientPublicKey(_ context.Context, clientID string) (model.ClientPublicKey, error) {
	clientID = strings.TrimSpace(clientID)
	if !model.ValidClientID(clientID) {
		return model.ClientPublicKey{}, ErrInvalidInput
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, ok := s.clients[clientID]
	if !ok {
		return model.ClientPublicKey{}, ErrNotFound
	}
	if !client.IsActive || client.RevokedAt != nil {
		return model.ClientPublicKey{}, ErrForbidden
	}
	publicKey, ok := s.clientPublicKeys[clientID]
	if !ok {
		return model.ClientPublicKey{}, ErrNotFound
	}
	return publicKey, nil
}

// RevokeClient disables future server access and pending grants; already downloaded ciphertext still requires client-side rotation.
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
		changed := false
		for _, version := range secret.Versions {
			if access, ok := version.Access[clientID]; ok && access.RevokedAt == nil {
				access.RevokedAt = &now
				changed = true
			}
		}
		if changed {
			s.syncSecretVisibilityLocked(secret)
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
	if err := normalizeSecretIdentity(&req); err != nil {
		return model.SecretVersionRef{}, ErrInvalidInput
	}
	if err := validateOpaqueSecretPayload(req.Ciphertext, req.Envelopes); err != nil {
		return model.SecretVersionRef{}, err
	}
	if !model.ValidCryptoMetadata(req.CryptoMetadata) {
		return model.SecretVersionRef{}, ErrInvalidInput
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
		if existingSecretID, ok := s.activeVisibleSecretIDLocked(envelope.ClientID, req.Namespace, req.Key); ok && existingSecretID != "" {
			return model.SecretVersionRef{}, ErrConflict
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
		Namespace:         req.Namespace,
		Key:               req.Key,
		CreatedByClientID: actorClientID,
		CreatedAt:         now,
		Versions:          []*memoryVersion{version},
	}
	s.syncSecretVisibilityLocked(s.secrets[secretID])
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
			SecretID:          secret.SecretID,
			Namespace:         secretNamespace(secret),
			Key:               secretKey(secret),
			VersionID:         version.VersionID,
			Permissions:       access.Permissions,
			CreatedAt:         secret.CreatedAt,
			CreatedByClientID: secret.CreatedByClientID,
			AccessExpiresAt:   cloneTimePtr(access.ExpiresAt),
		})
	}
	sort.Slice(secrets, func(i, j int) bool {
		if secrets[i].CreatedAt.Equal(secrets[j].CreatedAt) {
			return secrets[i].SecretID < secrets[j].SecretID
		}
		return secrets[i].CreatedAt.After(secrets[j].CreatedAt)
	})
	return secrets, nil
}

func (s *MemoryStore) ResolveSecretIDByKey(_ context.Context, actorClientID, namespace, key string, permission model.Permission) (string, error) {
	namespace = model.NormalizeSecretNamespace(namespace)
	key = model.NormalizeSecretKey(key)
	if !model.ValidSecretNamespace(namespace) || !model.ValidSecretKey(key) {
		return "", ErrInvalidInput
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	secretID, ok := s.activeVisibleSecretIDLocked(actorClientID, namespace, key)
	if !ok {
		return "", ErrNotFound
	}
	if _, _, _, err := s.visibleSecretLocked(actorClientID, secretID, permission); err != nil {
		return "", err
	}
	return secretID, nil
}

func (s *MemoryStore) GetSecret(_ context.Context, actorClientID, secretID string) (model.SecretReadResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	secret, version, access, err := s.visibleSecretLocked(actorClientID, secretID, model.PermissionRead)
	if err != nil {
		return model.SecretReadResponse{}, err
	}
	return model.SecretReadResponse{
		SecretID:        secret.SecretID,
		Namespace:       secretNamespace(secret),
		Key:             secretKey(secret),
		VersionID:       version.VersionID,
		Ciphertext:      version.Ciphertext,
		CryptoMetadata:  cloneRaw(version.CryptoMetadata),
		Envelope:        access.Envelope,
		Permissions:     access.Permissions,
		GrantedAt:       access.GrantedAt,
		AccessExpiresAt: cloneTimePtr(access.ExpiresAt),
	}, nil
}

func (s *MemoryStore) ListSecretVersions(_ context.Context, actorClientID, secretID string) ([]model.SecretVersionMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	secret, _, _, err := s.visibleSecretLocked(actorClientID, secretID, model.PermissionRead)
	if err != nil {
		return nil, err
	}
	versions := make([]model.SecretVersionMetadata, 0, len(secret.Versions))
	for i := len(secret.Versions) - 1; i >= 0; i-- {
		version := secret.Versions[i]
		versions = append(versions, model.SecretVersionMetadata{
			SecretID:          secret.SecretID,
			VersionID:         version.VersionID,
			CreatedAt:         version.CreatedAt,
			CreatedByClientID: version.CreatedByClientID,
			RevokedAt:         cloneTimePtr(version.RevokedAt),
		})
	}
	return versions, nil
}

func (s *MemoryStore) ListSecretAccess(_ context.Context, actorClientID, secretID string) ([]model.SecretAccessMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	secret, version, _, err := s.visibleSecretLocked(actorClientID, secretID, model.PermissionShare)
	if err != nil {
		return nil, err
	}
	accesses := make([]model.SecretAccessMetadata, 0, len(version.Access))
	for _, access := range version.Access {
		if !activeAccess(access) {
			continue
		}
		accesses = append(accesses, model.SecretAccessMetadata{
			SecretID:    secret.SecretID,
			VersionID:   version.VersionID,
			ClientID:    access.ClientID,
			Permissions: access.Permissions,
			GrantedAt:   access.GrantedAt,
			ExpiresAt:   cloneTimePtr(access.ExpiresAt),
		})
	}
	sort.Slice(accesses, func(i, j int) bool { return accesses[i].ClientID < accesses[j].ClientID })
	return accesses, nil
}

func (s *MemoryStore) DeleteSecret(_ context.Context, actorClientID, secretID string, cascade bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, version, err := s.visibleSecretForDeleteLocked(actorClientID, secretID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if secret.CreatedByClientID != actorClientID {
		revoked := false
		for _, version := range secret.Versions {
			if access, ok := version.Access[actorClientID]; ok && activeAccess(access) {
				access.RevokedAt = &now
				revoked = true
			}
		}
		for _, pending := range s.pendingAccess {
			if pending.SecretID == secretID && pending.ClientID == actorClientID && activePendingAccess(pending) {
				pending.RevokedAt = &now
				revoked = true
			}
		}
		if !revoked {
			return ErrNotFound
		}
		s.syncSecretVisibilityLocked(secret)
		return nil
	}
	if !cascade && activeSharedAccessCount(version, actorClientID) > 0 {
		return ErrConflict
	}
	secret.DeletedAt = &now
	for _, version := range secret.Versions {
		for _, access := range version.Access {
			if access.RevokedAt == nil {
				access.RevokedAt = &now
			}
		}
	}
	for _, pending := range s.pendingAccess {
		if pending.SecretID == secretID && pending.RevokedAt == nil {
			pending.RevokedAt = &now
		}
	}
	s.syncSecretVisibilityLocked(secret)
	return nil
}

func (s *MemoryStore) ShareSecret(_ context.Context, actorClientID, secretID string, req model.ShareSecretRequest) error {
	if !model.ValidClientID(req.TargetClientID) || !model.ValidOptionalUUIDID(req.VersionID) || !model.ValidOpaqueBlob(req.Envelope) {
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
	if existingSecretID, ok := s.activeVisibleSecretIDLocked(req.TargetClientID, secretNamespace(secret), secretKey(secret)); ok && existingSecretID != secret.SecretID {
		return ErrConflict
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
	s.syncSecretVisibilityLocked(secret)
	return nil
}

func (s *MemoryStore) RequestAccessGrant(_ context.Context, actorClientID, secretID string, req model.AccessGrantRequest) (model.AccessGrantRef, error) {
	if !model.ValidClientID(req.TargetClientID) || !model.ValidOptionalUUIDID(req.VersionID) || !model.ValidPermissionBits(req.Permissions) {
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
	if existingSecretID, ok := s.activeVisibleSecretIDLocked(req.TargetClientID, secretNamespace(secret), secretKey(secret)); ok && existingSecretID != secret.SecretID {
		return model.AccessGrantRef{}, ErrConflict
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

func (s *MemoryStore) ListAccessGrantRequests(_ context.Context, secretID string) ([]model.AccessGrantMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	requests := make([]model.AccessGrantMetadata, 0)
	for _, pending := range s.pendingAccess {
		if secretID != "" && pending.SecretID != secretID {
			continue
		}
		status := "pending"
		if pending.ActivatedAt != nil {
			status = "activated"
		} else if pending.RevokedAt != nil {
			status = "revoked"
		} else if pending.ExpiresAt != nil && !pending.ExpiresAt.After(time.Now().UTC()) {
			status = "expired"
		}
		secret := s.secrets[pending.SecretID]
		metadata := model.AccessGrantMetadata{
			SecretID:            pending.SecretID,
			VersionID:           pending.VersionID,
			ClientID:            pending.ClientID,
			RequestedByClientID: pending.RequestedByClientID,
			Permissions:         pending.Permissions,
			RequestedAt:         pending.RequestedAt,
			ExpiresAt:           cloneTimePtr(pending.ExpiresAt),
			Status:              status,
		}
		if secret != nil {
			metadata.Namespace = secret.Namespace
			metadata.Key = secret.Key
		}
		requests = append(requests, metadata)
	}
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].RequestedAt.Equal(requests[j].RequestedAt) {
			if requests[i].SecretID == requests[j].SecretID {
				return requests[i].ClientID < requests[j].ClientID
			}
			return requests[i].SecretID < requests[j].SecretID
		}
		return requests[i].RequestedAt.After(requests[j].RequestedAt)
	})
	return requests, nil
}

func (s *MemoryStore) ActivateAccessGrant(_ context.Context, actorClientID, secretID, targetClientID string, req model.ActivateAccessRequest) error {
	if !model.ValidClientID(targetClientID) || !model.ValidOpaqueBlob(req.Envelope) {
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
	if existingSecretID, ok := s.activeVisibleSecretIDLocked(targetClientID, secretNamespace(secret), secretKey(secret)); ok && existingSecretID != secret.SecretID {
		return ErrConflict
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
	s.syncSecretVisibilityLocked(secret)
	return nil
}

func (s *MemoryStore) RevokeAccess(_ context.Context, actorClientID, secretID, targetClientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, _, err := s.visibleSecretForDeleteLocked(actorClientID, secretID)
	if err != nil {
		return err
	}
	if secret.CreatedByClientID != actorClientID || targetClientID == actorClientID {
		return ErrForbidden
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
	s.syncSecretVisibilityLocked(secret)
	return nil
}

func (s *MemoryStore) CreateSecretVersion(_ context.Context, actorClientID, secretID string, req model.CreateSecretVersionRequest) (model.SecretVersionRef, error) {
	if err := validateOpaqueSecretPayload(req.Ciphertext, req.Envelopes); err != nil {
		return model.SecretVersionRef{}, err
	}
	if !model.ValidCryptoMetadata(req.CryptoMetadata) {
		return model.SecretVersionRef{}, ErrInvalidInput
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
		if existingSecretID, ok := s.activeVisibleSecretIDLocked(envelope.ClientID, secretNamespace(secret), secretKey(secret)); ok && existingSecretID != secret.SecretID {
			return model.SecretVersionRef{}, ErrConflict
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
	s.syncSecretVisibilityLocked(secret)
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

func (s *MemoryStore) visibleSecretForDeleteLocked(actorClientID, secretID string) (*memorySecret, *memoryVersion, error) {
	if !s.clientActiveLocked(actorClientID) {
		return nil, nil, ErrForbidden
	}
	secret, ok := s.secrets[secretID]
	if !ok || secret.DeletedAt != nil {
		return nil, nil, ErrNotFound
	}
	version := s.versionLocked(secret, "")
	if version == nil {
		return nil, nil, ErrNotFound
	}
	access, ok := version.Access[actorClientID]
	if !ok || !activeAccess(access) {
		return nil, nil, ErrForbidden
	}
	return secret, version, nil
}

func activeSharedAccessCount(version *memoryVersion, ownerClientID string) int {
	if version == nil {
		return 0
	}
	count := 0
	for clientID, access := range version.Access {
		if clientID != ownerClientID && activeAccess(access) {
			count++
		}
	}
	return count
}

func normalizeSecretIdentity(req *model.CreateSecretRequest) error {
	req.Namespace = model.NormalizeSecretNamespace(req.Namespace)
	if !model.ValidSecretNamespace(req.Namespace) {
		return ErrInvalidInput
	}
	req.Key = model.NormalizeSecretKey(req.Key)
	if !model.ValidSecretKey(req.Key) {
		return ErrInvalidInput
	}
	return nil
}

func (s *MemoryStore) activeVisibleSecretIDLocked(clientID, namespace, key string) (string, bool) {
	secretID, ok := s.visibleKeyspace[visibleKeyspaceKey(clientID, namespace, key)]
	if !ok {
		return "", false
	}
	secret, ok := s.secrets[secretID]
	if !ok || secret.DeletedAt != nil {
		delete(s.visibleKeyspace, visibleKeyspaceKey(clientID, namespace, key))
		return "", false
	}
	version := s.versionLocked(secret, "")
	if version == nil {
		delete(s.visibleKeyspace, visibleKeyspaceKey(clientID, namespace, key))
		return "", false
	}
	access, ok := version.Access[clientID]
	if !ok || !activeAccess(access) {
		delete(s.visibleKeyspace, visibleKeyspaceKey(clientID, namespace, key))
		return "", false
	}
	return secretID, true
}

func (s *MemoryStore) syncSecretVisibilityLocked(secret *memorySecret) {
	if secret == nil {
		return
	}
	if s.visibleKeyspace == nil {
		s.visibleKeyspace = make(map[string]string)
	}
	for key, secretID := range s.visibleKeyspace {
		if secretID == secret.SecretID {
			delete(s.visibleKeyspace, key)
		}
	}
	if secret.DeletedAt != nil {
		return
	}
	version := s.versionLocked(secret, "")
	if version == nil {
		return
	}
	namespace := secretNamespace(secret)
	key := secretKey(secret)
	for clientID, access := range version.Access {
		if activeAccess(access) {
			s.visibleKeyspace[visibleKeyspaceKey(clientID, namespace, key)] = secret.SecretID
		}
	}
}

func (s *MemoryStore) rebuildVisibleKeyspaceLocked() {
	s.visibleKeyspace = make(map[string]string)
	for _, secret := range s.secrets {
		s.syncSecretVisibilityLocked(secret)
	}
}

func visibleKeyspaceKey(clientID, namespace, key string) string {
	return clientID + "\x00" + model.NormalizeSecretNamespace(namespace) + "\x00" + model.NormalizeSecretKey(key)
}

func secretNamespace(secret *memorySecret) string {
	if secret == nil {
		return model.DefaultSecretNamespace
	}
	return model.NormalizeSecretNamespace(secret.Namespace)
}

func secretKey(secret *memorySecret) string {
	if secret == nil {
		return ""
	}
	return model.NormalizeSecretKey(secret.Key)
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
		if !model.ValidClientID(clientID) || seen[clientID] || !model.ValidOpaqueBlob(envelope.Envelope) {
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
	if pending == nil || pending.ActivatedAt != nil || pending.RevokedAt != nil {
		return false
	}
	return pending.ExpiresAt == nil || pending.ExpiresAt.After(time.Now().UTC())
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
