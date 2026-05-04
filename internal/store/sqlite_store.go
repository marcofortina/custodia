// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

//go:build sqlite

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"custodia/internal/model"

	_ "modernc.org/sqlite"
)

// SQLiteStore is the Lite-profile persistence adapter.
//
// It persists the same logical model as the in-memory store as one JSON state
// document while SQLite provides local durability, WAL and file locking for
// single-node deployments. It is not intended for HA/FULL deployments.
type SQLiteStore struct {
	mu     sync.Mutex
	db     *sql.DB
	memory *MemoryStore
}

type sqliteSnapshot struct {
	Clients         map[string]model.Client         `json:"clients"`
	SubjectToClient map[string]string               `json:"subject_to_client"`
	Secrets         map[string]*memorySecret        `json:"secrets"`
	PendingAccess   map[string]*memoryPendingAccess `json:"pending_access"`
	AuditEvents     []model.AuditEvent              `json:"audit_events"`
	LastAuditHash   []byte                          `json:"last_audit_hash"`
}

func NewSQLiteStore(ctx context.Context, databaseURL string) (*SQLiteStore, error) {
	dsn, err := sqliteDSN(databaseURL)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	store := &SQLiteStore{db: db, memory: NewMemoryStore()}
	if err := store.bootstrap(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.load(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func sqliteDSN(databaseURL string) (string, error) {
	value := strings.TrimSpace(databaseURL)
	if value == "" {
		return "", ErrInvalidInput
	}
	if strings.HasPrefix(value, "file:") {
		value = strings.TrimPrefix(value, "file:")
	}
	if value == "" {
		return "", ErrInvalidInput
	}
	if value != ":memory:" {
		dir := filepath.Dir(value)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return "", err
			}
		}
	}
	return value, nil
}

func (s *SQLiteStore) bootstrap(ctx context.Context) error {
	statements := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		`CREATE TABLE IF NOT EXISTS custodia_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			payload TEXT NOT NULL CHECK (length(payload) > 0),
			updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
		)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return s.db.PingContext(ctx)
}

func (s *SQLiteStore) load(ctx context.Context) error {
	var payload string
	err := s.db.QueryRowContext(ctx, "SELECT payload FROM custodia_state WHERE id = 1").Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var snapshot sqliteSnapshot
	if err := json.Unmarshal([]byte(payload), &snapshot); err != nil {
		return err
	}
	s.memory.mu.Lock()
	defer s.memory.mu.Unlock()
	s.memory.clients = ensureClientMap(snapshot.Clients)
	s.memory.subjectToClient = ensureStringMap(snapshot.SubjectToClient)
	s.memory.secrets = ensureSecretMap(snapshot.Secrets)
	s.memory.pendingAccess = ensurePendingMap(snapshot.PendingAccess)
	s.memory.auditEvents = snapshot.AuditEvents
	s.memory.lastAuditHash = snapshot.LastAuditHash
	return nil
}

func ensureClientMap(values map[string]model.Client) map[string]model.Client {
	if values == nil {
		return map[string]model.Client{}
	}
	return values
}
func ensureStringMap(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}
	return values
}
func ensureSecretMap(values map[string]*memorySecret) map[string]*memorySecret {
	if values == nil {
		return map[string]*memorySecret{}
	}
	return values
}
func ensurePendingMap(values map[string]*memoryPendingAccess) map[string]*memoryPendingAccess {
	if values == nil {
		return map[string]*memoryPendingAccess{}
	}
	return values
}

func (s *SQLiteStore) save(ctx context.Context) error {
	s.memory.mu.RLock()
	snapshot := sqliteSnapshot{
		Clients:         s.memory.clients,
		SubjectToClient: s.memory.subjectToClient,
		Secrets:         s.memory.secrets,
		PendingAccess:   s.memory.pendingAccess,
		AuditEvents:     s.memory.auditEvents,
		LastAuditHash:   s.memory.lastAuditHash,
	}
	payload, err := json.Marshal(snapshot)
	s.memory.mu.RUnlock()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO custodia_state (id, payload, updated_at)
		VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at`, string(payload), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// mutate serializes logical state changes and persists the full snapshot after
// the in-memory operation succeeds. This keeps Lite semantics aligned with the
// memory store while avoiding partial writes.
func (s *SQLiteStore) mutate(ctx context.Context, fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(); err != nil {
		return err
	}
	return s.save(ctx)
}

func (s *SQLiteStore) Close() {
	if s != nil && s.db != nil {
		_ = s.db.Close()
	}
}
func (s *SQLiteStore) Health(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *SQLiteStore) CreateClient(ctx context.Context, client model.Client) error {
	return s.mutate(ctx, func() error { return s.memory.CreateClient(ctx, client) })
}
func (s *SQLiteStore) GetActiveClientBySubject(ctx context.Context, mtlsSubject string) (model.Client, error) {
	return s.memory.GetActiveClientBySubject(ctx, mtlsSubject)
}
func (s *SQLiteStore) ListClients(ctx context.Context) ([]model.Client, error) {
	return s.memory.ListClients(ctx)
}
func (s *SQLiteStore) GetClient(ctx context.Context, clientID string) (model.Client, error) {
	return s.memory.GetClient(ctx, clientID)
}
func (s *SQLiteStore) RevokeClient(ctx context.Context, clientID string) error {
	return s.mutate(ctx, func() error { return s.memory.RevokeClient(ctx, clientID) })
}
func (s *SQLiteStore) CreateSecret(ctx context.Context, actorClientID string, req model.CreateSecretRequest) (model.SecretVersionRef, error) {
	var ref model.SecretVersionRef
	err := s.mutate(ctx, func() error { var err error; ref, err = s.memory.CreateSecret(ctx, actorClientID, req); return err })
	return ref, err
}
func (s *SQLiteStore) ListSecrets(ctx context.Context, actorClientID string) ([]model.SecretMetadata, error) {
	return s.memory.ListSecrets(ctx, actorClientID)
}
func (s *SQLiteStore) GetSecret(ctx context.Context, actorClientID, secretID string) (model.SecretReadResponse, error) {
	return s.memory.GetSecret(ctx, actorClientID, secretID)
}
func (s *SQLiteStore) ListSecretVersions(ctx context.Context, actorClientID, secretID string) ([]model.SecretVersionMetadata, error) {
	return s.memory.ListSecretVersions(ctx, actorClientID, secretID)
}
func (s *SQLiteStore) ListSecretAccess(ctx context.Context, actorClientID, secretID string) ([]model.SecretAccessMetadata, error) {
	return s.memory.ListSecretAccess(ctx, actorClientID, secretID)
}
func (s *SQLiteStore) DeleteSecret(ctx context.Context, actorClientID, secretID string) error {
	return s.mutate(ctx, func() error { return s.memory.DeleteSecret(ctx, actorClientID, secretID) })
}
func (s *SQLiteStore) ShareSecret(ctx context.Context, actorClientID, secretID string, req model.ShareSecretRequest) error {
	return s.mutate(ctx, func() error { return s.memory.ShareSecret(ctx, actorClientID, secretID, req) })
}
func (s *SQLiteStore) RequestAccessGrant(ctx context.Context, actorClientID, secretID string, req model.AccessGrantRequest) (model.AccessGrantRef, error) {
	var ref model.AccessGrantRef
	err := s.mutate(ctx, func() error {
		var err error
		ref, err = s.memory.RequestAccessGrant(ctx, actorClientID, secretID, req)
		return err
	})
	return ref, err
}
func (s *SQLiteStore) ListAccessGrantRequests(ctx context.Context, secretID string) ([]model.AccessGrantMetadata, error) {
	return s.memory.ListAccessGrantRequests(ctx, secretID)
}
func (s *SQLiteStore) ActivateAccessGrant(ctx context.Context, actorClientID, secretID, targetClientID string, req model.ActivateAccessRequest) error {
	return s.mutate(ctx, func() error { return s.memory.ActivateAccessGrant(ctx, actorClientID, secretID, targetClientID, req) })
}
func (s *SQLiteStore) RevokeAccess(ctx context.Context, actorClientID, secretID, targetClientID string) error {
	return s.mutate(ctx, func() error { return s.memory.RevokeAccess(ctx, actorClientID, secretID, targetClientID) })
}
func (s *SQLiteStore) CreateSecretVersion(ctx context.Context, actorClientID, secretID string, req model.CreateSecretVersionRequest) (model.SecretVersionRef, error) {
	var ref model.SecretVersionRef
	err := s.mutate(ctx, func() error {
		var err error
		ref, err = s.memory.CreateSecretVersion(ctx, actorClientID, secretID, req)
		return err
	})
	return ref, err
}
func (s *SQLiteStore) AppendAudit(ctx context.Context, event model.AuditEvent) error {
	return s.mutate(ctx, func() error { return s.memory.AppendAudit(ctx, event) })
}
func (s *SQLiteStore) ListAuditEvents(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	return s.memory.ListAuditEvents(ctx, limit)
}

func (s *SQLiteStore) String() string { return fmt.Sprintf("sqlite:%p", s) }
