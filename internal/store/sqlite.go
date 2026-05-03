//go:build !sqlite

package store

import (
	"context"
	"errors"

	"custodia/internal/model"
)

var ErrSQLiteStoreNotWired = errors.New("sqlite store is not wired in this build; build with -tags sqlite and the SQLite driver dependency for Lite persistence")

type SQLiteStore struct{}

func NewSQLiteStore(context.Context, string) (*SQLiteStore, error) {
	return nil, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) Close()                       {}
func (s *SQLiteStore) Health(context.Context) error { return ErrSQLiteStoreNotWired }
func (s *SQLiteStore) CreateClient(context.Context, model.Client) error {
	return ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) GetActiveClientBySubject(context.Context, string) (model.Client, error) {
	return model.Client{}, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) ListClients(context.Context) ([]model.Client, error) {
	return nil, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) GetClient(context.Context, string) (model.Client, error) {
	return model.Client{}, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) RevokeClient(context.Context, string) error { return ErrSQLiteStoreNotWired }
func (s *SQLiteStore) CreateSecret(context.Context, string, model.CreateSecretRequest) (model.SecretVersionRef, error) {
	return model.SecretVersionRef{}, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) ListSecrets(context.Context, string) ([]model.SecretMetadata, error) {
	return nil, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) GetSecret(context.Context, string, string) (model.SecretReadResponse, error) {
	return model.SecretReadResponse{}, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) ListSecretVersions(context.Context, string, string) ([]model.SecretVersionMetadata, error) {
	return nil, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) ListSecretAccess(context.Context, string, string) ([]model.SecretAccessMetadata, error) {
	return nil, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) DeleteSecret(context.Context, string, string) error {
	return ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) ShareSecret(context.Context, string, string, model.ShareSecretRequest) error {
	return ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) RequestAccessGrant(context.Context, string, string, model.AccessGrantRequest) (model.AccessGrantRef, error) {
	return model.AccessGrantRef{}, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) ListAccessGrantRequests(context.Context, string) ([]model.AccessGrantMetadata, error) {
	return nil, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) ActivateAccessGrant(context.Context, string, string, string, model.ActivateAccessRequest) error {
	return ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) RevokeAccess(context.Context, string, string, string) error {
	return ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) CreateSecretVersion(context.Context, string, string, model.CreateSecretVersionRequest) (model.SecretVersionRef, error) {
	return model.SecretVersionRef{}, ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) AppendAudit(context.Context, model.AuditEvent) error {
	return ErrSQLiteStoreNotWired
}
func (s *SQLiteStore) ListAuditEvents(context.Context, int) ([]model.AuditEvent, error) {
	return nil, ErrSQLiteStoreNotWired
}
