// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

//go:build !postgres

package store

import (
	"context"
	"errors"

	"custodia/internal/model"
)

var ErrPostgresStoreNotWired = errors.New("postgres store is not wired in the standard-library bootstrap; use migrations/postgres/001_init.sql as the schema contract")

type PostgresStore struct{}

func NewPostgresStore(context.Context, string) (*PostgresStore, error) {
	return nil, ErrPostgresStoreNotWired
}
func (s *PostgresStore) Close()                       {}
func (s *PostgresStore) Health(context.Context) error { return ErrPostgresStoreNotWired }
func (s *PostgresStore) CreateClient(context.Context, model.Client) error {
	return ErrPostgresStoreNotWired
}
func (s *PostgresStore) GetActiveClientBySubject(context.Context, string) (model.Client, error) {
	return model.Client{}, ErrPostgresStoreNotWired
}
func (s *PostgresStore) ListClients(context.Context) ([]model.Client, error) {
	return nil, ErrPostgresStoreNotWired
}
func (s *PostgresStore) GetClient(context.Context, string) (model.Client, error) {
	return model.Client{}, ErrPostgresStoreNotWired
}
func (s *PostgresStore) ListSecretVersions(context.Context, string, string) ([]model.SecretVersionMetadata, error) {
	return nil, ErrPostgresStoreNotWired
}
func (s *PostgresStore) ListSecretAccess(context.Context, string, string) ([]model.SecretAccessMetadata, error) {
	return nil, ErrPostgresStoreNotWired
}
func (s *PostgresStore) RevokeClient(context.Context, string) error { return ErrPostgresStoreNotWired }
func (s *PostgresStore) CreateSecret(context.Context, string, model.CreateSecretRequest) (model.SecretVersionRef, error) {
	return model.SecretVersionRef{}, ErrPostgresStoreNotWired
}
func (s *PostgresStore) ListSecrets(context.Context, string) ([]model.SecretMetadata, error) {
	return nil, ErrPostgresStoreNotWired
}
func (s *PostgresStore) ResolveSecretIDByKey(context.Context, string, string, string, model.Permission) (string, error) {
	return "", ErrPostgresStoreNotWired
}
func (s *PostgresStore) GetSecret(context.Context, string, string) (model.SecretReadResponse, error) {
	return model.SecretReadResponse{}, ErrPostgresStoreNotWired
}
func (s *PostgresStore) DeleteSecret(context.Context, string, string, bool) error {
	return ErrPostgresStoreNotWired
}
func (s *PostgresStore) ShareSecret(context.Context, string, string, model.ShareSecretRequest) error {
	return ErrPostgresStoreNotWired
}
func (s *PostgresStore) RequestAccessGrant(context.Context, string, string, model.AccessGrantRequest) (model.AccessGrantRef, error) {
	return model.AccessGrantRef{}, ErrPostgresStoreNotWired
}
func (s *PostgresStore) ListAccessGrantRequests(context.Context, string) ([]model.AccessGrantMetadata, error) {
	return nil, ErrPostgresStoreNotWired
}
func (s *PostgresStore) ActivateAccessGrant(context.Context, string, string, string, model.ActivateAccessRequest) error {
	return ErrPostgresStoreNotWired
}
func (s *PostgresStore) RevokeAccess(context.Context, string, string, string) error {
	return ErrPostgresStoreNotWired
}
func (s *PostgresStore) CreateSecretVersion(context.Context, string, string, model.CreateSecretVersionRequest) (model.SecretVersionRef, error) {
	return model.SecretVersionRef{}, ErrPostgresStoreNotWired
}
func (s *PostgresStore) AppendAudit(context.Context, model.AuditEvent) error {
	return ErrPostgresStoreNotWired
}
func (s *PostgresStore) ListAuditEvents(context.Context, int) ([]model.AuditEvent, error) {
	return nil, ErrPostgresStoreNotWired
}
