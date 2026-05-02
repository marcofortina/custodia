//go:build postgres

package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"custodia/internal/audit"
	"custodia/internal/id"
	"custodia/internal/model"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, ErrInvalidInput
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &PostgresStore{pool: pool}, nil
}

func (s *PostgresStore) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

func (s *PostgresStore) Health(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *PostgresStore) CreateClient(ctx context.Context, client model.Client) error {
	if !model.ValidClientID(client.ClientID) || strings.TrimSpace(client.MTLSSubject) == "" {
		return ErrInvalidInput
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO clients (client_id, mtls_subject, is_active, created_at)
		VALUES ($1, $2, TRUE, COALESCE(NULLIF($3::timestamptz, '0001-01-01 00:00:00+00'::timestamptz), NOW()))`,
		client.ClientID, client.MTLSSubject, client.CreatedAt.UTC())
	return mapPostgresError(err)
}

func (s *PostgresStore) GetActiveClientBySubject(ctx context.Context, mtlsSubject string) (model.Client, error) {
	var client model.Client
	err := s.pool.QueryRow(ctx, `
		SELECT client_id, mtls_subject, is_active, created_at, revoked_at
		FROM clients
		WHERE mtls_subject = $1 AND is_active = TRUE AND revoked_at IS NULL`, mtlsSubject).
		Scan(&client.ClientID, &client.MTLSSubject, &client.IsActive, &client.CreatedAt, &client.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Client{}, ErrNotFound
	}
	return client, mapPostgresError(err)
}

func (s *PostgresStore) ListClients(ctx context.Context) ([]model.Client, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT client_id, mtls_subject, is_active, created_at, revoked_at
		FROM clients
		ORDER BY client_id`)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()
	clients := make([]model.Client, 0)
	for rows.Next() {
		var client model.Client
		if err := rows.Scan(&client.ClientID, &client.MTLSSubject, &client.IsActive, &client.CreatedAt, &client.RevokedAt); err != nil {
			return nil, mapPostgresError(err)
		}
		clients = append(clients, client)
	}
	return clients, mapPostgresError(rows.Err())
}

func (s *PostgresStore) GetClient(ctx context.Context, clientID string) (model.Client, error) {
	var client model.Client
	err := s.pool.QueryRow(ctx, `
		SELECT client_id, mtls_subject, is_active, created_at, revoked_at
		FROM clients
		WHERE client_id = $1`, clientID).
		Scan(&client.ClientID, &client.MTLSSubject, &client.IsActive, &client.CreatedAt, &client.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Client{}, ErrNotFound
	}
	return client, mapPostgresError(err)
}

func (s *PostgresStore) RevokeClient(ctx context.Context, clientID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackIgnored(ctx, tx)
	tag, err := tx.Exec(ctx, `
		UPDATE clients
		SET is_active = FALSE, revoked_at = COALESCE(revoked_at, NOW())
		WHERE client_id = $1`, clientID)
	if err != nil {
		return mapPostgresError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `
		UPDATE secret_access
		SET revoked_at = COALESCE(revoked_at, NOW())
		WHERE client_id = $1 AND revoked_at IS NULL`, clientID); err != nil {
		return mapPostgresError(err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE secret_access_requests
		SET revoked_at = COALESCE(revoked_at, NOW())
		WHERE (client_id = $1 OR requested_by_client_id = $1) AND activated_at IS NULL AND revoked_at IS NULL`, clientID); err != nil {
		return mapPostgresError(err)
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) CreateSecret(ctx context.Context, actorClientID string, req model.CreateSecretRequest) (model.SecretVersionRef, error) {
	if !model.ValidSecretName(req.Name) {
		return model.SecretVersionRef{}, ErrInvalidInput
	}
	if err := validateOpaqueSecretPayload(req.Ciphertext, req.Envelopes); err != nil {
		return model.SecretVersionRef{}, err
	}
	if !model.ValidCryptoMetadata(req.CryptoMetadata) {
		return model.SecretVersionRef{}, ErrInvalidInput
	}
	if !model.ValidPermissionBits(req.Permissions) || !validFutureExpiry(req.ExpiresAt) {
		return model.SecretVersionRef{}, ErrInvalidInput
	}
	if !containsEnvelopeFor(req.Envelopes, actorClientID) {
		return model.SecretVersionRef{}, ErrForbidden
	}
	ciphertext, err := decodeOpaqueBlob(req.Ciphertext)
	if err != nil {
		return model.SecretVersionRef{}, ErrInvalidInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.SecretVersionRef{}, err
	}
	defer rollbackIgnored(ctx, tx)
	if active, err := activeClientExists(ctx, tx, actorClientID); err != nil {
		return model.SecretVersionRef{}, err
	} else if !active {
		return model.SecretVersionRef{}, ErrForbidden
	}
	for _, envelope := range req.Envelopes {
		if active, err := activeClientExists(ctx, tx, envelope.ClientID); err != nil {
			return model.SecretVersionRef{}, err
		} else if !active {
			return model.SecretVersionRef{}, ErrInvalidInput
		}
	}
	var ref model.SecretVersionRef
	err = tx.QueryRow(ctx, `
		INSERT INTO secrets (name, created_by_client_id)
		VALUES ($1, $2)
		RETURNING secret_id::text`, req.Name, actorClientID).Scan(&ref.SecretID)
	if err != nil {
		return model.SecretVersionRef{}, mapPostgresError(err)
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO secret_versions (secret_id, ciphertext, crypto_metadata, created_by_client_id)
		VALUES ($1::uuid, $2, $3, $4)
		RETURNING version_id::text`, ref.SecretID, ciphertext, nullableJSON(req.CryptoMetadata), actorClientID).Scan(&ref.VersionID)
	if err != nil {
		return model.SecretVersionRef{}, mapPostgresError(err)
	}
	for _, envelope := range req.Envelopes {
		envelopeBytes, err := decodeOpaqueBlob(envelope.Envelope)
		if err != nil {
			return model.SecretVersionRef{}, ErrInvalidInput
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO secret_access (secret_id, version_id, client_id, envelope, permissions, expires_at)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)`,
			ref.SecretID, ref.VersionID, envelope.ClientID, envelopeBytes, req.Permissions, req.ExpiresAt); err != nil {
			return model.SecretVersionRef{}, mapPostgresError(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return model.SecretVersionRef{}, err
	}
	return ref, nil
}

func (s *PostgresStore) ListSecrets(ctx context.Context, actorClientID string) ([]model.SecretMetadata, error) {
	if active, err := activeClientExists(ctx, s.pool, actorClientID); err != nil {
		return nil, err
	} else if !active {
		return nil, ErrForbidden
	}
	rows, err := s.pool.Query(ctx, `
		SELECT s.secret_id::text, s.name, v.version_id::text, a.permissions, s.created_at
		FROM secrets s
		JOIN LATERAL (
			SELECT version_id, secret_id, created_at
			FROM secret_versions
			WHERE secret_id = s.secret_id AND revoked_at IS NULL
			ORDER BY created_at DESC
			LIMIT 1
		) v ON TRUE
		JOIN secret_access a ON a.secret_id = v.secret_id AND a.version_id = v.version_id AND a.client_id = $1
		WHERE s.deleted_at IS NULL
		  AND a.revoked_at IS NULL
		  AND (a.expires_at IS NULL OR a.expires_at > NOW())
		  AND (a.permissions & $2) = $2
		ORDER BY s.created_at DESC`, actorClientID, int(model.PermissionRead))
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()
	secrets := make([]model.SecretMetadata, 0)
	for rows.Next() {
		var secret model.SecretMetadata
		if err := rows.Scan(&secret.SecretID, &secret.Name, &secret.VersionID, &secret.Permissions, &secret.CreatedAt); err != nil {
			return nil, mapPostgresError(err)
		}
		secrets = append(secrets, secret)
	}
	return secrets, mapPostgresError(rows.Err())
}

func (s *PostgresStore) GetSecret(ctx context.Context, actorClientID, secretID string) (model.SecretReadResponse, error) {
	if _, _, err := visibleVersion(ctx, s.pool, actorClientID, secretID, "", model.PermissionRead); err != nil {
		return model.SecretReadResponse{}, err
	}
	var response model.SecretReadResponse
	var ciphertext []byte
	var envelope []byte
	var metadata []byte
	err := s.pool.QueryRow(ctx, `
		SELECT s.secret_id::text, v.version_id::text, v.ciphertext, v.crypto_metadata, a.envelope, a.permissions
		FROM secrets s
		JOIN LATERAL (
			SELECT * FROM secret_versions
			WHERE secret_id = s.secret_id AND revoked_at IS NULL
			ORDER BY created_at DESC
			LIMIT 1
		) v ON TRUE
		JOIN secret_access a ON a.secret_id = v.secret_id AND a.version_id = v.version_id AND a.client_id = $2
		WHERE s.secret_id = $1::uuid AND s.deleted_at IS NULL
		  AND a.revoked_at IS NULL
		  AND (a.expires_at IS NULL OR a.expires_at > NOW())
		  AND (a.permissions & $3) = $3`, secretID, actorClientID, int(model.PermissionRead)).
		Scan(&response.SecretID, &response.VersionID, &ciphertext, &metadata, &envelope, &response.Permissions)
	if err != nil {
		return model.SecretReadResponse{}, mapPostgresError(err)
	}
	response.Ciphertext = encodeOpaqueBlob(ciphertext)
	response.CryptoMetadata = cloneRaw(json.RawMessage(metadata))
	response.Envelope = encodeOpaqueBlob(envelope)
	return response, nil
}

func (s *PostgresStore) ListSecretVersions(ctx context.Context, actorClientID, secretID string) ([]model.SecretVersionMetadata, error) {
	if _, _, err := visibleVersion(ctx, s.pool, actorClientID, secretID, "", model.PermissionRead); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT secret_id::text, version_id::text, created_at, created_by_client_id, revoked_at
		FROM secret_versions
		WHERE secret_id = $1::uuid
		ORDER BY created_at DESC`, secretID)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()
	versions := make([]model.SecretVersionMetadata, 0)
	for rows.Next() {
		var version model.SecretVersionMetadata
		if err := rows.Scan(&version.SecretID, &version.VersionID, &version.CreatedAt, &version.CreatedByClientID, &version.RevokedAt); err != nil {
			return nil, mapPostgresError(err)
		}
		versions = append(versions, version)
	}
	return versions, mapPostgresError(rows.Err())
}

func (s *PostgresStore) ListSecretAccess(ctx context.Context, actorClientID, secretID string) ([]model.SecretAccessMetadata, error) {
	_, versionID, err := visibleVersion(ctx, s.pool, actorClientID, secretID, "", model.PermissionShare)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT secret_id::text, version_id::text, client_id, permissions, granted_at, expires_at
		FROM secret_access
		WHERE secret_id = $1::uuid
		  AND version_id = $2::uuid
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY client_id`, secretID, versionID)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()
	accesses := make([]model.SecretAccessMetadata, 0)
	for rows.Next() {
		var access model.SecretAccessMetadata
		if err := rows.Scan(&access.SecretID, &access.VersionID, &access.ClientID, &access.Permissions, &access.GrantedAt, &access.ExpiresAt); err != nil {
			return nil, mapPostgresError(err)
		}
		accesses = append(accesses, access)
	}
	return accesses, mapPostgresError(rows.Err())
}

func (s *PostgresStore) DeleteSecret(ctx context.Context, actorClientID, secretID string) error {
	if _, _, err := visibleVersion(ctx, s.pool, actorClientID, secretID, "", model.PermissionWrite); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE secrets SET deleted_at = COALESCE(deleted_at, NOW()) WHERE secret_id = $1::uuid AND deleted_at IS NULL`, secretID)
	if err != nil {
		return mapPostgresError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) ShareSecret(ctx context.Context, actorClientID, secretID string, req model.ShareSecretRequest) error {
	if !model.ValidClientID(req.TargetClientID) || !model.ValidOpaqueBlob(req.Envelope) || !model.ValidPermissionBits(req.Permissions) || !validFutureExpiry(req.ExpiresAt) {
		return ErrInvalidInput
	}
	envelopeBytes, err := decodeOpaqueBlob(req.Envelope)
	if err != nil {
		return ErrInvalidInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackIgnored(ctx, tx)
	_, versionID, err := visibleVersion(ctx, tx, actorClientID, secretID, req.VersionID, model.PermissionShare)
	if err != nil {
		return err
	}
	if active, err := activeClientExists(ctx, tx, req.TargetClientID); err != nil {
		return err
	} else if !active {
		return ErrInvalidInput
	}
	if active, err := activeAccessExists(ctx, tx, secretID, versionID, req.TargetClientID); err != nil {
		return err
	} else if active {
		return ErrConflict
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO secret_access (secret_id, version_id, client_id, envelope, permissions, expires_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
		ON CONFLICT (secret_id, version_id, client_id) DO UPDATE
		SET envelope = EXCLUDED.envelope,
		    permissions = EXCLUDED.permissions,
		    expires_at = EXCLUDED.expires_at,
		    granted_at = NOW(),
		    revoked_at = NULL
		WHERE secret_access.revoked_at IS NOT NULL OR secret_access.expires_at <= NOW()`,
		secretID, versionID, req.TargetClientID, envelopeBytes, req.Permissions, req.ExpiresAt); err != nil {
		return mapPostgresError(err)
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) RequestAccessGrant(ctx context.Context, actorClientID, secretID string, req model.AccessGrantRequest) (model.AccessGrantRef, error) {
	if !model.ValidClientID(req.TargetClientID) || !model.ValidPermissionBits(req.Permissions) || !validFutureExpiry(req.ExpiresAt) {
		return model.AccessGrantRef{}, ErrInvalidInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.AccessGrantRef{}, err
	}
	defer rollbackIgnored(ctx, tx)
	versionID, err := resolveActiveVersion(ctx, tx, secretID, req.VersionID)
	if err != nil {
		return model.AccessGrantRef{}, err
	}
	if active, err := activeClientExists(ctx, tx, actorClientID); err != nil {
		return model.AccessGrantRef{}, err
	} else if !active {
		return model.AccessGrantRef{}, ErrInvalidInput
	}
	if active, err := activeClientExists(ctx, tx, req.TargetClientID); err != nil {
		return model.AccessGrantRef{}, err
	} else if !active {
		return model.AccessGrantRef{}, ErrInvalidInput
	}
	if active, err := activeAccessExists(ctx, tx, secretID, versionID, req.TargetClientID); err != nil {
		return model.AccessGrantRef{}, err
	} else if active {
		return model.AccessGrantRef{}, ErrConflict
	}
	if pending, err := activePendingAccessExists(ctx, tx, secretID, versionID, req.TargetClientID); err != nil {
		return model.AccessGrantRef{}, err
	} else if pending {
		return model.AccessGrantRef{}, ErrConflict
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO secret_access_requests (secret_id, version_id, client_id, permissions, expires_at, requested_by_client_id)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)`, secretID, versionID, req.TargetClientID, req.Permissions, req.ExpiresAt, actorClientID)
	if err != nil {
		return model.AccessGrantRef{}, mapPostgresError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return model.AccessGrantRef{}, err
	}
	return model.AccessGrantRef{SecretID: secretID, VersionID: versionID, ClientID: req.TargetClientID, Status: "pending"}, nil
}

func (s *PostgresStore) ListAccessGrantRequests(ctx context.Context, secretID string) ([]model.AccessGrantMetadata, error) {
	query := `
		SELECT secret_id::text, version_id::text, client_id, requested_by_client_id, permissions, requested_at, expires_at,
		       CASE
		           WHEN activated_at IS NOT NULL THEN 'activated'
		           WHEN revoked_at IS NOT NULL THEN 'revoked'
		           WHEN expires_at IS NOT NULL AND expires_at <= NOW() THEN 'expired'
		           ELSE 'pending'
		       END AS status
		FROM secret_access_requests`
	args := []any{}
	if secretID != "" {
		query += ` WHERE secret_id = $1::uuid`
		args = append(args, secretID)
	}
	query += ` ORDER BY requested_at DESC`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()
	requests := make([]model.AccessGrantMetadata, 0)
	for rows.Next() {
		var request model.AccessGrantMetadata
		if err := rows.Scan(&request.SecretID, &request.VersionID, &request.ClientID, &request.RequestedByClientID, &request.Permissions, &request.RequestedAt, &request.ExpiresAt, &request.Status); err != nil {
			return nil, mapPostgresError(err)
		}
		requests = append(requests, request)
	}
	return requests, mapPostgresError(rows.Err())
}

func (s *PostgresStore) ActivateAccessGrant(ctx context.Context, actorClientID, secretID, targetClientID string, req model.ActivateAccessRequest) error {
	if !model.ValidClientID(targetClientID) || !model.ValidOpaqueBlob(req.Envelope) {
		return ErrInvalidInput
	}
	envelopeBytes, err := decodeOpaqueBlob(req.Envelope)
	if err != nil {
		return ErrInvalidInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackIgnored(ctx, tx)
	var versionID string
	var permissions int
	var expiresAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT version_id::text, permissions, expires_at
		FROM secret_access_requests
		WHERE secret_id = $1::uuid AND client_id = $2 AND activated_at IS NULL AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())`, secretID, targetClientID).
		Scan(&versionID, &permissions, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return mapPostgresError(err)
	}
	if _, _, err := visibleVersion(ctx, tx, actorClientID, secretID, versionID, model.PermissionShare); err != nil {
		return err
	}
	if active, err := activeClientExists(ctx, tx, targetClientID); err != nil {
		return err
	} else if !active {
		return ErrInvalidInput
	}
	if active, err := activeAccessExists(ctx, tx, secretID, versionID, targetClientID); err != nil {
		return err
	} else if active {
		return ErrConflict
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO secret_access (secret_id, version_id, client_id, envelope, permissions, expires_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
		ON CONFLICT (secret_id, version_id, client_id) DO UPDATE
		SET envelope = EXCLUDED.envelope,
		    permissions = EXCLUDED.permissions,
		    expires_at = EXCLUDED.expires_at,
		    granted_at = NOW(),
		    revoked_at = NULL
		WHERE secret_access.revoked_at IS NOT NULL OR secret_access.expires_at <= NOW()`, secretID, versionID, targetClientID, envelopeBytes, permissions, expiresAt); err != nil {
		return mapPostgresError(err)
	}
	_, err = tx.Exec(ctx, `
		UPDATE secret_access_requests
		SET activated_at = NOW()
		WHERE secret_id = $1::uuid AND version_id = $2::uuid AND client_id = $3 AND activated_at IS NULL AND revoked_at IS NULL`, secretID, versionID, targetClientID)
	if err != nil {
		return mapPostgresError(err)
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) RevokeAccess(ctx context.Context, actorClientID, secretID, targetClientID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackIgnored(ctx, tx)
	if _, _, err := visibleVersion(ctx, tx, actorClientID, secretID, "", model.PermissionShare); err != nil {
		return err
	}
	accessTag, err := tx.Exec(ctx, `
		UPDATE secret_access
		SET revoked_at = NOW()
		WHERE secret_id = $1::uuid AND client_id = $2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())`, secretID, targetClientID)
	if err != nil {
		return mapPostgresError(err)
	}
	pendingTag, err := tx.Exec(ctx, `
		UPDATE secret_access_requests
		SET revoked_at = NOW()
		WHERE secret_id = $1::uuid AND client_id = $2 AND activated_at IS NULL AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())`, secretID, targetClientID)
	if err != nil {
		return mapPostgresError(err)
	}
	if accessTag.RowsAffected()+pendingTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) CreateSecretVersion(ctx context.Context, actorClientID, secretID string, req model.CreateSecretVersionRequest) (model.SecretVersionRef, error) {
	if err := validateOpaqueSecretPayload(req.Ciphertext, req.Envelopes); err != nil {
		return model.SecretVersionRef{}, err
	}
	if !model.ValidCryptoMetadata(req.CryptoMetadata) {
		return model.SecretVersionRef{}, ErrInvalidInput
	}
	if !model.ValidPermissionBits(req.Permissions) || !validFutureExpiry(req.ExpiresAt) {
		return model.SecretVersionRef{}, ErrInvalidInput
	}
	if !containsEnvelopeFor(req.Envelopes, actorClientID) {
		return model.SecretVersionRef{}, ErrForbidden
	}
	ciphertext, err := decodeOpaqueBlob(req.Ciphertext)
	if err != nil {
		return model.SecretVersionRef{}, ErrInvalidInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.SecretVersionRef{}, err
	}
	defer rollbackIgnored(ctx, tx)
	if _, _, err := visibleVersion(ctx, tx, actorClientID, secretID, "", model.PermissionWrite); err != nil {
		return model.SecretVersionRef{}, err
	}
	for _, envelope := range req.Envelopes {
		if active, err := activeClientExists(ctx, tx, envelope.ClientID); err != nil {
			return model.SecretVersionRef{}, err
		} else if !active {
			return model.SecretVersionRef{}, ErrInvalidInput
		}
	}
	now := time.Now().UTC()
	retiredRows, err := tx.Query(ctx, `
		UPDATE secret_versions
		SET revoked_at = $2
		WHERE secret_id = $1::uuid AND revoked_at IS NULL
		RETURNING version_id::text`, secretID, now)
	if err != nil {
		return model.SecretVersionRef{}, mapPostgresError(err)
	}
	retiredVersionIDs := make([]string, 0)
	for retiredRows.Next() {
		var versionID string
		if err := retiredRows.Scan(&versionID); err != nil {
			retiredRows.Close()
			return model.SecretVersionRef{}, mapPostgresError(err)
		}
		retiredVersionIDs = append(retiredVersionIDs, versionID)
	}
	if err := retiredRows.Err(); err != nil {
		retiredRows.Close()
		return model.SecretVersionRef{}, mapPostgresError(err)
	}
	retiredRows.Close()
	for _, versionID := range retiredVersionIDs {
		if _, err := tx.Exec(ctx, `
			UPDATE secret_access_requests
			SET revoked_at = $3
			WHERE secret_id = $1::uuid AND version_id = $2::uuid AND activated_at IS NULL AND revoked_at IS NULL`, secretID, versionID, now); err != nil {
			return model.SecretVersionRef{}, mapPostgresError(err)
		}
	}
	ref := model.SecretVersionRef{SecretID: secretID}
	err = tx.QueryRow(ctx, `
		INSERT INTO secret_versions (secret_id, ciphertext, crypto_metadata, created_by_client_id)
		VALUES ($1::uuid, $2, $3, $4)
		RETURNING version_id::text`, secretID, ciphertext, nullableJSON(req.CryptoMetadata), actorClientID).Scan(&ref.VersionID)
	if err != nil {
		return model.SecretVersionRef{}, mapPostgresError(err)
	}
	for _, envelope := range req.Envelopes {
		envelopeBytes, err := decodeOpaqueBlob(envelope.Envelope)
		if err != nil {
			return model.SecretVersionRef{}, ErrInvalidInput
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO secret_access (secret_id, version_id, client_id, envelope, permissions, expires_at)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)`, secretID, ref.VersionID, envelope.ClientID, envelopeBytes, req.Permissions, req.ExpiresAt); err != nil {
			return model.SecretVersionRef{}, mapPostgresError(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return model.SecretVersionRef{}, err
	}
	return ref, nil
}

func (s *PostgresStore) AppendAudit(ctx context.Context, event model.AuditEvent) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackIgnored(ctx, tx)
	var previousHash []byte
	_ = tx.QueryRow(ctx, `
		SELECT event_hash
		FROM audit_events
		ORDER BY occurred_at DESC, event_id DESC
		LIMIT 1`).Scan(&previousHash)
	if event.EventID == "" {
		event.EventID = id.New()
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	event.PreviousHash = cloneBytes(previousHash)
	event.EventHash = audit.ComputeHash(previousHash, event)
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_events (event_id, occurred_at, actor_client_id, action, resource_type, resource_id, outcome, metadata, previous_hash, event_hash)
		VALUES ($1::uuid, $2, NULLIF($3, ''), $4, $5, NULLIF($6, ''), $7, $8, $9, $10)`,
		event.EventID, event.OccurredAt, event.ActorClientID, event.Action, event.ResourceType, event.ResourceID, event.Outcome, nullableJSON(event.Metadata), event.PreviousHash, event.EventHash)
	if err != nil {
		return mapPostgresError(err)
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ListAuditEvents(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT event_id::text, occurred_at, COALESCE(actor_client_id, ''), action, resource_type, COALESCE(resource_id, ''), outcome, metadata, previous_hash, event_hash
		FROM audit_events
		ORDER BY occurred_at ASC, event_id ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()
	events := make([]model.AuditEvent, 0)
	for rows.Next() {
		var event model.AuditEvent
		var metadata []byte
		if err := rows.Scan(&event.EventID, &event.OccurredAt, &event.ActorClientID, &event.Action, &event.ResourceType, &event.ResourceID, &event.Outcome, &metadata, &event.PreviousHash, &event.EventHash); err != nil {
			return nil, mapPostgresError(err)
		}
		event.Metadata = cloneRaw(json.RawMessage(metadata))
		events = append(events, event)
	}
	return events, mapPostgresError(rows.Err())
}

type pgQuerier interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func visibleVersion(ctx context.Context, q pgQuerier, actorClientID, secretID, versionID string, permission model.Permission) (string, string, error) {
	if active, err := activeClientExists(ctx, q, actorClientID); err != nil {
		return "", "", err
	} else if !active {
		return "", "", ErrForbidden
	}
	query, args := visibleVersionQuery(secretID, actorClientID, versionID, int(permission))
	var resolvedSecretID string
	var resolvedVersionID string
	err := q.QueryRow(ctx, query, args...).Scan(&resolvedSecretID, &resolvedVersionID)
	if err == nil {
		return resolvedSecretID, resolvedVersionID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", "", mapPostgresError(err)
	}
	if exists, existsErr := activeSecretExists(ctx, q, secretID); existsErr != nil {
		return "", "", existsErr
	} else if !exists {
		return "", "", ErrNotFound
	}
	if versionID != "" {
		if exists, existsErr := activeVersionExists(ctx, q, secretID, versionID); existsErr != nil {
			return "", "", existsErr
		} else if !exists {
			return "", "", ErrNotFound
		}
	}
	return "", "", ErrForbidden
}

func visibleVersionQuery(secretID, actorClientID, versionID string, permission int) (string, []any) {
	if versionID != "" {
		return `
			SELECT s.secret_id::text, v.version_id::text
			FROM secrets s
			JOIN secret_versions v ON v.secret_id = s.secret_id AND v.version_id = $3::uuid AND v.revoked_at IS NULL
			JOIN secret_access a ON a.secret_id = v.secret_id AND a.version_id = v.version_id AND a.client_id = $2
			WHERE s.secret_id = $1::uuid AND s.deleted_at IS NULL
			  AND a.revoked_at IS NULL
			  AND (a.expires_at IS NULL OR a.expires_at > NOW())
			  AND (a.permissions & $4) = $4`, []any{secretID, actorClientID, versionID, permission}
	}
	return `
		SELECT s.secret_id::text, v.version_id::text
		FROM secrets s
		JOIN LATERAL (
			SELECT version_id, secret_id
			FROM secret_versions
			WHERE secret_id = s.secret_id AND revoked_at IS NULL
			ORDER BY created_at DESC
			LIMIT 1
		) v ON TRUE
		JOIN secret_access a ON a.secret_id = v.secret_id AND a.version_id = v.version_id AND a.client_id = $2
		WHERE s.secret_id = $1::uuid AND s.deleted_at IS NULL
		  AND a.revoked_at IS NULL
		  AND (a.expires_at IS NULL OR a.expires_at > NOW())
		  AND (a.permissions & $3) = $3`, []any{secretID, actorClientID, permission}
}

func resolveActiveVersion(ctx context.Context, q pgQuerier, secretID, versionID string) (string, error) {
	if exists, err := activeSecretExists(ctx, q, secretID); err != nil {
		return "", err
	} else if !exists {
		return "", ErrNotFound
	}
	if versionID != "" {
		if exists, err := activeVersionExists(ctx, q, secretID, versionID); err != nil {
			return "", err
		} else if !exists {
			return "", ErrNotFound
		}
		return versionID, nil
	}
	var resolved string
	err := q.QueryRow(ctx, `
		SELECT version_id::text
		FROM secret_versions
		WHERE secret_id = $1::uuid AND revoked_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`, secretID).Scan(&resolved)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return resolved, mapPostgresError(err)
}

func activeClientExists(ctx context.Context, q pgQuerier, clientID string) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM clients WHERE client_id = $1 AND is_active = TRUE AND revoked_at IS NULL)`, clientID).Scan(&exists)
	return exists, mapPostgresError(err)
}

func activeSecretExists(ctx context.Context, q pgQuerier, secretID string) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM secrets WHERE secret_id = $1::uuid AND deleted_at IS NULL)`, secretID).Scan(&exists)
	return exists, mapPostgresError(err)
}

func activeVersionExists(ctx context.Context, q pgQuerier, secretID, versionID string) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM secret_versions WHERE secret_id = $1::uuid AND version_id = $2::uuid AND revoked_at IS NULL)`, secretID, versionID).Scan(&exists)
	return exists, mapPostgresError(err)
}

func activeAccessExists(ctx context.Context, q pgQuerier, secretID, versionID, clientID string) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM secret_access
			WHERE secret_id = $1::uuid AND version_id = $2::uuid AND client_id = $3
			  AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())
		)`, secretID, versionID, clientID).Scan(&exists)
	return exists, mapPostgresError(err)
}

func activePendingAccessExists(ctx context.Context, q pgQuerier, secretID, versionID, clientID string) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM secret_access_requests
			WHERE secret_id = $1::uuid AND version_id = $2::uuid AND client_id = $3
			  AND activated_at IS NULL AND revoked_at IS NULL
			  AND (expires_at IS NULL OR expires_at > NOW())
		)`, secretID, versionID, clientID).Scan(&exists)
	return exists, mapPostgresError(err)
}

func decodeOpaqueBlob(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

func encodeOpaqueBlob(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func nullableJSON(value json.RawMessage) any {
	if len(value) == 0 {
		return nil
	}
	return []byte(value)
}

func rollbackIgnored(ctx context.Context, tx pgx.Tx) {
	_ = tx.Rollback(ctx)
}

func mapPostgresError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return ErrConflict
		case "23503", "23514", "22P02", "22007":
			return ErrInvalidInput
		}
	}
	return err
}
