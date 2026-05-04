-- Copyright (c) 2026 Marco Fortina
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- This file is part of Custodia.
-- Custodia is distributed under the GNU Affero General Public License v3.0.
-- See the accompanying LICENSE file for details.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS clients (
    client_id      TEXT PRIMARY KEY,
    mtls_subject   TEXT UNIQUE NOT NULL,
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS secrets (
    secret_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 TEXT NOT NULL CHECK (length(btrim(name)) > 0 AND length(name) <= 255),
    created_by_client_id TEXT NOT NULL REFERENCES clients(client_id),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at           TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS secret_versions (
    secret_id            UUID NOT NULL REFERENCES secrets(secret_id) ON DELETE CASCADE,
    version_id           UUID NOT NULL DEFAULT gen_random_uuid(),
    ciphertext           BYTEA NOT NULL,
    crypto_metadata      JSONB,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by_client_id TEXT NOT NULL REFERENCES clients(client_id),
    revoked_at           TIMESTAMPTZ,
    PRIMARY KEY (secret_id, version_id),
    CHECK (octet_length(ciphertext) > 0)
);

CREATE TABLE IF NOT EXISTS secret_access (
    secret_id     UUID NOT NULL,
    version_id    UUID NOT NULL,
    client_id     TEXT NOT NULL REFERENCES clients(client_id),
    envelope      BYTEA NOT NULL,
    permissions   INT NOT NULL,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    PRIMARY KEY (secret_id, version_id, client_id),
    FOREIGN KEY (secret_id, version_id) REFERENCES secret_versions(secret_id, version_id) ON DELETE CASCADE,
    CHECK (octet_length(envelope) > 0),
    CHECK (permissions > 0 AND permissions <= 7),
    CHECK (expires_at IS NULL OR expires_at > granted_at)
);

CREATE TABLE IF NOT EXISTS secret_access_requests (
    request_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id              UUID NOT NULL,
    version_id             UUID NOT NULL,
    client_id              TEXT NOT NULL REFERENCES clients(client_id),
    permissions            INT NOT NULL,
    expires_at             TIMESTAMPTZ,
    requested_by_client_id TEXT NOT NULL REFERENCES clients(client_id),
    requested_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at           TIMESTAMPTZ,
    revoked_at             TIMESTAMPTZ,
    FOREIGN KEY (secret_id, version_id) REFERENCES secret_versions(secret_id, version_id) ON DELETE CASCADE,
    CHECK (permissions > 0 AND permissions <= 7),
    CHECK (expires_at IS NULL OR expires_at > requested_at)
);


CREATE TABLE IF NOT EXISTS web_users (
    user_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT UNIQUE NOT NULL,
    password_hash BYTEA NOT NULL,
    mfa_secret    TEXT,
    passkey_id    BYTEA,
    role          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at    TIMESTAMPTZ,
    CHECK (role IN ('admin', 'operator', 'auditor'))
);

CREATE TABLE IF NOT EXISTS web_user_mappings (
    user_id   UUID NOT NULL REFERENCES web_users(user_id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    PRIMARY KEY (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_client_id TEXT REFERENCES clients(client_id),
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT,
    outcome         TEXT NOT NULL,
    metadata        JSONB,
    previous_hash   BYTEA,
    event_hash      BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_clients_active_subject ON clients (mtls_subject) WHERE is_active = TRUE AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_secret_versions_latest ON secret_versions (secret_id, created_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_secret_access_client ON secret_access (client_id, secret_id, version_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_secret_access_requests_pending ON secret_access_requests (secret_id, version_id, client_id) WHERE activated_at IS NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at ON audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_web_users_active_role ON web_users (role) WHERE revoked_at IS NULL;
