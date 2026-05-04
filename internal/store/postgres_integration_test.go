// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

//go:build postgres

package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"custodia/internal/model"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresStoreSecretLifecycleIntegration(t *testing.T) {
	databaseURL := os.Getenv("TEST_CUSTODIA_POSTGRES_URL")
	if databaseURL == "" {
		t.Skip("TEST_CUSTODIA_POSTGRES_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open postgres pool: %v", err)
	}
	defer pool.Close()

	schema, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "001_init.sql"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if _, err := pool.Exec(ctx, string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}

	vaultStore, err := NewPostgresStore(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	defer vaultStore.Close()

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	alice := "alice-" + suffix
	bob := "bob-" + suffix
	if err := vaultStore.CreateClient(ctx, model.Client{ClientID: alice, MTLSSubject: alice}); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if err := vaultStore.CreateClient(ctx, model.Client{ClientID: bob, MTLSSubject: bob}); err != nil {
		t.Fatalf("create bob: %v", err)
	}

	created, err := vaultStore.CreateSecret(ctx, alice, model.CreateSecretRequest{
		Name:        "integration-secret",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: alice, Envelope: "ZW52ZWxvcGUtYWxpY2U="}},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if created.SecretID == "" || created.VersionID == "" {
		t.Fatalf("expected secret and version ids, got %+v", created)
	}

	if err := vaultStore.ShareSecret(ctx, alice, created.SecretID, model.ShareSecretRequest{
		VersionID:      created.VersionID,
		TargetClientID: bob,
		Envelope:       "ZW52ZWxvcGUtYm9i",
		Permissions:    int(model.PermissionRead),
	}); err != nil {
		t.Fatalf("share secret: %v", err)
	}

	read, err := vaultStore.GetSecret(ctx, bob, created.SecretID)
	if err != nil {
		t.Fatalf("read shared secret: %v", err)
	}
	if read.Ciphertext != "Y2lwaGVydGV4dA==" || read.Envelope != "ZW52ZWxvcGUtYm9i" {
		t.Fatalf("unexpected opaque payload: %+v", read)
	}
}
