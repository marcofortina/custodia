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
	"path/filepath"
	"testing"

	"custodia/internal/model"
)

func TestSQLiteStorePersistsClientAndSecretLifecycle(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "custodia.db")
	vaultStore, err := NewSQLiteStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	if err := vaultStore.CreateClient(ctx, model.Client{ClientID: "client_alice", MTLSSubject: "client_alice"}); err != nil {
		t.Fatalf("CreateClient(alice) error = %v", err)
	}
	if err := vaultStore.CreateClient(ctx, model.Client{ClientID: "client_bob", MTLSSubject: "client_bob"}); err != nil {
		t.Fatalf("CreateClient(bob) error = %v", err)
	}
	created, err := vaultStore.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:        "db-secret",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}
	vaultStore.Close()

	reopened, err := NewSQLiteStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen NewSQLiteStore() error = %v", err)
	}
	defer reopened.Close()
	read, err := reopened.GetSecret(ctx, "client_alice", created.SecretID)
	if err != nil {
		t.Fatalf("GetSecret() after reopen error = %v", err)
	}
	if read.SecretID != created.SecretID || read.VersionID != created.VersionID || read.Ciphertext != "Y2lwaGVydGV4dA==" {
		t.Fatalf("unexpected persisted secret: %+v", read)
	}
}
