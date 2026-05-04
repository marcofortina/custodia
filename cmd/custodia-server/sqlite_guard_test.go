// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

//go:build !sqlite

package main

import (
	"context"
	"errors"
	"testing"

	"custodia/internal/config"
	"custodia/internal/store"
)

func TestBuildStoreReturnsSQLiteBuildGuardWithoutSQLiteTag(t *testing.T) {
	_, closeStore, err := buildStore(context.Background(), config.Config{StoreBackend: "sqlite", DatabaseURL: "file:/tmp/custodia-test.db"})
	if closeStore != nil {
		closeStore()
	}
	if err == nil || !errors.Is(err, store.ErrSQLiteStoreNotWired) {
		t.Fatalf("expected sqlite build guard error, got %v", err)
	}
}
