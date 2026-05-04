// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

//go:build !sqlite

package store

import (
	"context"
	"errors"
	"testing"
)

func TestSQLiteStoreFailsClosedWithoutSQLiteBuildTag(t *testing.T) {
	_, err := NewSQLiteStore(context.Background(), "file:/tmp/custodia.db")
	if !errors.Is(err, ErrSQLiteStoreNotWired) {
		t.Fatalf("NewSQLiteStore() error = %v, want %v", err, ErrSQLiteStoreNotWired)
	}
}
