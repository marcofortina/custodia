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
