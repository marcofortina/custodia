// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package webauth

import (
	"errors"
	"testing"
	"time"
)

func TestPasskeyChallengeStoreConsumesOnce(t *testing.T) {
	store := NewPasskeyChallengeStore()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if !store.Store(PasskeyChallengeRecord{Challenge: "challenge", ClientID: "admin", Purpose: "authenticate", ExpiresAt: now.Add(time.Minute)}) {
		t.Fatal("expected challenge to be stored")
	}
	if _, err := store.Consume("challenge", "admin", "authenticate", now); err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	if _, err := store.Consume("challenge", "admin", "authenticate", now); !errors.Is(err, ErrPasskeyChallengeNotFound) {
		t.Fatalf("second Consume() error = %v, want %v", err, ErrPasskeyChallengeNotFound)
	}
}

func TestPasskeyChallengeStoreRejectsWrongClientOrExpired(t *testing.T) {
	store := NewPasskeyChallengeStore()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	store.Store(PasskeyChallengeRecord{Challenge: "challenge", ClientID: "admin", Purpose: "authenticate", ExpiresAt: now.Add(time.Minute)})
	if _, err := store.Consume("challenge", "other", "authenticate", now); !errors.Is(err, ErrPasskeyChallengeNotFound) {
		t.Fatalf("wrong-client Consume() error = %v, want %v", err, ErrPasskeyChallengeNotFound)
	}
	store.Store(PasskeyChallengeRecord{Challenge: "expired", ClientID: "admin", Purpose: "authenticate", ExpiresAt: now.Add(-time.Second)})
	if _, err := store.Consume("expired", "admin", "authenticate", now); !errors.Is(err, ErrPasskeyChallengeNotFound) {
		t.Fatalf("expired Consume() error = %v, want %v", err, ErrPasskeyChallengeNotFound)
	}
}

func TestPasskeyChallengeStorePrunesExpiredChallenges(t *testing.T) {
	store := NewPasskeyChallengeStore()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	store.Store(PasskeyChallengeRecord{Challenge: "expired", ClientID: "admin", Purpose: "authenticate", ExpiresAt: now.Add(-time.Second)})
	store.Store(PasskeyChallengeRecord{Challenge: "valid", ClientID: "admin", Purpose: "authenticate", ExpiresAt: now.Add(time.Minute)})
	if removed := store.Prune(now); removed != 1 {
		t.Fatalf("Prune() = %d, want 1", removed)
	}
	if _, err := store.Consume("valid", "admin", "authenticate", now); err != nil {
		t.Fatalf("valid challenge missing after prune: %v", err)
	}
}
