package webauth

import (
	"errors"
	"testing"
	"time"
)

func TestPasskeyCredentialStoreRegistersAndGetsCredential(t *testing.T) {
	store := NewPasskeyCredentialStore()
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if !store.Register(PasskeyCredentialRecord{CredentialID: "credential-1", ClientID: "admin", CreatedAt: created}) {
		t.Fatal("Register() = false")
	}
	record, err := store.Get("credential-1", "admin")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if record.CredentialID != "credential-1" || record.ClientID != "admin" || !record.CreatedAt.Equal(created) {
		t.Fatalf("unexpected record: %+v", record)
	}
	if got := store.CountForClient("admin"); got != 1 {
		t.Fatalf("CountForClient() = %d, want 1", got)
	}
}

func TestPasskeyCredentialStoreRejectsWrongClient(t *testing.T) {
	store := NewPasskeyCredentialStore()
	store.Register(PasskeyCredentialRecord{CredentialID: "credential-1", ClientID: "admin", CreatedAt: time.Now().UTC()})
	_, err := store.Get("credential-1", "operator")
	if !errors.Is(err, ErrPasskeyCredentialNotFound) {
		t.Fatalf("Get() error = %v, want %v", err, ErrPasskeyCredentialNotFound)
	}
}

func TestPasskeyCredentialStoreTouchUpdatesLastUsedAt(t *testing.T) {
	store := NewPasskeyCredentialStore()
	store.Register(PasskeyCredentialRecord{CredentialID: "credential-1", ClientID: "admin", CreatedAt: time.Now().UTC()})
	used := time.Date(2026, 1, 2, 4, 5, 6, 0, time.UTC)
	record, err := store.Touch("credential-1", "admin", used)
	if err != nil {
		t.Fatalf("Touch() error = %v", err)
	}
	if !record.LastUsedAt.Equal(used) {
		t.Fatalf("LastUsedAt = %s, want %s", record.LastUsedAt, used)
	}
}

func TestPasskeyCredentialStoreRejectsInvalidRecord(t *testing.T) {
	store := NewPasskeyCredentialStore()
	if store.Register(PasskeyCredentialRecord{CredentialID: "credential-1", ClientID: "admin"}) {
		t.Fatal("expected missing CreatedAt to be rejected")
	}
}
