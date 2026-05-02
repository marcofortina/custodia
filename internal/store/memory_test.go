package store

import (
	"context"
	"testing"

	"custodia/internal/model"
)

func TestMemoryStoreSecretLifecycleKeepsEnvelopePerClient(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_alice", "client_alice")
	mustCreateClient(t, store, "client_bob", "client_bob")

	created, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:       "db_prod_password",
		Ciphertext: "ciphertext-for-server-storage",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "envelope-for-alice"},
		},
		Permissions: 7,
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}

	if _, err := store.GetSecret(ctx, "client_bob", created.SecretID); err != ErrForbidden {
		t.Fatalf("expected bob to be forbidden before share, got %v", err)
	}

	err = store.ShareSecret(ctx, "client_alice", created.SecretID, model.ShareSecretRequest{
		VersionID:      created.VersionID,
		TargetClientID: "client_bob",
		Envelope:       "envelope-for-bob",
		Permissions:    int(model.PermissionRead),
	})
	if err != nil {
		t.Fatalf("share secret: %v", err)
	}

	read, err := store.GetSecret(ctx, "client_bob", created.SecretID)
	if err != nil {
		t.Fatalf("bob read after share: %v", err)
	}
	if read.Envelope != "envelope-for-bob" {
		t.Fatalf("expected bob envelope only, got %q", read.Envelope)
	}
	if read.Ciphertext != "ciphertext-for-server-storage" {
		t.Fatalf("unexpected ciphertext: %q", read.Ciphertext)
	}
}

func TestMemoryStoreRequiresCreatorEnvelope(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_alice", "client_alice")
	mustCreateClient(t, store, "client_bob", "client_bob")

	_, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:       "db_prod_password",
		Ciphertext: "ciphertext",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_bob", Envelope: "envelope-for-bob"},
		},
		Permissions: 7,
	})
	if err != ErrForbidden {
		t.Fatalf("expected missing self envelope to be forbidden, got %v", err)
	}
}

func TestMemoryStoreRevokesFutureReadsOnly(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_alice", "client_alice")
	mustCreateClient(t, store, "client_bob", "client_bob")
	created, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:       "secret",
		Ciphertext: "ciphertext-v1",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "envelope-for-alice"},
			{ClientID: "client_bob", Envelope: "envelope-for-bob"},
		},
		Permissions: 7,
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if err := store.RevokeAccess(ctx, "client_alice", created.SecretID, "client_bob"); err != nil {
		t.Fatalf("revoke access: %v", err)
	}
	if _, err := store.GetSecret(ctx, "client_bob", created.SecretID); err != ErrForbidden {
		t.Fatalf("expected revoked bob to be forbidden, got %v", err)
	}
}

func TestMemoryStoreRejectsInvalidPermissionBits(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_alice", "client_alice")
	mustCreateClient(t, store, "client_bob", "client_bob")

	for _, permissions := range []int{0, 8, -1} {
		_, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
			Name:        "secret",
			Ciphertext:  "ciphertext",
			Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "envelope-for-alice"}},
			Permissions: permissions,
		})
		if err != ErrInvalidInput {
			t.Fatalf("expected create with permissions %d to be invalid, got %v", permissions, err)
		}
	}

	created, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:        "secret",
		Ciphertext:  "ciphertext",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "envelope-for-alice"}},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}

	for _, permissions := range []int{0, 8, -1} {
		err = store.ShareSecret(ctx, "client_alice", created.SecretID, model.ShareSecretRequest{
			VersionID:      created.VersionID,
			TargetClientID: "client_bob",
			Envelope:       "envelope-for-bob",
			Permissions:    permissions,
		})
		if err != ErrInvalidInput {
			t.Fatalf("expected share with permissions %d to be invalid, got %v", permissions, err)
		}
	}

	for _, permissions := range []int{0, 8, -1} {
		_, err = store.CreateSecretVersion(ctx, "client_alice", created.SecretID, model.CreateSecretVersionRequest{
			Ciphertext:  "ciphertext-v2",
			Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "envelope-for-alice-v2"}},
			Permissions: permissions,
		})
		if err != ErrInvalidInput {
			t.Fatalf("expected version create with permissions %d to be invalid, got %v", permissions, err)
		}
	}
}

func mustCreateClient(t *testing.T, store *MemoryStore, clientID, subject string) {
	t.Helper()
	if err := store.CreateClient(context.Background(), model.Client{ClientID: clientID, MTLSSubject: subject}); err != nil {
		t.Fatalf("create client %s: %v", clientID, err)
	}
}
