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
		Ciphertext: "Y2lwaGVydGV4dC1mb3Itc2VydmVyLXN0b3JhZ2U=",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"},
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
		Envelope:       "ZW52ZWxvcGUtZm9yLWJvYg==",
		Permissions:    int(model.PermissionRead),
	})
	if err != nil {
		t.Fatalf("share secret: %v", err)
	}

	read, err := store.GetSecret(ctx, "client_bob", created.SecretID)
	if err != nil {
		t.Fatalf("bob read after share: %v", err)
	}
	if read.Envelope != "ZW52ZWxvcGUtZm9yLWJvYg==" {
		t.Fatalf("expected bob envelope only, got %q", read.Envelope)
	}
	if read.Ciphertext != "Y2lwaGVydGV4dC1mb3Itc2VydmVyLXN0b3JhZ2U=" {
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
		Ciphertext: "Y2lwaGVydGV4dA==",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_bob", Envelope: "ZW52ZWxvcGUtZm9yLWJvYg=="},
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
		Ciphertext: "Y2lwaGVydGV4dC12MQ==",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"},
			{ClientID: "client_bob", Envelope: "ZW52ZWxvcGUtZm9yLWJvYg=="},
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
			Ciphertext:  "Y2lwaGVydGV4dA==",
			Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"}},
			Permissions: permissions,
		})
		if err != ErrInvalidInput {
			t.Fatalf("expected create with permissions %d to be invalid, got %v", permissions, err)
		}
	}

	created, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:        "secret",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"}},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}

	for _, permissions := range []int{0, 8, -1} {
		err = store.ShareSecret(ctx, "client_alice", created.SecretID, model.ShareSecretRequest{
			VersionID:      created.VersionID,
			TargetClientID: "client_bob",
			Envelope:       "ZW52ZWxvcGUtZm9yLWJvYg==",
			Permissions:    permissions,
		})
		if err != ErrInvalidInput {
			t.Fatalf("expected share with permissions %d to be invalid, got %v", permissions, err)
		}
	}

	for _, permissions := range []int{0, 8, -1} {
		_, err = store.CreateSecretVersion(ctx, "client_alice", created.SecretID, model.CreateSecretVersionRequest{
			Ciphertext:  "Y2lwaGVydGV4dC12Mg==",
			Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNlLXYy"}},
			Permissions: permissions,
		})
		if err != ErrInvalidInput {
			t.Fatalf("expected version create with permissions %d to be invalid, got %v", permissions, err)
		}
	}
}

func TestMemoryStoreRejectsInvalidOpaquePayloadEncoding(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_alice", "client_alice")
	mustCreateClient(t, store, "client_bob", "client_bob")

	_, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:        "secret",
		Ciphertext:  "not base64",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"}},
		Permissions: int(model.PermissionAll),
	})
	if err != ErrInvalidInput {
		t.Fatalf("expected invalid ciphertext to be rejected, got %v", err)
	}

	_, err = store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:        "secret",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "not base64"}},
		Permissions: int(model.PermissionAll),
	})
	if err != ErrInvalidInput {
		t.Fatalf("expected invalid envelope to be rejected, got %v", err)
	}

	created, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:        "secret",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"}},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}

	err = store.ShareSecret(ctx, "client_alice", created.SecretID, model.ShareSecretRequest{
		VersionID:      created.VersionID,
		TargetClientID: "client_bob",
		Envelope:       "not base64",
		Permissions:    int(model.PermissionRead),
	})
	if err != ErrInvalidInput {
		t.Fatalf("expected invalid share envelope to be rejected, got %v", err)
	}

	_, err = store.CreateSecretVersion(ctx, "client_alice", created.SecretID, model.CreateSecretVersionRequest{
		Ciphertext:  "not base64",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNlLXYy"}},
		Permissions: int(model.PermissionAll),
	})
	if err != ErrInvalidInput {
		t.Fatalf("expected invalid version ciphertext to be rejected, got %v", err)
	}
}

func TestMemoryStoreRejectsDuplicateRecipientEnvelopes(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_alice", "client_alice")

	_, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:       "secret",
		Ciphertext: "Y2lwaGVydGV4dA==",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"},
			{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNlLTI="},
		},
		Permissions: int(model.PermissionAll),
	})
	if err != ErrInvalidInput {
		t.Fatalf("expected duplicate recipient envelopes to be rejected, got %v", err)
	}
}

func mustCreateClient(t *testing.T, store *MemoryStore, clientID, subject string) {
	t.Helper()
	if err := store.CreateClient(context.Background(), model.Client{ClientID: clientID, MTLSSubject: subject}); err != nil {
		t.Fatalf("create client %s: %v", clientID, err)
	}
}

func TestMemoryStoreGrantRequestRequiresClientSideEnvelopeActivation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_admin", "client_admin")
	mustCreateClient(t, store, "client_alice", "client_alice")
	mustCreateClient(t, store, "client_bob", "client_bob")

	created, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:       "secret",
		Ciphertext: "Y2lwaGVydGV4dA==",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"},
		},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}

	grant, err := store.RequestAccessGrant(ctx, "client_admin", created.SecretID, model.AccessGrantRequest{
		TargetClientID: "client_bob",
		Permissions:    int(model.PermissionRead),
	})
	if err != nil {
		t.Fatalf("request grant: %v", err)
	}
	if grant.Status != "pending" || grant.VersionID != created.VersionID {
		t.Fatalf("unexpected grant ref: %+v", grant)
	}
	if _, err := store.GetSecret(ctx, "client_bob", created.SecretID); err != ErrForbidden {
		t.Fatalf("expected bob to be forbidden before activation, got %v", err)
	}
	if err := store.ActivateAccessGrant(ctx, "client_bob", created.SecretID, "client_bob", model.ActivateAccessRequest{Envelope: "ZW52ZWxvcGUtZm9yLWJvYg=="}); err != ErrForbidden {
		t.Fatalf("expected non-sharing target activation to be forbidden, got %v", err)
	}
	if err := store.ActivateAccessGrant(ctx, "client_alice", created.SecretID, "client_bob", model.ActivateAccessRequest{Envelope: "ZW52ZWxvcGUtZm9yLWJvYg=="}); err != nil {
		t.Fatalf("activate grant: %v", err)
	}
	read, err := store.GetSecret(ctx, "client_bob", created.SecretID)
	if err != nil {
		t.Fatalf("bob read after activation: %v", err)
	}
	if read.Envelope != "ZW52ZWxvcGUtZm9yLWJvYg==" || read.Permissions != int(model.PermissionRead) {
		t.Fatalf("unexpected activated access: %+v", read)
	}
}
