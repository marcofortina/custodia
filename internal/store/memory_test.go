package store

import (
	"context"
	"testing"
	"time"

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

func TestMemoryStoreCreateSecretVersionSupersedesOlderVersionsAndPendingGrants(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_admin", "client_admin")
	mustCreateClient(t, store, "client_alice", "client_alice")
	mustCreateClient(t, store, "client_bob", "client_bob")

	created, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:       "secret",
		Ciphertext: "Y2lwaGVydGV4dC12MQ==",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtYWxpY2UtdjE="},
		},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := store.RequestAccessGrant(ctx, "client_admin", created.SecretID, model.AccessGrantRequest{
		VersionID:      created.VersionID,
		TargetClientID: "client_bob",
		Permissions:    int(model.PermissionRead),
	}); err != nil {
		t.Fatalf("request grant: %v", err)
	}

	rotated, err := store.CreateSecretVersion(ctx, "client_alice", created.SecretID, model.CreateSecretVersionRequest{
		Ciphertext: "Y2lwaGVydGV4dC12Mg==",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtYWxpY2UtdjI="},
		},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create rotated version: %v", err)
	}
	if rotated.VersionID == created.VersionID {
		t.Fatalf("expected a new version id, got %q", rotated.VersionID)
	}

	read, err := store.GetSecret(ctx, "client_alice", created.SecretID)
	if err != nil {
		t.Fatalf("read rotated secret: %v", err)
	}
	if read.VersionID != rotated.VersionID || read.Ciphertext != "Y2lwaGVydGV4dC12Mg==" {
		t.Fatalf("expected latest rotated version, got %+v", read)
	}

	if err := store.ShareSecret(ctx, "client_alice", created.SecretID, model.ShareSecretRequest{
		VersionID:      created.VersionID,
		TargetClientID: "client_bob",
		Envelope:       "ZW52ZWxvcGUtYm9iLW9sZA==",
		Permissions:    int(model.PermissionRead),
	}); err != ErrNotFound {
		t.Fatalf("expected superseded version share to be rejected, got %v", err)
	}
	if err := store.ActivateAccessGrant(ctx, "client_alice", created.SecretID, "client_bob", model.ActivateAccessRequest{Envelope: "ZW52ZWxvcGUtYm9iLW9sZA=="}); err != ErrNotFound {
		t.Fatalf("expected superseded pending grant activation to be rejected, got %v", err)
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

func TestMemoryStoreExpiresAccessGrants(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_alice", "client_alice")
	mustCreateClient(t, store, "client_bob", "client_bob")
	future := time.Now().UTC().Add(time.Hour)
	past := time.Now().UTC().Add(-time.Hour)

	if _, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:        "expired",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"}},
		Permissions: int(model.PermissionAll),
		ExpiresAt:   &past,
	}); err != ErrInvalidInput {
		t.Fatalf("expected past create expiration to be invalid, got %v", err)
	}

	created, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:        "secret",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"}},
		Permissions: int(model.PermissionAll),
		ExpiresAt:   &future,
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := store.GetSecret(ctx, "client_alice", created.SecretID); err != nil {
		t.Fatalf("expected non-expired access to read: %v", err)
	}

	if err := store.ShareSecret(ctx, "client_alice", created.SecretID, model.ShareSecretRequest{
		VersionID:      created.VersionID,
		TargetClientID: "client_bob",
		Envelope:       "ZW52ZWxvcGUtZm9yLWJvYg==",
		Permissions:    int(model.PermissionRead),
		ExpiresAt:      &past,
	}); err != ErrInvalidInput {
		t.Fatalf("expected past share expiration to be invalid, got %v", err)
	}
}

func TestMemoryStoreRevokeClientRevokesAccessAndPendingGrants(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_admin", "client_admin")
	mustCreateClient(t, store, "client_alice", "client_alice")
	mustCreateClient(t, store, "client_bob", "client_bob")
	mustCreateClient(t, store, "client_charlie", "client_charlie")

	created, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:       "secret",
		Ciphertext: "Y2lwaGVydGV4dA==",
		Envelopes: []model.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"},
			{ClientID: "client_bob", Envelope: "ZW52ZWxvcGUtZm9yLWJvYg=="},
		},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := store.RequestAccessGrant(ctx, "client_admin", created.SecretID, model.AccessGrantRequest{
		TargetClientID: "client_charlie",
		Permissions:    int(model.PermissionRead),
	}); err != nil {
		t.Fatalf("request grant: %v", err)
	}

	if err := store.RevokeClient(ctx, "client_bob"); err != nil {
		t.Fatalf("revoke bob: %v", err)
	}
	if _, err := store.GetSecret(ctx, "client_bob", created.SecretID); err != ErrForbidden {
		t.Fatalf("expected revoked client read to be forbidden, got %v", err)
	}

	if err := store.RevokeClient(ctx, "client_admin"); err != nil {
		t.Fatalf("revoke admin: %v", err)
	}
	if err := store.ActivateAccessGrant(ctx, "client_alice", created.SecretID, "client_charlie", model.ActivateAccessRequest{Envelope: "ZW52ZWxvcGUtY2hhcmxpZQ=="}); err != ErrNotFound {
		t.Fatalf("expected pending grant from revoked requester to be revoked, got %v", err)
	}
}

func TestMemoryStoreExpiredPendingGrantCannotBeActivated(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_admin", "client_admin")
	mustCreateClient(t, store, "client_alice", "client_alice")
	mustCreateClient(t, store, "client_bob", "client_bob")

	created, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:        "secret",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGUtZm9yLWFsaWNl"}},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := store.RequestAccessGrant(ctx, "client_admin", created.SecretID, model.AccessGrantRequest{
		TargetClientID: "client_bob",
		Permissions:    int(model.PermissionRead),
	}); err != nil {
		t.Fatalf("request grant: %v", err)
	}

	past := time.Now().UTC().Add(-time.Minute)
	store.mu.Lock()
	store.pendingAccess[pendingAccessKey(created.SecretID, created.VersionID, "client_bob")].ExpiresAt = &past
	store.mu.Unlock()

	if err := store.ActivateAccessGrant(ctx, "client_alice", created.SecretID, "client_bob", model.ActivateAccessRequest{Envelope: "ZW52ZWxvcGUtZm9yLWJvYg=="}); err != ErrNotFound {
		t.Fatalf("expected expired pending grant activation to be rejected, got %v", err)
	}
}

func TestMemoryStoreRejectsInvalidClientIdentifiers(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.CreateClient(ctx, model.Client{ClientID: "client alice", MTLSSubject: "client alice"}); err != ErrInvalidInput {
		t.Fatalf("expected invalid client id to be rejected, got %v", err)
	}
	mustCreateClient(t, store, "client_alice", "client_alice")
	_, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:        "secret",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client/alice", Envelope: "ZW52ZWxvcGU="}},
		Permissions: int(model.PermissionAll),
	})
	if err != ErrInvalidInput {
		t.Fatalf("expected invalid envelope client id to be rejected, got %v", err)
	}
}

func TestMemoryStoreRejectsInvalidSecretNames(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_alice", "client_alice")
	for _, name := range []string{"", "   ", "secret\nname"} {
		_, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
			Name:        name,
			Ciphertext:  "Y2lwaGVydGV4dA==",
			Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}},
			Permissions: int(model.PermissionAll),
		})
		if err != ErrInvalidInput {
			t.Fatalf("expected invalid secret name %q to be rejected, got %v", name, err)
		}
	}
}

func TestMemoryStoreRejectsOversizedCryptoMetadata(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "client_alice", "client_alice")
	oversized := make([]byte, model.MaxCryptoMetadataBytes+1)
	for i := range oversized {
		oversized[i] = 'x'
	}
	_, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:           "secret",
		Ciphertext:     "Y2lwaGVydGV4dA==",
		CryptoMetadata: oversized,
		Envelopes:      []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}},
		Permissions:    int(model.PermissionAll),
	})
	if err != ErrInvalidInput {
		t.Fatalf("expected oversized crypto metadata to be rejected, got %v", err)
	}
}

func TestMemoryStoreDeleteSecretRevokesPendingAccessRequests(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	mustCreateClient(t, store, "admin", "admin")
	mustCreateClient(t, store, "client_alice", "client_alice")
	mustCreateClient(t, store, "client_bob", "client_bob")
	created, err := store.CreateSecret(ctx, "client_alice", model.CreateSecretRequest{
		Name:        "secret",
		Ciphertext:  "Y2lwaGVydGV4dA==",
		Envelopes:   []model.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52ZWxvcGU="}},
		Permissions: int(model.PermissionAll),
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := store.RequestAccessGrant(ctx, "admin", created.SecretID, model.AccessGrantRequest{TargetClientID: "client_bob", Permissions: int(model.PermissionRead)}); err != nil {
		t.Fatalf("request access: %v", err)
	}
	if err := store.DeleteSecret(ctx, "client_alice", created.SecretID); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	requests, err := store.ListAccessGrantRequests(ctx, created.SecretID)
	if err != nil {
		t.Fatalf("list requests: %v", err)
	}
	if len(requests) != 1 || requests[0].Status != "revoked" {
		t.Fatalf("expected pending request to be revoked after secret delete, got %+v", requests)
	}
}
