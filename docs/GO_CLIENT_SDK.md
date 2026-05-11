# Custodia Go client SDK

`pkg/client` is the repository Go transport client for Custodia. Phase 5 stabilizes the transport SDK surface by adding public transport types and methods that do not require external users to import `custodia/internal/*` packages.

## Current scope

The Go client has two layers:

- transport methods that use mTLS and speak the documented `/v1/*` REST API;
- high-level crypto helpers that encrypt plaintext, create recipient envelopes, decrypt authorized payloads and share existing DEKs locally before calling the transport layer.

The server still receives only opaque ciphertext, crypto metadata and recipient envelopes. Recipient public keys come from the caller-provided resolver, not from Custodia server. Private keys remain behind the caller-provided private-key provider or the local X25519 helper.

## Public transport methods

Use the public Phase 5 methods and types for new integrations:

```go
created, err := c.CreateSecretPayload(client.CreateSecretPayload{
    Namespace:  "default",
    Key:        "database-password",
    Ciphertext: "base64-opaque-ciphertext",
    Envelopes: []client.RecipientEnvelope{
        {ClientID: "client_alice", Envelope: "base64-opaque-envelope"},
    },
    Permissions: client.PermissionRead,
})
```

These types and methods are SDK-facing transport APIs. `pkg/client/types.go` and `pkg/client/public_transport.go` deliberately avoid importing or exposing `custodia/internal/*`. New integrations should prefer the `namespace/key` helpers for read, share, revoke, version metadata, access metadata, update and delete flows.


## Public operational methods

The Go transport SDK also exposes public operational response types and methods that avoid `custodia/internal/*` return types:

```go
status, err := c.StatusInfo()
version, err := c.VersionInfo()
diagnostics, err := c.DiagnosticsInfo()
revocation, err := c.RevocationStatusInfo()
serial, err := c.RevocationSerialStatusInfo("0xCAFE")
events, err := c.ListAuditEventMetadata(client.AuditEventFilters{Limit: 25})
artifact, err := c.ExportAuditEventArtifact(client.AuditEventFilters{Outcome: "failure"})
```

Public operational types include `OperationalStatus`, `BuildInfo`, `RuntimeDiagnostics`, `RevocationStatus`, `RevocationSerialStatus`, `AuditEvent` and `AuditExportArtifact`. These methods are metadata/operations-only helpers; they do not expose secret plaintext, ciphertext or envelopes in logs.


## High-level crypto client

Use `NewCryptoClient` or `Client.WithCrypto` to enable local encryption/decryption on top of the transport SDK:

```go
cryptoClient, err := client.NewCryptoClient(c, client.CryptoOptions{
    PublicKeyResolver:  resolver,
    PrivateKeyProvider: privateKeys,
    RandomSource:       cryptoRandReader,
    Clock:              client.SystemClock{},
})
if err != nil {
    return err
}

created, err := cryptoClient.CreateEncryptedSecret(ctx, client.CreateEncryptedSecretRequest{
    Namespace:   "db01",
    Key:         "user:sys",
    Plaintext:   []byte("correct horse battery staple"),
    Recipients:  []string{"client_bob"},
    Permissions: client.PermissionAll,
})

secret, err := cryptoClient.ReadDecryptedSecretByKey(ctx, "db01", "user:sys")

err = cryptoClient.ShareEncryptedSecretByKey(ctx, "db01", "user:sys", client.ShareEncryptedSecretRequest{
    TargetClientID: "client_charlie",
    Permissions:    client.PermissionRead,
})
```

`CreateEncryptedSecret` automatically includes the current private-key provider client id as a recipient so the creator can read the secret later. `CreateEncryptedSecretVersionByKey` encrypts a new version locally and posts only opaque payloads. `ShareEncryptedSecretByKey` opens the caller's existing envelope locally to recover the DEK, creates a new envelope for the target recipient, and sends only that envelope to the server.

Crypto metadata persists the content nonce and canonical AAD binding used by the client. This avoids relying on server-side plaintext names during read paths and keeps decryption deterministic across create/read/share/version operations.

## Public crypto interface contracts

Future high-level Go crypto helpers must depend on explicit caller-provided crypto dependencies instead of resolving trust through Custodia server:

```go
opts := client.CryptoOptions{
    PublicKeyResolver: resolver,
    PrivateKeyProvider: privateKeys,
    RandomSource: cryptoRandReader,
    Clock: client.SystemClock{},
}
if err := opts.Validate(); err != nil {
    return err
}
```

`PublicKeyResolver` resolves recipient encryption keys outside Custodia. `PrivateKeyProvider` returns a local decrypter handle. `RandomSource` is caller-provided CSPRNG input and `Clock` exists for deterministic metadata/tests. These contracts keep the server out of public-key discovery and private-key handling.

## Internal-model helpers

Internal-model methods such as `CreateSecret`, `GetSecret`, `ShareSecret`, `Me`, `ListSecrets`, `ListClients`, `Status`, `Version`, `Diagnostics`, `RevocationStatus` and `ListAuditEvents` remain for monorepo use, but several expose internal model types and are documented as internal-model helpers. New external consumers should use the public transport, operational and `namespace/key` methods.

## External consumer contract

The repository includes a compile test that creates a temporary external Go module, imports `custodia/pkg/client`, and verifies that the public Phase 5 SDK types compile without importing `custodia/internal/*`.


## Public surface guardrails

The repository enforces two guardrails:

- `pkg/client/types.go` and `pkg/client/public_transport.go` must not import `custodia/internal/*`;
- an external temporary Go module must compile against the public transport types and methods.

These guardrails keep the transport and high-level crypto SDK usable by external consumers without requiring imports from `custodia/internal/*`.
