# Custodia Go client SDK

`pkg/client` is the repository Go transport client for Custodia. Phase 5 starts stabilizing it as a public SDK surface by adding public transport types that do not require external users to import `custodia/internal/*` packages.

## Current scope

The Go client is a transport client:

- it uses mTLS;
- it speaks the documented `/v1/*` REST API;
- it sends and receives opaque ciphertext/envelope payloads;
- it does not encrypt plaintext, decrypt ciphertext or resolve recipient keys.

High-level E2E crypto helpers are planned after `docs/CLIENT_CRYPTO_SPEC.md` and deterministic test vectors are complete.

## Public transport methods

Use the public Phase 5 methods and types for new integrations:

```go
created, err := c.CreateSecretPayload(client.CreateSecretPayload{
    Name:       "database-password",
    Ciphertext: "base64-opaque-ciphertext",
    Envelopes: []client.RecipientEnvelope{
        {ClientID: "client_alice", Envelope: "base64-opaque-envelope"},
    },
    Permissions: client.PermissionRead,
})
```

These types are stable SDK-facing types. They deliberately avoid exposing `internal/model`.

## Legacy methods

Older methods such as `CreateSecret`, `GetSecret`, `ShareSecret` and `Me` remain for compatibility inside the monorepo, but they expose internal model types and should not be the public SDK surface for new external consumers.

## External consumer contract

The repository includes a compile test that creates a temporary external Go module, imports `custodia/pkg/client`, and verifies that the public Phase 5 SDK types compile without importing `custodia/internal/*`.
