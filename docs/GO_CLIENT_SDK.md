# Custodia Go client SDK

`pkg/client` is the repository Go transport client for Custodia. Phase 5 stabilizes the transport SDK surface by adding public transport types and methods that do not require external users to import `custodia/internal/*` packages.

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

These types and methods are SDK-facing transport APIs. `pkg/client/types.go` and `pkg/client/public_transport.go` deliberately avoid importing or exposing `custodia/internal/*`.


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

## Legacy methods

Older methods such as `CreateSecret`, `GetSecret`, `ShareSecret`, `Me`, `ListSecrets` and `ListClients` remain for compatibility inside the monorepo, but they expose internal model types and are documented as legacy helpers. New external consumers should use the public Phase 5 transport methods.

## External consumer contract

The repository includes a compile test that creates a temporary external Go module, imports `custodia/pkg/client`, and verifies that the public Phase 5 SDK types compile without importing `custodia/internal/*`.


## Public surface guardrails

The repository enforces two guardrails:

- `pkg/client/types.go` and `pkg/client/public_transport.go` must not import `custodia/internal/*`;
- an external temporary Go module must compile against the public transport types and methods.

These guardrails keep the transport SDK usable before high-level crypto clients are implemented.
