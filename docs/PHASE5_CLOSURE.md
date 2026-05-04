# Custodia Phase 5 closure tracker

Phase 5 tracks official client libraries and client-side cryptography.

## Closed in this block

- Client libraries specification added to the repository.
- Shared client crypto specification added.
- Client crypto test-vector scaffold added.
- Go transport client public SDK types added so external consumers do not need to import `custodia/internal/*`.
- Go transport public methods added for opaque payload operations.
- Go operational SDK public response types and methods added for status, diagnostics, revocation and audit metadata.
- Public Go transport files no longer import `custodia/internal/*`.
- Legacy Go helpers that expose internal model types are documented as monorepo compatibility helpers.
- External Go consumer compile guard added for public transport types and methods.
- Go and Python transport SDK guides added.
- Python typed transport payload helpers and tests added.
- Client crypto metadata validator added for the v1 scaffold.
- Deterministic metadata/AAD fixtures added with canonical AAD and SHA-256 checks.
- Deterministic AES-256-GCM ciphertext and HPKE-v1 recipient envelope fixtures added for the shared v1 crypto vectors.
- Public Go crypto dependency interfaces added for high-level crypto helpers.
- Go high-level crypto client added for local create/read/share/version flows.
- Go X25519 helper added for local HPKE-v1 envelope opening without exposing internal packages.
- External Go consumer compile guard extended to the high-level crypto client surface.
- `make test-client-crypto` added for focused client-crypto fixture validation.

## Still open

- Python high-level crypto client.
- Node.js/TypeScript transport client.
- Rust transport client.
- Java transport client.
- C++ transport client.

## Current boundary

Go now has public transport, operational and high-level crypto SDK surfaces. The Go crypto client encrypts/decrypts locally, creates HPKE-v1 recipient envelopes, shares existing DEKs locally and sends only opaque payloads to the server. Python is still a typed transport client. Deterministic crypto fixtures cover canonical AAD, AES-256-GCM ciphertext and HPKE-v1 recipient envelopes.

The server remains metadata/ciphertext/envelope-only. Custodia must not become a public-key directory.

## Verification

Run:

```bash
make test-client-crypto
go test -p=1 -timeout 60s ./pkg/client ./internal/clientcrypto
go test -p=1 -timeout 60s ./...
python3 -m py_compile clients/python/custodia_client/__init__.py
```

Phase 5 core is not complete until the Python high-level crypto client is implemented on top of the deterministic ciphertext/envelope vectors. The broader multi-language roadmap still has Node.js/TypeScript, Rust, Java and C++ open.
