# Custodia Phase 5 closure tracker

Phase 5 tracks official client libraries and client-side cryptography.

## Closed in this block

- Client libraries specification added to the repository.
- Shared client crypto specification added.
- Client crypto test-vector scaffold added.
- Go transport client public SDK types added so external consumers do not need to import `custodia/internal/*`.
- Go transport public methods added for opaque payload operations.
- Public Go transport files no longer import `custodia/internal/*`.
- Legacy Go helpers that expose internal model types are documented as monorepo compatibility helpers.
- External Go consumer compile guard added for public transport types and methods.
- Go and Python transport SDK guides added.

## Still open

- Deterministic cryptographic test vectors.
- Go high-level crypto client.
- Python high-level crypto client.
- Node.js/TypeScript transport client.
- Rust transport client.
- Java transport client.
- C++ transport client.

## Current boundary

Go and Python are transport clients. They speak REST/mTLS and move opaque payloads. They do not yet encrypt plaintext, unwrap envelopes, decrypt ciphertext or resolve recipient public keys.

The server remains metadata/ciphertext/envelope-only. Custodia must not become a public-key directory.

## Verification

Run:

```bash
go test -p=1 -timeout 60s ./pkg/client ./internal/clientcrypto
go test -p=1 -timeout 60s ./...
python3 -m py_compile clients/python/custodia_client/__init__.py
```

Phase 5 is not complete until deterministic crypto vectors and high-level crypto clients are implemented.
