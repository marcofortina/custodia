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
- Public Go crypto dependency interfaces added for future high-level crypto helpers.
- `make test-client-crypto` added for focused client-crypto fixture validation.

## Still open

- Go high-level crypto client.
- Python high-level crypto client.
- Node.js/TypeScript transport client.
- Rust transport client.
- Java transport client.
- C++ transport client.

## Current boundary

Go and Python are transport clients. They speak REST/mTLS and move opaque payloads. Python now has typed transport payload helpers; Go has public transport and operational SDK surfaces. Deterministic crypto fixtures now cover canonical AAD, AES-256-GCM ciphertext and HPKE-v1 recipient envelopes. They are test vectors only; Go and Python do not yet expose high-level E2E crypto helpers.

The server remains metadata/ciphertext/envelope-only. Custodia must not become a public-key directory.

## Verification

Run:

```bash
make test-client-crypto
go test -p=1 -timeout 60s ./pkg/client ./internal/clientcrypto
go test -p=1 -timeout 60s ./...
python3 -m py_compile clients/python/custodia_client/__init__.py
```

Phase 5 is not complete until high-level crypto clients are implemented on top of the deterministic ciphertext/envelope vectors.
