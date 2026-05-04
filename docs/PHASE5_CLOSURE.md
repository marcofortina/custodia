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
- Python high-level crypto client added for local create/read/share/version flows.
- Python crypto vector tests added against the shared deterministic AES-256-GCM and HPKE-v1 fixtures.
- External Go consumer compile guard extended to the high-level crypto client surface.
- `make test-client-crypto` added for focused client-crypto fixture validation.

## Still open

- Node.js/TypeScript transport and high-level crypto clients added for opaque REST payloads, with TypeScript declarations and Node test target.
- Rust transport client.
- Java transport client.
- C++ transport client.

## Current boundary

Go now has public transport, operational and high-level crypto SDK surfaces. Python now has typed transport helpers plus a high-level crypto wrapper. Node.js / TypeScript now has transport and high-level crypto clients for opaque REST payloads with TypeScript declarations. Go, Python and Node.js high-level clients encrypt/decrypt locally, create HPKE-v1 recipient envelopes, share existing DEKs locally and send only opaque payloads to the server. Deterministic crypto fixtures cover canonical AAD, AES-256-GCM ciphertext and HPKE-v1 recipient envelopes.

The server remains metadata/ciphertext/envelope-only. Custodia must not become a public-key directory.

## Verification

Run:

```bash
make test-client-crypto
go test -p=1 -timeout 60s ./pkg/client ./internal/clientcrypto
go test -p=1 -timeout 60s ./...
python3 -m py_compile clients/python/custodia_client/__init__.py clients/python/custodia_client/types.py clients/python/custodia_client/crypto.py
python3 -m unittest discover -s clients/python/tests
node --check clients/node/src/index.js
npm test --prefix clients/node
```

Phase 5 core Go+Python+Node is complete at repository level. The broader multi-language roadmap still has Rust, Java and C++ open.
