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
- Java transport client added for opaque REST/mTLS payloads with a Java test target.
- Java high-level crypto client added for local create/read/share/version flows.
- C++ transport client added for opaque REST/mTLS payloads with a libcurl-backed C++ test target.
- C++ high-level crypto client added for local create/read/share/version flows with OpenSSL-backed AES-GCM/X25519/HKDF primitives.

## Still open

- Rust transport client.

## Current boundary

Go now has public transport, operational and high-level crypto SDK surfaces. Python now has typed transport helpers plus a high-level crypto wrapper. Node.js / TypeScript now has transport and high-level crypto clients for opaque REST payloads with TypeScript declarations. Java and C++ now have transport and high-level crypto clients. Go, Python, Node.js, Java and C++ high-level clients encrypt/decrypt locally, create HPKE-v1 recipient envelopes, share existing DEKs locally and send only opaque payloads to the server. Deterministic crypto fixtures cover canonical AAD, AES-256-GCM ciphertext and HPKE-v1 recipient envelopes.

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
make test-java-client
make test-cpp-client
```

Phase 5 is complete for Go, Python, Node.js/TypeScript, Java and C++ at repository level. The only planned language still open in the broader roadmap is Rust transport.
