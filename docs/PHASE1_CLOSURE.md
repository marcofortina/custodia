# Custodia Phase 1 closure

Phase 1 is closed as the secure repository baseline for Custodia.

## Goal

Phase 1 established the core vault contract:

- Custodia stores opaque ciphertext only;
- the server never sees plaintext;
- the server never receives or derives client encryption/decryption keys;
- clients are authenticated and authorized before metadata/ciphertext access;
- all sensitive operations are auditable.

## Closed in the repository

- Metadata-only vault API.
- Opaque secret blob storage.
- Client authorization grants.
- mTLS client identity boundary.
- Basic audit event recording.
- PostgreSQL-compatible storage path.
- Go and Python SDK baseline.
- Admin/operator CLI baseline.
- Health/readiness/status endpoints.
- Test coverage for core executable packages.

## Security boundary

Custodia is not a key directory and not a decryption service.

The server may store:

- encrypted secret blobs;
- metadata;
- recipient envelopes;
- grants and audit records.

The server must not store or expose:

- plaintext secrets;
- client decrypt keys;
- client encryption key-directory material;
- server-side unwrap/decrypt capability for customer data.

## Verification gates

Run:

```bash
go test -p=1 -timeout 60s ./...
go build ./cmd/custodia-server ./cmd/vault-admin ./cmd/custodia-signer
python3 -m py_compile clients/python/custodia_client/__init__.py
```

Expected result: all packages with executable project logic report `ok`, and the three Go binaries build.

## External dependencies

Phase 1 does not require external production HSM, WORM, HA database, SIEM or formal verification evidence. Those belong to later phases.

## Closure statement

Phase 1 is closed at repository level when tests/builds pass and the crypto boundary remains metadata-only.
