# Custodia

Custodia is a REST vault for encrypted secrets. The server authenticates clients with mTLS, authorizes access, stores opaque encrypted blobs and returns only the caller's opaque envelope. Encryption, decryption, key discovery, key rotation and key trust stay outside the server.

## What is implemented in this bootstrap

- Go vault server with TLS 1.3 / mTLS support.
- Client identity extraction from certificate SAN/CN.
- REST API for encrypted secret create/read/delete/share/new-version.
- Per-version access grants with `read`, `write`, `share` bitmask.
- Future revocation semantics: revoked grants stop future reads; already downloaded material is not invalidated.
- PostgreSQL-compatible schema and store.
- In-memory store for local development and tests.
- Hash-chained audit event model.
- Memory and Valkey-compatible rate limiter backends.
- Minimal admin CLI for metadata operations exposed by the API.
- Minimal Go and Python client libraries that only transport ciphertext and opaque envelopes.
- Docker, Compose and Helm skeletons.

## What is deliberately not implemented server-side

- No plaintext handling.
- No DEK/wrapped-DEK handling.
- No public-key directory.
- No server-side cryptographic key resolution.
- No server-side application decryption.

## Local development

```bash
cp .env.example .env
make test
make run-dev
```

The development mode uses the in-memory store and insecure HTTP only when `CUSTODIA_DEV_INSECURE_HTTP=true` is set. Production must use `CUSTODIA_TLS_CERT_FILE`, `CUSTODIA_TLS_KEY_FILE` and `CUSTODIA_CLIENT_CA_FILE`.

## API permissions

```text
share = 1
write = 2
read  = 4
all   = 7
```

## Example encrypted secret payload

```json
{
  "name": "db_prod_password",
  "ciphertext": "base64-client-ciphertext",
  "crypto_metadata": { "format": "client-defined" },
  "envelopes": [
    { "client_id": "client_alice", "envelope": "base64-client-envelope" }
  ],
  "permissions": 7
}
```

The server validates authorization and stores the strings as opaque transport data. It does not interpret the cryptographic content.
