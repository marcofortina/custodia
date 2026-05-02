# Custodia

Custodia is a REST vault for encrypted secrets. The server authenticates clients with mTLS, authorizes access, stores opaque encrypted blobs and returns only the caller's opaque envelope. Encryption, decryption, key discovery, key rotation and key trust stay outside the server.

## What is implemented in this bootstrap

- Go vault server with TLS 1.3 / mTLS support.
- Client identity extraction from certificate SAN/CN.
- REST API for encrypted secret create/read/delete/share/new-version.
- Admin API/CLI for client metadata create/list/revoke.
- Pending grant request/activation workflow: admins can request access, but a client with `share` must upload the target envelope.
- Per-version access grants with `read`, `write`, `share` bitmask.
- Configurable recipient-envelope cap for create/new-version requests, defaulting to 100.
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
  "ciphertext": "Y2lwaGVydGV4dA==",
  "crypto_metadata": { "format": "client-defined" },
  "envelopes": [
    { "client_id": "client_alice", "envelope": "ZW52ZWxvcGUtZm9yLWFsaWNl" }
  ],
  "permissions": 7
}
```

The server validates authorization, the configured envelope-count cap and base64 transport syntax, then stores the strings as opaque transport data. It does not interpret the cryptographic content.

## Admin client metadata

```bash
vault-admin client create --client-id client_bob --mtls-subject client_bob
vault-admin client list
vault-admin client revoke --client-id client_bob --reason compromised
vault-admin access grant-request --secret-id SECRET --client-id client_bob --permissions read
vault-admin access activate --secret-id SECRET --client-id client_bob --envelope-file bob.envelope
```

Client creation registers metadata only. Certificate issuance/signing remains outside the vault server and belongs to the dedicated CA/signing service described by the design.
