# Custodia

Custodia is a REST vault for encrypted secrets. The server authenticates clients with mTLS, authorizes access, stores opaque encrypted blobs and returns only the caller's opaque envelope. Encryption, decryption, key discovery, key rotation and key trust stay outside the server.

## What is implemented in this bootstrap

- Go vault server with TLS 1.3 / mTLS support and optional client CRL rejection.
- Client identity extraction from certificate SAN/CN.
- REST API for encrypted secret create/read/delete/share/new-version plus metadata-only secret listing.
- Admin API/CLI for client metadata create/list/revoke.
- Pending grant request/activation workflow: admins can request access, but a client with `share` must upload the target envelope.
- Per-version access grants with `read`, `write`, `share` bitmask and optional future `expires_at`.
- Configurable recipient-envelope cap for create/new-version requests, defaulting to 100.
- Future revocation semantics: revoked grants stop future reads; already downloaded material is not invalidated.
- PostgreSQL-compatible schema contract plus optional `pgx` store implementation behind the `postgres` build tag.
- In-memory store for local development and tests.
- Hash-chained audit event model with admin audit listing and verification API/CLI.
- Memory and Valkey-compatible rate limiter backends with readiness checks.
- Minimal admin CLI for metadata operations exposed by the API.
- Minimal Go and Python client libraries that only transport ciphertext and opaque envelopes; the Go client includes access workflow helpers.
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

The development mode uses the in-memory store and insecure HTTP only when `CUSTODIA_DEV_INSECURE_HTTP=true` is set. Production must use `CUSTODIA_TLS_CERT_FILE`, `CUSTODIA_TLS_KEY_FILE` and `CUSTODIA_CLIENT_CA_FILE`. Set `CUSTODIA_CLIENT_CRL_FILE` to a PEM CRL signed by the configured client CA to fail closed on revoked client certificate serials.

## Build metadata

Release builds can stamp version, commit and date into both server and CLI binaries. The values are exposed through `GET /v1/status`, `/web/status` and `vault-admin version`. See `docs/BUILD_METADATA.md`.

## PostgreSQL store

The default build keeps the project standard-library-only for local tests. To enable the real PostgreSQL store, add the driver dependency and build with the explicit tag:

```bash
go get github.com/jackc/pgx/v5
go test -tags postgres ./...
go build -tags postgres ./cmd/custodia-server
make build-postgres
```

Then configure:

```bash
CUSTODIA_STORE_BACKEND=postgres
CUSTODIA_DATABASE_URL=postgres://custodia:secret@127.0.0.1:5432/custodia?sslmode=require
```

Run `migrations/postgres/001_init.sql` before starting the server. Container builds can enable the optional store with `CUSTODIA_GO_BUILD_TAGS=postgres docker compose build custodia` after the `pgx/v5` dependency is present in `go.mod`. The store persists only opaque ciphertext/envelope bytes and metadata; it does not add any server-side cryptographic key handling.

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

The server validates authorization, the configured envelope-count cap and base64 transport syntax, then stores opaque transport data. It does not interpret the cryptographic content. Permission bitmasks must be non-zero combinations of `share`, `write` and `read`; the PostgreSQL schema enforces the same non-zero range guardrail.

## Admin client metadata

```bash
vault-admin client create --client-id client_bob --mtls-subject client_bob
vault-admin client list
vault-admin client revoke --client-id client_bob --reason compromised
vault-admin access grant-request --secret-id SECRET --client-id client_bob --permissions read
vault-admin audit list --limit 100
vault-admin audit verify --limit 500
vault-admin access activate --secret-id SECRET --client-id client_bob --envelope-file bob.envelope
```

Client creation registers metadata only. Certificate issuance/signing remains outside the vault server and belongs to the dedicated CA/signing service described by the design.

## Web metadata console

The admin web console is intentionally metadata-only. It requires an admin mTLS identity and never renders ciphertext, envelopes, plaintext, or key material. See `docs/WEB_CONSOLE.md` for the current page map and security boundary.

## HTTP timeout guardrails

The server has bounded HTTP timeouts by default: read/write 15s, idle 60s and graceful shutdown 10s. Override with `CUSTODIA_HTTP_READ_TIMEOUT_SECONDS`, `CUSTODIA_HTTP_WRITE_TIMEOUT_SECONDS`, `CUSTODIA_HTTP_IDLE_TIMEOUT_SECONDS` and `CUSTODIA_SHUTDOWN_TIMEOUT_SECONDS`.


### PostgreSQL integration tests

The default test suite does not require external services. To exercise the optional PostgreSQL store, install the `postgres` build-tag dependencies and provide a disposable database URL:

```bash
go get github.com/jackc/pgx/v5
TEST_CUSTODIA_POSTGRES_URL=postgres://user:pass@localhost:5432/custodia_test?sslmode=disable go test -tags postgres ./internal/store
```


### Optional PostgreSQL integration check

The default test target is dependency-free. To verify the optional PostgreSQL store, provide a live test database and run:

```bash
TEST_CUSTODIA_POSTGRES_URL=postgres://user:pass@localhost:5432/custodia_test?sslmode=disable make test-postgres
```
