# Implementation status

## Implemented

- Phase 1 REST vault primitives, including metadata-only secret listing.
- mTLS identity extraction.
- Optional client CRL loading with trusted-issuer signature verification and fail-closed TLS rejection for revoked serials.
- Opaque ciphertext/envelope storage contract.
- Secret access grants, optional future expiration and future revocation.
- Strong-revocation versioning supersedes older active versions and cancels pending grants for superseded versions.
- Strict permission bitmask validation for read/write/share grants.
- Base64 transport validation for ciphertext/envelope blobs and duplicate recipient rejection.
- Strict JSON transport guardrails: `application/json` content type, 1 MiB body cap and trailing-payload rejection.
- Default HTTP security headers for API and metadata-only web responses.
- Configurable bounded HTTP read/write/idle/shutdown timeouts.
- Configurable recipient-envelope cap with default 100 and HTTP 413 rejection on create/new-version overflow.
- Hash-chained audit events for successful and failed auth/API operations, with admin-only listing and verification API/CLI.
- PostgreSQL schema contract, in-memory executable store and optional `pgx` PostgreSQL store behind the `postgres` build tag.
- Idempotent bootstrap client registration for all configured stores.
- Valkey-compatible rate limiting with `/ready` health checks.
- Minimal admin CLI for API-backed client metadata create/list/revoke and access revoke operations.
- Minimal Go/Python clients, with Go and Python helpers for secret metadata and access grant workflows.
- Docker, Compose and Helm deployment skeletons.

## Not claimed as complete production implementation

The repository contains an executable standard-library baseline and deployable building blocks. A real production implementation still needs environment-specific work:

- real CA/signing service backed by TPM/HSM;
- CRL distribution/refresh automation and OCSP stapling;
- production PostgreSQL/CockroachDB topology, migrations automation and PostgreSQL integration tests against a live database;
- Valkey cluster with mTLS;
- load balancer TLS pass-through configuration;
- web UI MFA/passkey implementation beyond the metadata-only placeholder;
- formal verification and WORM/SIEM integration.

These are explicitly operational components in the analysis and cannot be truthfully completed as local source code only.

## Patch 008 - pending grant activation

- Added admin-only pending access grant requests.
- Added envelope-only access activation by an already authorized client with `share`.
- Added CLI commands for `access grant-request` and `access activate`.
- Added PostgreSQL schema contract for `secret_access_requests`.

## Patch 009 - strong revocation version superseding

- New client-side secret versions now retire older active versions for future server-side operations.
- Pending grants tied to retired versions are cancelled.
- Added store and API tests for old-version share/activation rejection.

## Patch 010 - client CRL enforcement

- Added optional `CUSTODIA_CLIENT_CRL_FILE` support.
- CRLs are accepted only when signed by the configured client CA.
- Revoked client certificate serials are rejected in the TLS verification callback before API authz.

## Patch 011 - PostgreSQL permission schema guardrail

- Aligned `secret_access.permissions` with runtime validation by rejecting `0` at the database level too.
- Added a migration contract test to keep `secret_access` and pending grant permissions non-zero.


## Patch 012 - audit event listing

- Added admin-only `GET /v1/audit-events` with bounded `limit`.
- Added `vault-admin audit list`.
- Added memory-store list support while preserving immutable hash-chain fields in responses.


## Patch 013 - access expiration guardrails

- Added optional `expires_at` support to create/share/new-version/pending grant requests.
- Rejected past expirations instead of storing already-expired access.
- Preserved pending grant expiration through activation.
- Updated PostgreSQL schema contract for pending access requests.


## Patch 014 - metadata-only secret listing

- Added `GET /v1/secrets` for caller-visible secret metadata.
- Kept ciphertext/envelope material out of list responses.
- Added Go client `ListSecrets` helper.


## Patch 015 - rate limiter readiness

- Added optional rate-limiter health checks to `/ready`.
- Added Valkey `PING` readiness support without adding external dependencies.
- Kept `/health` lightweight and `/ready` dependency-aware.


## Patch 016 - Go client access workflow helpers

- Added Go client helpers for pending grant request, activation and access revoke.
- Escaped dynamic URL path segments in the Go client to avoid malformed paths when ids contain reserved characters.
- Added client-side tests for documented access workflow routes.


## Patch 017 - optional PostgreSQL store

- Added a real PostgreSQL implementation behind the explicit `postgres` build tag.
- Kept the default build dependency-free so `go test ./...` continues to work offline.
- Implemented client lifecycle, secret CRUD/list, sharing, pending grant activation, strong-revocation versioning and audit hash chaining against PostgreSQL.
- Stored ciphertext/envelopes as opaque `BYTEA` decoded from API base64 transport strings, without interpreting cryptographic content.

## Patch 018 - strict JSON transport guardrails

- Required `Content-Type: application/json` for JSON request bodies.
- Capped JSON bodies at 1 MiB before decoding.
- Rejected trailing JSON payloads after the first decoded value.
- Added API tests for unsupported media type, trailing payloads and oversized bodies.

## Patch 019 - default HTTP security headers

- Added `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
- Added a restrictive default Content Security Policy for API and placeholder web responses.
- Added a regression test so security headers stay present on lightweight health responses.

## Patch 020 - persistent-store bootstrap clients

- Applied `CUSTODIA_BOOTSTRAP_CLIENTS` to both in-memory and configured persistent stores.
- Made bootstrap idempotent by ignoring already-existing client records.
- Added a server bootstrap regression test.

## Patch 021 - Python client access workflow helpers

- Added Python helpers for metadata-only secret listing, pending grant request, activation and access revocation.
- URL-escaped dynamic path segments in the Python client.
- Documented that Python payloads remain opaque/base64 transport values and no key discovery happens through Custodia.

## Patch 022 - bounded HTTP server timeouts

- Added configurable read, write, idle and graceful-shutdown timeouts.
- Kept safe defaults for invalid or missing environment values.
- Added config regression tests for timeout parsing and defaults.

## Patch 023 - audit chain verification

- Added `GET /v1/audit-events/verify` for admin-only hash-chain verification.
- Added `vault-admin audit verify`.
- Added unit/API guardrails for tampered chains and invalid limits.


## Patch 024 - web user metadata schema

- Added PostgreSQL `web_users` and `web_user_mappings` schema for the future metadata-only Web UI.
- Kept the crypto boundary intact: no server-side encryption keys, public-key directory or secret plaintext fields.
- Added schema guardrails for role constraints and client mappings.

## Patch 025 - reloadable client CRL verifier

- Replaced static CRL snapshots with a reload-on-change verifier for configured client CRLs.
- Kept fail-closed behavior when the changed CRL is unreadable, invalid or not signed by the trusted client CA.
- Added regression coverage for revocation updates without process restart.


## Patch 026 - PostgreSQL integration test scaffold

- Added an opt-in `postgres` build-tag integration test for the real PostgreSQL store.
- The default `go test ./...` remains external-service free.
- The test applies the project migration and verifies opaque create/share/read lifecycle against PostgreSQL.
