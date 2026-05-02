# Implementation status

## Implemented

- Phase 1 REST vault primitives.
- mTLS identity extraction.
- Opaque ciphertext/envelope storage contract.
- Secret access grants and future revocation.
- Strong-revocation versioning supersedes older active versions and cancels pending grants for superseded versions.
- Strict permission bitmask validation for read/write/share grants.
- Base64 transport validation for ciphertext/envelope blobs and duplicate recipient rejection.
- Configurable recipient-envelope cap with default 100 and HTTP 413 rejection on create/new-version overflow.
- Hash-chained audit events for successful and failed auth/API operations.
- PostgreSQL schema contract and in-memory executable store.
- Valkey-compatible rate limiting.
- Minimal admin CLI for API-backed client metadata create/list/revoke and access revoke operations.
- Minimal Go/Python clients.
- Docker, Compose and Helm deployment skeletons.

## Not claimed as complete production implementation

The repository contains an executable standard-library baseline and deployable building blocks. A real production implementation still needs environment-specific work:

- real CA/signing service backed by TPM/HSM;
- CRL/OCSP distribution and fail-closed policy;
- real CockroachDB/PostgreSQL store wiring, then CockroachDB multi-region or PostgreSQL Patroni topology;
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
