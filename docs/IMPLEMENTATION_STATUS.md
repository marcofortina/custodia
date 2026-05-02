# Implementation status

## Implemented

- Phase 1 REST vault primitives.
- mTLS identity extraction.
- Opaque ciphertext/envelope storage contract.
- Secret access grants and future revocation.
- Strict permission bitmask validation for read/write/share grants.
- Hash-chained audit events for successful and failed auth/API operations.
- PostgreSQL schema contract and in-memory executable store.
- Valkey-compatible rate limiting.
- Minimal admin CLI for API-backed metadata operations.
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
