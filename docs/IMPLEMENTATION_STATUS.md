# Implementation status

## Current status after patch 625

- Phase 1 is closed at repository level.
- Phase 2 is closed at repository level: mTLS lifecycle, strong-revocation versioning, Valkey-compatible rate limiting, Go/Python SDK helpers, metadata-only web console, TOTP MFA and the passkey/WebAuthn boundary through external assertion verification are implemented.
- Phase 3 is closed as a repository baseline: Helm/Kubernetes deployment metadata, HA/DR runbooks, diagnostics, audit export integrity, audit archive/shipment helpers, S3/Object Lock shipment, k3s/CockroachDB rehearsal, dedicated signer service, PKCS#11/SoftHSM bridge, CRL distribution/revocation responder, formal verification artifacts, production readiness gates and external evidence gates are implemented.
- The cryptographic boundary remains unchanged: Custodia stores and authorizes opaque ciphertext, crypto metadata and recipient envelopes, but never decrypts, unwraps keys or publishes client encryption credential keys.
- Phase 4 is closed at repository level: Lite/full/custom profiles, shared YAML config, build-tagged SQLite Lite store, Lite packaging, local CA bootstrap/passphrase support, SQLite backup, Lite-to-Full readiness checks and Phase 4 closure documentation are implemented.
- Production Fort Knox completeness still depends on external evidence: real HSM/PKCS#11/TPM, WORM/object-lock storage, database HA, Valkey HA, zero-trust network controls, penetration testing, revocation drills, audited WebAuthn verifier deployment and formal verification execution in the target environment.


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
- Admin-protected metadata-only web console pages for status, clients, access requests and audit summaries.
- Build metadata propagation through status API, web status and `vault-admin version`.
- Custodia Lite profile with shared YAML config, SQLite build-tag store, local CA bootstrap, CA passphrase file support, backup helper and Lite-to-Full readiness checks.

## Not claimed as local-only source-code guarantees

The repository contains executable code, tests, runbooks, release gates and evidence gates for the Fort Knox design. The following items are intentionally treated as operator-controlled production evidence instead of pretending they can be proven by local source code alone:

- real HSM/PKCS#11/TPM-backed CA key custody; the file provider remains a development/bootstrap path and the PKCS#11 provider fails closed unless implemented for the deployment;
- external WORM/object-lock storage and SIEM retention policy enforcement;
- real PostgreSQL/CockroachDB/managed database HA topology and failover evidence;
- Valkey cluster and production network policy evidence;
- CRL/OCSP revocation distribution drills in the target environment;
- penetration-test evidence and release artifact evidence;
- TLC/formal verification execution evidence in CI or a dedicated verification pipeline;
- a production audited WebAuthn assertion verifier command when passkeys are enabled; the repository provides the fail-closed adapter and pre-signature validation boundary, while the cryptographic verifier itself remains operator-provided evidence. TOTP-backed metadata-only web MFA is implemented.

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
- Kept the crypto boundary intact: no server-side encryption keys, credential-key directory or secret plaintext fields.
- Added schema guardrails for role constraints and client mappings.

## Patch 025 - reloadable client CRL verifier

- Replaced static CRL snapshots with a reload-on-change verifier for configured client CRLs.
- Kept fail-closed behavior when the changed CRL is unreadable, invalid or not signed by the trusted client CA.
- Added regression coverage for revocation updates without process restart.


## Patch 026 - PostgreSQL integration test scaffold

- Added an opt-in `postgres` build-tag integration test for the real PostgreSQL store.
- The default `go test ./...` remains external-service free.
- The test applies the project migration and verifies opaque create/share/read lifecycle against PostgreSQL.


## Patch 027 - admin-protected web console shell

- Protected `/web/` with the existing mTLS admin guard instead of leaving the console shell public.
- Kept the Web UI metadata-only: no ciphertext reads, envelopes, plaintext or key material are exposed through the shell.
- Added regression coverage for missing certificate, non-admin and admin access.

- Optional `CUSTODIA_HEALTH_ADDR` is configured but only used after the dedicated health listener patch.

## Patch 192 - audit export SHA-256 header

- Added `X-Custodia-Audit-Export-SHA256` to JSONL audit exports.
- The digest is computed over the exact response body bytes before they are written to the client.
- Kept the endpoint metadata-only and independent from secret ciphertext/envelopes.

## Patch 193 - audit export event count header

- Added `X-Custodia-Audit-Export-Events` to expose the number of exported events.
- Preserved bounded export semantics and existing audit export filters.

## Patch 194 - audit export integrity documentation

- Documented offline verification of audit JSONL exports.
- Clarified the distinction between export artifact hashing and audit hash-chain verification.

## Patch 195 - audit export integrity README link

- Linked the audit export integrity guide from the project README.

## Patch 197 - admin build version endpoint

- Added admin-only `GET /v1/version`.
- The endpoint returns build metadata and audits `version.read`.

## Patch 198 - vault-admin server version command

- Added `vault-admin version server` to read build metadata from the authenticated API.
- Kept the existing local `vault-admin version` command unchanged.

## Patch 199 - Go client version helper

- Added `Client.Version()` to read server build metadata.

## Patch 200 - Python client version helper

- Added `CustodiaClient.version()` and documented it in the Python client README.

## Patch 202 - bounded web audit listings

- Added a bounded `limit` query parameter to `/web/audit`.
- Invalid web audit limits are rejected and audited.

## Patch 203 - web audit filters

- Reused API audit filters on the metadata-only web audit page.
- Invalid outcome/action/resource filters are rejected before rendering.

## Patch 204 - bounded web audit verification

- Added bounded `limit` support to `/web/audit/verify`.

## Patch 205 - web client active filter

- Added `active=true|false` filtering to the metadata-only clients page.

## Patch 206 - bounded web access request listings

- Added bounded `limit` support to `/web/access-requests`.

## Patch 207 - web access request status filter

- Added pending-grant status filtering to the web access request page.

## Patch 208 - web access request secret filter

- Added `secret_id` filtering with UUID validation to the web access request page.

## Patch 209 - web access request target filter

- Added target client filtering to the web access request page.

## Patch 210 - web access request requester filter

- Added requester client filtering to the web access request page.

- Request correlation is implemented through `X-Request-ID` response headers and audit metadata enrichment.

- Runtime diagnostics are implemented through admin API `/v1/diagnostics`, web `/web/diagnostics`, Go/Python helpers and `vault-admin diagnostics read`.


## Operational documentation

Implemented runbooks now cover production readiness, backup/restore, disaster recovery, CA signing service boundaries, CRL/OCSP operations, SIEM/WORM audit export and formal verification scope. These documents do not claim that TPM/HSM signing, OCSP stapling, WORM storage or formal proofs are implemented in code yet.

## Patch 232 - client certificate signing package

- Added an internal client certificate signer that validates CSR signatures, client-id identity binding and certificate TTL bounds.
- The signer issues client-auth certificates only and does not handle application encryption keys.

## Patch 234 - dedicated certificate signer service

- Added `custodia-signer`, a separate admin-only service for CSR signing.
- The vault API process still does not load or use CA private key material.

## Patch 236 - Docker signer binary

- The Docker image now includes `custodia-signer` alongside `custodia-server` and `vault-admin`.

## Patch 237 - signer build targets

- Local build targets now compile `custodia-signer`.
- A development signer target is available for isolated local workflows.

## Patch 239 - implemented signer service docs

- Documented the implemented signer API boundary, production mTLS requirements and remaining TPM/HSM gap.

## Patch 242 - client CSR generation helper

- Added local ECDSA client key and CSR generation helper.
- The generated CSR binds the `client_id` into CN and DNS SAN for mTLS identity extraction.

## Patch 244 - vault-admin client CSR command

- Added `vault-admin client csr` for local key/CSR generation.
- Private keys are written locally with exclusive creation and restrictive permissions.

## Patch 246 - vault-admin certificate sign command

- Added `vault-admin certificate sign` to submit CSRs to the dedicated signer service.
- The command targets `custodia-signer`, not the vault API server.

## Patch 248 - certificate lifecycle guide

- Documented the metadata registration, CSR generation, signer submission and API mTLS usage flow.

## Patch 249 - compose signer profile

- Added an optional Compose signer profile for local development workflows.


## Patch 252 - TOTP web authentication helper

- Added RFC 6238-compatible TOTP generation and verification helpers.
- Kept TOTP handling scoped to web authentication metadata, not secret encryption or vault payload handling.

## Patch 253 - TOTP web authentication tests

- Added tests for valid TOTP codes, invalid codes and bounded verification windows.
- Covered deterministic time-window behavior for web MFA validation.

## Patch 254 - signed web session helper

- Added signed web session token helpers for metadata-only web authentication.
- Session material is integrity-protected and separate from vault secret payloads.

## Patch 255 - signed web session tests

- Added tests for valid sessions, tampered sessions and expired sessions.
- Added guardrails for session signature and expiry handling.

## Patch 256 - web MFA and passkey configuration

- Added web authentication configuration for MFA/passkey enablement and session signing.
- Documented environment-driven behavior without changing API crypto boundaries.

## Patch 257 - web authentication option wiring

- Wired web authentication options into the HTTP server configuration.
- Kept default behavior explicit so deployments can require MFA before exposing metadata-only web pages.

## Patch 258 - web TOTP login/logout handlers

- Added `/web/login` and `/web/logout` handlers.
- Login establishes a signed web session after admin mTLS plus valid TOTP.
- Logout clears the signed web session cookie.

## Patch 259 - require MFA session for web console

- Protected metadata-only web console pages with the signed MFA session gate.
- Preserved admin mTLS as the outer identity/authz boundary.

## Patch 260 - web TOTP MFA session tests

- Added tests for TOTP-backed login/session behavior.
- Added regression coverage that protected web pages require a valid web session when MFA is enabled.

## Patch 261 - web TOTP MFA documentation

- Documented TOTP MFA setup, required environment variables and operational boundary.
- Clarified that web MFA does not introduce plaintext, ciphertext, envelope or key-material rendering.

## Patch 262 - passkey challenge options helper

- Added passkey/WebAuthn challenge option generation helpers.
- Kept the implementation to server-side challenge/options metadata, not assertion verification.

## Patch 263 - passkey challenge options tests

- Added tests for passkey challenge/options generation.
- Covered bounded metadata output without storing or exposing secret material.

## Patch 264 - web passkey options endpoints

- Added metadata-only passkey registration/authentication options endpoints.
- Endpoints return challenge/options metadata and stay behind the configured web auth boundary.

## Patch 265 - web passkey options endpoint tests

- Added endpoint tests for passkey options behavior.
- Verified that disabled passkey support is rejected and enabled support emits only metadata challenge options.

## Patch 266 - web MFA environment example

- Documented web MFA/passkey environment variables in `.env.example`.
- Kept production defaults explicit so operators do not accidentally expose unauthenticated metadata pages.

## Patch 267 - web passkey support documentation

- Documented the passkey/WebAuthn support boundary.
- Explicitly stated that full assertion verification remains future hardening and TOTP must stay enabled until that verifier exists.

## Patch 268 - web auth status metadata

- Surfaced web MFA/passkey configuration state through status metadata.
- Added status visibility without exposing secrets, envelopes, ciphertext or client-side key material.

## Phase 2 status

Phase 2 is now functionally closed for the server baseline: mTLS rotation lifecycle, strong-revocation versioning, Valkey-compatible rate limiting, Go/Python SDK helpers, metadata-only web console and TOTP MFA are implemented. Passkey support is present as server-side challenge/options integration and documented boundary; production deployments should keep TOTP enabled until full assertion verification is completed.

## Patch 272 - signer request ID correlation

- Added `X-Request-ID` propagation/generation to `custodia-signer`.

## Patch 274 - signer audit recorder

- Added JSONL signer audit recorder for certificate signing workflows.

## Patch 277 - audited signer certificate requests

- Signer certificate signing attempts now record success/failure audit events with actor, client id and request id.

## Patch 280 - signer audit trail documentation

- Documented signer JSONL audit trail and SIEM/WORM forwarding expectations.

## Patch 282 - Go audit export metadata helper

- Added Go client support for returning JSONL export body plus SHA-256 and event-count headers.

## Patch 284 - Python audit export metadata helper

- Added Python client support for returning JSONL export body plus SHA-256 and event-count headers.

## Patch 287 - vault-admin audit export artifacts

- `vault-admin audit export` can now write JSONL body, SHA-256 header and event-count header to separate files.

## Patch 290 - audit artifact helper documentation

- Documented SDK and CLI helpers for retaining audit export artifacts with integrity metadata.

## Completeness note

This file is intentionally a functional ledger, not a one-section-per-patch changelog for all 271 patches. Early work is tracked patch-by-patch where useful, while high-volume later work may still be grouped by implemented capability. The Phase 2 web-authentication closure patches are listed individually because they define the MFA/passkey security boundary.

Coverage from patch 1 through patch 271 is represented by these implemented surfaces:

- project bootstrap, Go module, standard-library HTTP server, model validation and in-memory store baseline;
- mTLS identity extraction, client lifecycle, admin bootstrap and optional CRL enforcement;
- opaque secret CRUD, metadata-only listing, access grants, pending grant activation and strong-revocation versioning;
- strict JSON/base64/permission/body-size/timeout guardrails;
- hash-chained audit, audit listing/filtering/verification/export and export integrity headers;
- PostgreSQL schema contract and optional `postgres` build-tag store;
- Valkey-compatible rate limiting and readiness checks;
- `vault-admin` client/access/audit/status/version/diagnostics/CSR/certificate lifecycle helpers;
- Go/Python SDK helpers for secrets, grants, audit, status, diagnostics and version reads;
- Docker/Compose/Helm deployment scaffolding and production/DR/backup/security runbooks;
- dedicated `custodia-signer` process plus client certificate lifecycle tooling;
- metadata-only web console protected by admin mTLS and TOTP web sessions;
- passkey/WebAuthn challenge/options endpoints without claiming full assertion verification.

Any future implementation patch must update this file or an explicitly linked status/runbook document in the same patch series.

## Patch 292 - signer key provider abstraction

- Added explicit signer CA key provider abstraction.
- File-backed CA keys remain the development/bootstrap provider.
- PKCS#11 is reserved and fails closed instead of falling back silently.

## Patch 294 - signer key provider config

- `custodia-signer` now reads `CUSTODIA_SIGNER_KEY_PROVIDER` and routes signer initialization through the provider abstraction.

## Patch 296 - signer key provider environment

- Documented `CUSTODIA_SIGNER_KEY_PROVIDER=file` in `.env.example`.

## Patch 297 - signer key provider boundary docs

- Documented file-backed vs reserved PKCS#11 provider behavior and fail-closed production boundary.

## Patch 301 - audit artifact verification package

- Added verification for audit JSONL export body, SHA-256 digest sidecar and event-count sidecar.
- The verifier checks the exact exported artifact instead of re-querying live audit state.

## Patch 303 - vault-admin audit export verifier

- Added `vault-admin audit verify-export` for local/offline audit export artifact verification.
- The command emits a JSON verification result and returns an error on digest or event-count mismatch.

## Patch 305 - audit export verifier documentation

- Documented the `vault-admin audit verify-export` workflow for JSONL, `.sha256` and `.events` artifacts.

## Patch 311 - client CRL status metadata

- Added CRL status metadata parsing for trusted client CRLs.
- Status includes issuer, update window and revoked entry count without exposing certificate private material.

## Patch 313 - admin revocation status endpoint

- Added admin-only `GET /v1/revocation/status` to monitor configured client CRL health.
- Added `vault-admin revocation status` plus Go/Python SDK helpers.

## Patch 318 - revocation monitoring documentation

- Documented revocation status monitoring and production checklist expectations.
- Kept OCSP as a remaining production gap rather than claiming it complete.

## Patch 328 - audit archive production checklist

- Production readiness now requires `vault-admin audit archive-export` before WORM/SIEM ingestion.

## Patch 329 - backup restore audit archive manifest

- Backup/restore guidance now requires checking the audit archive manifest produced by the verifier/archive workflow.


## Patch 331 - audit archive shipper package

- Added verified archive shipment support for copying audit bundles to a sink directory.
- The shipper re-verifies JSONL digest and event count before copying.

## Patch 333 - vault-admin audit ship-archive

- Added `vault-admin audit ship-archive` to write sink-ready audit shipments with `shipment.json`.

## Patch 335 - audit shipment runbook

- Documented the audit archive shipment workflow and the external WORM boundary.

## Patch 337 - SIEM/WORM shipment step

- Updated SIEM/WORM guidance to require shipment manifests before external ingestion.


## Patch 341 - deployment HA metadata config

- Added deployment-mode, database HA target and audit shipment sink configuration.

## Patch 342 - deployment HA status metadata

- Surfaced deployment HA metadata in admin operational status for monitoring and runbook checks.

## Patch 344 - Helm deployment HA metadata

- Wired deployment HA metadata through the Helm ConfigMap and values.

## Patch 347 - database HA runbook

- Documented CockroachDB and PostgreSQL Patroni/managed HA deployment boundaries.
- Clarified that DB HA is an external control-plane responsibility, not embedded in the vault API process.

## Patch 351 - CRL distribution loader

- Added a small CRL distribution loader that validates PEM CRL files before serving or shipping them.

## Patch 353 - signer CRL distribution endpoint

- Added `GET /v1/crl.pem` to `custodia-signer` for configured PEM CRL publication.
- The endpoint returns CRL metadata headers and audits read success/failure.

## Patch 355 - vault-admin CRL fetch command

- Added `vault-admin revocation fetch-crl --out FILE` to download signer-published CRLs into exclusive output files.

## Patch 359 - signer CRL distribution documentation

- Documented the CRL distribution endpoint and clarified that full OCSP remains a separate hardening step.

## Patch 361 - executable access invariant model

- Added a small executable access-control model for client activation, grants, client revocation and strong secret-version revocation.

## Patch 363 - TLA access-control model

- Added `formal/CustodiaAccess.tla` and bounded TLC configuration for server-side authorization invariants.

## Patch 365 - formal verification check script

- Added `scripts/check-formal.sh` and `make formal-check` integration for local TLC checks.

## Patch 367 - formal verification scope update

- Updated formal-verification documentation to distinguish implemented server-side artifacts from out-of-scope client cryptography and WebAuthn proof work.


## Patch 371 - production readiness checker

- Added a production readiness checker for the deployment environment contract.
- The checker rejects unsafe development defaults and missing Fort Knox production dependencies.

## Patch 373 - vault-admin production readiness command

- Added `vault-admin production check --env-file FILE`.
- The command fails on critical production-readiness findings.

## Patch 375 - production readiness make target

- Added `make production-check` with `CUSTODIA_PRODUCTION_ENV_FILE`.

## Phase 3 closure status

- Phase 3 is closed as a code, runbook and deployment-readiness baseline.
- Production 101% still depends on external systems that cannot be proven inside this repository: real PKCS#11/HSM hardware, actual WORM/SIEM retention, and real HA database topology.

## Patch 381 - release check script

- Added `scripts/release-check.sh` to run Go tests, builds, Python client syntax checks and formal verification when TLC is installed.

## Patch 382 - release check Make target

- Added `make release-check` as a single local pre-release gate.

## Patch 384 - CI release check workflow

- Added a GitHub Actions workflow that runs the release check on pushes and pull requests.

## Patch 386 - production env readiness example

- Added `deploy/examples/production.env.example` with production-readiness inputs for API, signer, HA metadata and audit shipment.

## Patch 387 - production env example docs

- Documented how to use the production env example with `make production-check`.

## Patch 391 - production external evidence checker

- Added external evidence checks for HSM/PKCS#11, WORM retention, database HA, Valkey cluster, zero-trust networking, air-gapped backup, penetration testing, formal verification, revocation drills and release checks.
- Kept the checker evidence-oriented: it verifies operator evidence references without pretending to validate confidential external systems inside the repo.

## Patch 393 - vault-admin production evidence command

- Added `vault-admin production evidence-check --env-file FILE`.
- The command fails closed when any Fort Knox external evidence reference is missing.

## Patch 395 - production evidence make target

- Added `make production-evidence-check`.

## Patch 397 - production evidence guide

- Documented the external evidence gate and required evidence files.

## Patch 398 - release check evidence gate

- `scripts/release-check.sh` now runs production and external evidence gates when `CUSTODIA_PRODUCTION_ENV_FILE` is set.

## Final design-gap check after patch 400

The remaining Fort Knox items are no longer undocumented repository gaps. They are represented as external production evidence gates:

- HSM/PKCS#11/TPM attestation for CA key custody;
- WORM/object-lock retention proof for immutable audit storage;
- database HA/failover evidence;
- Valkey cluster evidence;
- zero-trust network policy evidence;
- air-gapped backup evidence;
- penetration-test evidence;
- formal verification execution evidence;
- CRL/OCSP revocation drill evidence;
- release-check evidence for the shipped commit/image.

The repository still does not claim to implement physical HSM hardware, external WORM storage, managed database clusters or third-party penetration testing. Those are operator-controlled production artifacts by design.

## Patch 401 - id package tests

- Added UUIDv4 format and uniqueness tests for `internal/id`.
- The package now reports `ok` under `go test ./...` instead of `[no test files]`.

## Patch 402 - memory rate limiter tests

- Added coverage for memory limiter allow/deny behavior, unlimited zero-limit behavior and health checks.

## Patch 403 - Valkey rate limiter protocol tests

- Added coverage for Redis/Valkey URL parsing and RESP helper behavior.
- The `internal/ratelimit` package now reports `ok` under `go test ./...` instead of `[no test files]`.

## Patch 404 - final test coverage status

- All Go packages now contain tests where they include executable project logic.
- Remaining `[no test files]` output should be treated as a regression unless the package is intentionally interface-only.

## Patch 405 - implementation status post-404 sync

- Updated the top-level implementation status from the stale post-271 wording to the current post-404 baseline.
- Clarified that Phase 3 is closed as a repository baseline while real Fort Knox production still requires external evidence for HSM/PKCS#11/TPM, WORM/Object Lock, HA databases, Valkey HA, revocation drills, penetration testing and formal verification execution.
- Replaced the older “not claimed as complete production implementation” wording with an explicit local-source-code versus production-evidence boundary.

## Patch 406 - PKCS#11 command signer provider

- Added a concrete `pkcs11` key-provider bridge that delegates certificate digest signing to `CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND`.
- The signer keeps the CA private key outside the vault API process and outside Go memory when the external command is backed by an HSM/PKCS#11 module.
- Missing command configuration still fails closed.

## Patch 407 - PKCS#11 command signer tests

- Added protocol tests for the command signer JSON request/response boundary.
- Preserved fail-closed coverage for invalid command output.

## Patch 408 - signer PKCS#11 command config

- Wired `CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND` into `custodia-signer` configuration.

## Patch 410 - production PKCS#11 command gate

- Production readiness now requires the signer PKCS#11 command when `CUSTODIA_SIGNER_KEY_PROVIDER=pkcs11`.

## Patch 412 - PKCS#11 signer bridge command

- Added `scripts/pkcs11-sign-command.sh`, an external bridge for `pkcs11-tool`/SoftHSM/HSM-backed signing.

## Patch 413 - SoftHSM development token helper

- Added `scripts/softhsm-dev-token.sh` for local SoftHSM token bootstrap.
- SoftHSM is explicitly development/test only and not production-grade.

## Patch 416 - PKCS#11 SoftHSM documentation

- Documented the PKCS#11 bridge protocol, SoftHSM workflow and production HSM evidence boundary.


## Patch 422 - S3 Object Lock audit shipper

- Added a SigV4 S3-compatible audit archive shipper that uploads verified bundles with Object Lock retention headers.
- The implementation supports MinIO/Object Lock smoke testing and production S3-compatible WORM sinks.

## Patch 424 - vault-admin S3 audit shipment command

- Added `vault-admin audit ship-archive-s3` for verified S3/Object Lock archive shipment.

## Patch 427 - MinIO Object Lock compose profile

- Added a local MinIO profile that creates an Object Lock-enabled `custodia-audit` bucket for development smoke testing.

## Patch 431 - S3 Object Lock audit shipment documentation

- Documented MinIO/S3 Object Lock audit shipment, SigV4 headers and the external storage immutability boundary.

## Patch 436 - k3s CockroachDB profile guide

- Added a k3s-friendly CockroachDB HA profile guide for repository-level database HA rehearsal.
- The guide explicitly marks the profile as lab/dev and not a managed production database replacement.

## Patch 437 - k3s CockroachDB namespace

- Added the `custodia-db` namespace manifest used by the k3s CockroachDB profile.

## Patch 438 - k3s CockroachDB services

- Added headless and public ClusterIP services for CockroachDB SQL, gossip and health access.

## Patch 439 - k3s CockroachDB StatefulSet

- Added a three-node CockroachDB StatefulSet for HA-like k3s rehearsal.
- The manifest uses insecure CockroachDB mode intentionally for local reproducibility and must be hardened for production.

## Patch 440 - k3s CockroachDB init job

- Added a Kubernetes Job that initializes the CockroachDB cluster and creates the `custodia` database/user.

## Patch 441 - k3s CockroachDB smoke script

- Added a `kubectl`-based smoke script that waits for CockroachDB readiness and runs `SELECT 1` through the SQL service.

## Patch 442 - k3s CockroachDB make targets

- Added `make k3s-cockroachdb-apply` and `make k3s-cockroachdb-smoke`.

## Patch 443 - production env k3s CockroachDB target

- Updated the production env example with a concrete CockroachDB/k3s HA database target.

## Patch 444 - k3s Custodia database secret example

- Added an example Kubernetes Secret wiring Custodia to the k3s CockroachDB SQL endpoint.

## Patch 445 - k3s Custodia Helm values example

- Added a Helm values example for running Custodia against the k3s CockroachDB profile.

## Patch 446 - k3s CockroachDB HA documentation

- Added an end-to-end guide for applying CockroachDB, wiring Custodia and documenting the production boundary.

## Patch 447 - k3s CockroachDB README link

- Linked the k3s CockroachDB HA guide from the README operational runbook list.

## Patch 448 - database HA runbook k3s rehearsal

- Added k3s CockroachDB rehearsal steps to the database HA runbook.

## Patch 449 - production checklist k3s CockroachDB gate

- Added production checklist gates for k3s CockroachDB smoke output and TLS hardening.

## Patch 450 - release check k3s CockroachDB smoke

- Added syntax checking for the k3s CockroachDB smoke script.
- Added an opt-in `CUSTODIA_RUN_K3S_COCKROACHDB_SMOKE=true` release-check path.

## Patch 452 - CRL revocation responder package

- Added a CRL-backed revocation responder package that evaluates certificate serial numbers against a parsed CRL.
- The responder returns deterministic `good` or `revoked` metadata without implementing binary OCSP.

## Patch 454 - signer revocation serial status endpoint

- Added signer endpoint `GET /v1/revocation/serial?serial_hex=<hex>`.
- The endpoint reads the configured CRL file and audits success/failure outcomes.

## Patch 456 - vault-admin revocation serial command

- Added `vault-admin revocation check-serial` for operator revocation drills against `custodia-signer`.

## Patch 458 - SDK revocation serial helpers

- Added Go and Python helpers for the CRL-backed revocation serial status endpoint.

## Patch 461 - revocation serial responder docs

- Documented the responder as JSON/CRL-backed and explicitly not a full RFC 6960 OCSP responder.

## Patch 466 - passkey challenge store

- Added an in-memory passkey challenge store with TTL, prune and consume-once semantics.

## Patch 468 - passkey client data verifier

- Added server-side validation for WebAuthn `clientDataJSON` fields that are safe to verify without credential storage: `type`, `challenge` and `origin`.

## Patch 470 - passkey challenge preverification endpoints

- Added `POST /web/passkey/register/verify` and `POST /web/passkey/authenticate/verify`.
- The endpoints consume stored challenges exactly once and reject replay or wrong-origin client data.

## Patch 472 - passkey preverification documentation

- Documented the passkey challenge preverification boundary at that milestone. Later patch blocks add credential metadata, authenticatorData validation, COSE credential-key parsing and the external assertion verifier adapter.

## Patch 476 - passkey credential metadata store

- Added an in-memory passkey credential metadata store for credential id, client id and usage timestamps.
- Kept the store metadata-only: no COSE credential key, authenticator data, attestation object or signature material is interpreted or persisted.

## Patch 478 - passkey credential metadata verifier wiring

- Registration preverification now requires and records a credential id after challenge/clientData validation.
- Authentication preverification now requires the credential id to already belong to the calling client before the challenge can be accepted.

## Patch 480 - passkey credential status count

- Operational status now reports the number of registered passkey credential metadata records.

## Patch 482 - passkey credential metadata documentation

- Documented the remaining boundary: credential metadata and anti-replay are implemented, while full WebAuthn COSE/CBOR/signature verification remains explicit future work.

## Patch 486 - passkey authenticator data parser

- Added WebAuthn authenticator data parsing for RP ID hash, flags and signature counter.
- Added sign-counter validation helper for anti-clone scaffolding.

## Patch 488 - passkey credential sign counter store

- Added signature-counter metadata to passkey credential records.
- Added `TouchWithSignCount` to reject non-increasing counters when authenticator data is supplied.

## Patch 490 - passkey authenticator data verifier wiring

- Passkey registration/authentication preverification can now parse optional base64url `authenticator_data`.
- Registration stores the parsed signature counter; authentication rejects non-increasing counters for known credentials.

## Patch 494 - passkey counter compatibility fix

- Preserved existing counters when authentication preverification omits authenticator data, avoiding artificial counter increments.

## Patch 495 - passkey authenticator data production gate

- Documented production gates for authenticator data drills and the remaining COSE/signature verification boundary.

## Patch 497 - passkey authenticator RP ID validator

- Added authenticator-data validation for RP ID hash, user-present and user-verified flags.
- This hardens the existing passkey scaffold without claiming full WebAuthn signature verification.

## Patch 499 - passkey authenticator RP ID enforcement

- Wired RP ID hash and user-verification enforcement into passkey register/authenticate preverification when authenticator data is supplied.

## Patch 501 - passkey user-verification status

- Exposed the passkey user-verification policy in operational status.

## Patch 503 - passkey authenticator validation docs

- Documented RP ID hash, user-present and user-verified enforcement and kept the COSE/signature verification boundary explicit.

## Patch 507 - passkey credential credential-key metadata store

- Added opaque COSE credential-key metadata storage to passkey credential records.
- Credential records now defensively clone stored COSE bytes before returning them.

## Patch 509 - passkey credential-key metadata verifier

- Registration preverification now requires `credential_key_cose` and stores it with the credential metadata.
- Authentication preverification now requires the credential to have stored credential-key metadata before it can succeed.

## Patch 511 - passkey credential-key storage status

- `/v1/status` now reports `web_passkey_credential_key_storage: opaque_cose`.

## Patch 513 - passkey credential-key metadata documentation

- Documented that Custodia stores opaque COSE credential-key metadata without yet parsing CBOR/COSE or verifying authenticator signatures.

## Patch 519 - passkey COSE credential-key parser

- Added a minimal COSE_Key metadata parser for passkey credential-key blobs.
- The parser accepts EC2/P-256/ES256 and RSA/RS256 metadata shapes and rejects malformed or unsupported COSE maps.

## Patch 521 - passkey COSE parser enforcement

- Registration preverification now rejects malformed or unsupported `credential_key_cose` values before credential metadata is registered.

## Patch 523 - passkey COSE parser status

- `/v1/status` now reports `web_passkey_credential_key_parser: cose_es256_rs256`.

## Patch 525 - passkey COSE parser documentation

- Documented the COSE parser boundary and clarified that authenticator signature verification remains the final full-WebAuthn boundary.

## Patch 529 - passkey assertion external verifier command

- Added an external command adapter for WebAuthn assertion verification.
- The adapter sends credential id, client id, RP ID, origin, clientDataJSON, authenticatorData, signature, COSE credential-key metadata and sign count to an operator-provided verifier.

## Patch 531 - passkey assertion verifier command config

- Added `CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND` and wired it into the web passkey authentication verifier path.

## Patch 533 - passkey external assertion enforcement

- When configured, authentication preverification now requires authenticator data and signature material and fails closed on verifier command failure.

## Patch 535 - passkey assertion verifier status

- `/v1/status` now reports `web_passkey_assertion_verifier` as `preverify_only` or `external_command`.

## Patch 537 - production check passkey assertion verifier

- Production readiness now requires `CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND` when passkeys are enabled.

## Patch 539 - passkey assertion verifier command template

- Added a fail-closed command template documenting the expected stdin/stdout contract for the external audited verifier.

## Patch 542 - passkey assertion verifier documentation

- Documented the final WebAuthn boundary: the repository validates all pre-signature inputs and delegates cryptographic assertion verification to an external audited verifier.


## Patch 546 - final post-545 documentation sync

- Updated current implementation status from the stale post-404 wording to the post-545 repository baseline.
- Clarified that WebAuthn/passkey support now includes challenge lifecycle, credential metadata, authenticator-data validation, COSE credential-key parsing and a fail-closed external assertion verifier adapter.
- Kept the final production boundary honest: the audited WebAuthn verifier implementation and external infrastructure evidence remain operator-provided, not invented inside the vault server.

## Patch 549 - phase 3 closure documentation sync

- Updated `docs/PHASE3_CLOSURE.md` to reflect the final post-545 repository baseline.
- Added explicit coverage for PKCS#11/SoftHSM, S3/Object Lock/MinIO, k3s/CockroachDB, CRL-backed revocation responder, release gates and external evidence gates.
- Clarified that SoftHSM, MinIO and k3s profiles are rehearsal tools, not production evidence replacements.

## Patch 550 - phase closure README links

- Linked `docs/PHASE1_CLOSURE.md` and `docs/PHASE2_CLOSURE.md` from the README operational runbook list.
- Moved production readiness/evidence links into the runbook list instead of leaving them under the formal-verification section.

## Patch 552 - profile-driven config loader

- Added `CUSTODIA_PROFILE=lite|full|custom` defaults to the shared config loader.
- Added flat YAML `--config` parsing support with environment-variable overrides.

## Patch 554 - custodia-server config file loading

- Wired `custodia-server --config PATH` into startup configuration loading.

## Patch 555 - shared YAML signer config keys

- Allowed the shared YAML file to carry signer-related configuration keys without introducing a second config vocabulary.

## Patch 557 - profile-aware production checks

- Made `vault-admin production check` profile-aware.
- Lite checks now accept SQLite/memory/file-signer defaults while still enforcing mTLS, Web MFA and local CA material.
- Full checks keep requiring production-grade PostgreSQL, Valkey, PKCS#11 and WORM/SIEM settings.

## Patch 559 - Custodia Lite profile specification

- Added the Custodia Lite Profile specification to the repository documentation.

## Patch 560 - Lite and Full YAML examples

- Added flat YAML config examples for Lite and Full profiles.

## Patch 561 - Lite config guide

- Added Lite configuration documentation and README links.

## Patch 562 - Lite env example

- Added a Lite `.env` example using the existing Custodia configuration vocabulary.

## Patch 564 - SQLite Lite schema contract

- Added the SQLite Lite schema contract with WAL, busy timeout, foreign keys and a single persisted state table.
- The schema intentionally avoids reduced Lite tables so the Lite profile preserves the same logical model as FULL.

## Patch 566 - SQLite Lite store build guard

- Added a fail-closed SQLite store guard for standard builds without the `sqlite` build tag.

## Patch 568 - build-tagged SQLite Lite store

- Added an opt-in SQLite Lite store implementation behind `-tags sqlite`.
- The implementation persists the same in-process logical model snapshot instead of introducing a separate reduced SQLite schema.

## Patch 569 - SQLite Lite store backend wiring

- Wired `CUSTODIA_STORE_BACKEND=sqlite` through `custodia-server` so Lite can start with the tagged SQLite artifact.

## Patch 572 - SQLite Lite build targets

- Added `make build-sqlite` and `make test-sqlite` for Lite release artifacts.

## Patch 573 - Lite SQLite store guide

- Documented the SQLite Lite store scope, build tag, configuration, safety properties and backup guidance.

## Patch 578 - Lite installation guide

- Added `docs/LITE_INSTALL.md` with secure single-node installation guidance for the Lite profile.
- The guide keeps mTLS, Web MFA, audit integrity and the opaque crypto boundary intact while reducing external dependencies.

## Patch 579 - Lite local CA bootstrap guide

- Added `docs/LITE_CA_BOOTSTRAP.md` documenting the local file-backed CA model for Lite.
- Marked the future bootstrap helper and CA passphrase-file support as dedicated Phase 4 work instead of claiming they already exist.

## Patch 580 - Lite backup and restore guide

- Added `docs/LITE_BACKUP_RESTORE.md` with SQLite online backup and restore procedures.

## Patch 581 - Lite to Full upgrade guide

- Added `docs/LITE_TO_FULL_UPGRADE.md` covering the configuration and infrastructure path from Lite to Full.

## Patch 582 - Lite systemd unit example

- Added a hardened `custodia-lite.service` example using `custodia-server --config /etc/custodia/config.yaml`.

## Patch 583 - Lite Docker Compose example

- Added `deploy/docker-compose.lite.yml` for single-node Lite packaging with the SQLite build tag.

## Patch 584 - SQLite Lite backup helper

- Added `scripts/sqlite-backup.sh` using SQLite `.backup` for online Lite database backups.

## Patch 585 - SQLite Lite backup make target

- Added `make sqlite-backup`.

## Patch 587 - Lite operations guide links

- Linked Lite installation, CA bootstrap, backup/restore and upgrade guides from the README.

## Patch 591 - file-backed CA key passphrase support

- Added passphrase support for encrypted file-backed CA keys.
- The signer can now read `CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE` and decrypt local Lite CA key material.

## Patch 593 - signer CA passphrase file config

- Wired the signer service to pass the configured CA passphrase file into the file-backed CA provider.

## Patch 595 - Lite local CA bootstrap generator

- Added a Lite bootstrap generator that creates a local self-signed CA, server certificate, admin client certificate, empty CRL and `config.lite.yaml`.
- The generated CA key can be encrypted when a passphrase is provided.

## Patch 597 - Lite local CA bootstrap command

- Added `vault-admin ca bootstrap-local` for single-node Lite bootstrap.
- The command writes local CA/cert/CRL/config artifacts, supports an existing passphrase file, can generate `ca.pass`, and refuses to overwrite existing files.

## Patch 599 - Lite CA bootstrap documentation sync

- Updated Lite CA/bootstrap docs and installation guidance to describe the implemented bootstrap command and passphrase-file behavior.

## Patch 602 - Lite to Full upgrade readiness checks

- Added a dedicated Lite-to-Full readiness checker that validates source Lite/SQLite settings and target Full/PostgreSQL-oriented settings.
- The checker does not perform data migration and keeps the opaque crypto boundary intact.

## Patch 604 - Lite to Full upgrade readiness CLI

- Added `vault-admin lite upgrade-check --lite-env-file FILE --full-env-file FILE`.
- Critical findings fail the command; warnings allow staged migration planning.

## Patch 606 - Lite upgrade check helper

- Added `scripts/lite-upgrade-check.sh` and `make lite-upgrade-check` wrappers for operational use.

## Patch 609 - Full upgrade target env example

- Added `deploy/examples/full-upgrade-target.env.example` as a concrete target-side migration planning template.

## Patch 610 - Lite to Full upgrade readiness docs

- Documented the readiness command in the Lite-to-Full upgrade guide.

## Patch 611 - Lite migration readiness guide

- Added a dedicated migration-readiness guide clarifying what is checked and what remains an operator-controlled migration/evidence activity.

## Patch 612 - Phase 4 closure

- Added `docs/PHASE4_CLOSURE.md` summarizing the repository-level closure of Custodia Lite.

## Patch 615 - Lite upgrade helper source fallback

- Fixed `scripts/lite-upgrade-check.sh` so source checkouts can run the readiness helper through `go run ./cmd/vault-admin` when `vault-admin` is not installed in `PATH`.

## Patch 616 - SQLite Lite driver dependency

- Declared the `modernc.org/sqlite` module dependency required by the build-tagged SQLite Lite artifact.
- Standard builds remain unaffected because the SQLite implementation is behind the `sqlite` build tag.

## Patch 617 - Lite specification final sync

- Updated `docs/CUSTODIA_LITE_PROFILE.md` from planning language to the post-Fase-4 implementation baseline.
- Clarified that SQLite, local CA bootstrap, CA passphrase file support and Lite operational docs are implemented at repository level, while data migration remains a future dedicated tool.

## Patch 619 - web authentication boundary documentation sync

- Updated API, security model and web-console docs that still described MFA/passkey web authentication as future-only.
- Clarified that the web console remains metadata-only while admin mTLS, TOTP-backed sessions and optional passkey assertion delegation are available.

## Patch 621 - SQLite build target driver download

- Added an explicit `sqlite-driver-download` Make target and made `build-sqlite`/`test-sqlite` depend on it so connected environments materialize the declared SQLite driver module before building tagged Lite artifacts.


## Patch 623 - README Lite closure cleanup

- Moved Lite runbook links into the README operational runbook list instead of leaving them as orphan links after the revocation section.
- Added a concise Custodia Lite / SQLite store README section and updated the implemented-features summary.

## Patch 624 - passkey production checklist sync

- Collapsed stale incremental passkey checklist sections into the final WebAuthn verification gate.
- Clarified that passkey promotion requires an audited external assertion verifier and retained TOTP as the conservative production baseline.

## Patch 625 - Lite specification phase 4 completion sync

- Marked the Lite specification implementation blocks as completed repository work.
- Kept the data-migration tool as the remaining explicit future item rather than implying it already exists.
