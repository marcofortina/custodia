# Implementation status

## Current status after web console hardening

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
- Go, Python and Node.js / TypeScript clients with public transport helpers and high-level client-side crypto wrappers for opaque REST payloads.
- Docker, Compose and Helm deployment skeletons.
- Admin-protected metadata-only web console pages for status, diagnostics, clients, access requests and audit summaries. The console now uses local embedded CSS/JS/favicon assets, strict self-only web CSP, styled HTML error pages for web-console errors, preserved filter values, client-side data-table pagination and AJAX autorefresh controls.
- Build metadata propagation through status API, web status and `custodia-admin version`.
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
- Added `custodia-admin audit list`.
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
- Added `custodia-admin audit verify`.
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

## Patch 198 - custodia-admin server version command

- Added `custodia-admin version server` to read build metadata from the authenticated API.
- Kept the existing local `custodia-admin version` command unchanged.

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

- Runtime diagnostics are implemented through admin API `/v1/diagnostics`, web `/web/diagnostics`, Go/Python helpers and `custodia-admin diagnostics read`.


## Operational documentation

Implemented runbooks now cover production readiness, backup/restore, disaster recovery, CA signing service boundaries, CRL/OCSP operations, SIEM/WORM audit export and formal verification scope. These documents do not claim that TPM/HSM signing, OCSP stapling, WORM storage or formal proofs are implemented in code yet.

## Patch 232 - client certificate signing package

- Added an internal client certificate signer that validates CSR signatures, client-id identity binding and certificate TTL bounds.
- The signer issues client-auth certificates only and does not handle application encryption keys.

## Patch 234 - dedicated certificate signer service

- Added `custodia-signer`, a separate admin-only service for CSR signing.
- The vault API process still does not load or use CA private key material.

## Patch 236 - Docker signer binary

- The Docker image now includes `custodia-signer` alongside `custodia-server` and `custodia-admin`.

## Patch 237 - signer build targets

- Local build targets now compile `custodia-signer`.
- A development signer target is available for isolated local workflows.

## Patch 239 - implemented signer service docs

- Documented the implemented signer API boundary, production mTLS requirements and remaining TPM/HSM gap.

## Patch 242 - client CSR generation helper

- Added local ECDSA client key and CSR generation helper.
- The generated CSR binds the `client_id` into CN and DNS SAN for mTLS identity extraction.

## Patch 244 - custodia-admin client CSR command

- Added `custodia-admin client csr` for local key/CSR generation.
- Private keys are written locally with exclusive creation and restrictive permissions.

## Patch 246 - custodia-admin certificate sign command

- Added `custodia-admin certificate sign` to submit CSRs to the dedicated signer service.
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

## Patch 287 - custodia-admin audit export artifacts

- `custodia-admin audit export` can now write JSONL body, SHA-256 header and event-count header to separate files.

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
- `custodia-admin` client/access/audit/status/version/diagnostics/CSR/certificate lifecycle helpers;
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

## Patch 303 - custodia-admin audit export verifier

- Added `custodia-admin audit verify-export` for local/offline audit export artifact verification.
- The command emits a JSON verification result and returns an error on digest or event-count mismatch.

## Patch 305 - audit export verifier documentation

- Documented the `custodia-admin audit verify-export` workflow for JSONL, `.sha256` and `.events` artifacts.

## Patch 311 - client CRL status metadata

- Added CRL status metadata parsing for trusted client CRLs.
- Status includes issuer, update window and revoked entry count without exposing certificate private material.

## Patch 313 - admin revocation status endpoint

- Added admin-only `GET /v1/revocation/status` to monitor configured client CRL health.
- Added `custodia-admin revocation status` plus Go/Python SDK helpers.

## Patch 318 - revocation monitoring documentation

- Documented revocation status monitoring and production checklist expectations.
- Kept OCSP as a remaining production gap rather than claiming it complete.

## Patch 328 - audit archive production checklist

- Production readiness now requires `custodia-admin audit archive-export` before WORM/SIEM ingestion.

## Patch 329 - backup restore audit archive manifest

- Backup/restore guidance now requires checking the audit archive manifest produced by the verifier/archive workflow.


## Patch 331 - audit archive shipper package

- Added verified archive shipment support for copying audit bundles to a sink directory.
- The shipper re-verifies JSONL digest and event count before copying.

## Patch 333 - custodia-admin audit ship-archive

- Added `custodia-admin audit ship-archive` to write sink-ready audit shipments with `shipment.json`.

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

## Patch 355 - custodia-admin CRL fetch command

- Added `custodia-admin revocation fetch-crl --out FILE` to download signer-published CRLs into exclusive output files.

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

## Patch 373 - custodia-admin production readiness command

- Added `custodia-admin production check --env-file FILE`.
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

- Added `deploy/examples/checks/production-readiness.env.example` with production-readiness inputs for API, signer, HA metadata and audit shipment.

## Patch 387 - production env example docs

- Documented how to use the production env example with `make production-check`.

## Patch 391 - production external evidence checker

- Added external evidence checks for HSM/PKCS#11, WORM retention, database HA, Valkey cluster, zero-trust networking, air-gapped backup, penetration testing, formal verification, revocation drills and release checks.
- Kept the checker evidence-oriented: it verifies operator evidence references without pretending to validate confidential external systems inside the repo.

## Patch 393 - custodia-admin production evidence command

- Added `custodia-admin production evidence-check --env-file FILE`.
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

## Patch 424 - custodia-admin S3 audit shipment command

- Added `custodia-admin audit ship-archive-s3` for verified S3/Object Lock archive shipment.

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

## Patch 456 - custodia-admin revocation serial command

- Added `custodia-admin revocation check-serial` for operator revocation drills against `custodia-signer`.

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
- Added YAML `--config` parsing support with environment-variable overrides.

## Patch 554 - custodia-server config file loading

- Wired `custodia-server --config PATH` into startup configuration loading.

## Patch 555 - shared YAML signer config keys

- Allowed the shared YAML file to carry signer-related configuration keys without introducing a second config vocabulary.

## Patch 557 - profile-aware production checks

- Made `custodia-admin production check` profile-aware.
- Lite checks now accept SQLite/memory/file-signer defaults while still enforcing mTLS, Web MFA and local CA material.
- Full checks keep requiring production-grade PostgreSQL, Valkey, PKCS#11 and WORM/SIEM settings.

## Patch 559 - Custodia Lite profile specification

- Added the Custodia Lite Profile specification to the repository documentation.

## Patch 560 - Lite and Full YAML examples

- Added YAML config examples for Lite and Full profiles.

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

- Added a hardened `custodia-server.service` example using `custodia-server --config /etc/custodia/custodia-server.yaml`.

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

- Added a Lite bootstrap generator that creates a local self-signed CA, server certificate, admin client certificate, empty CRL and `custodia-server.lite.yaml`.
- The generated CA key can be encrypted when a passphrase is provided.

## Patch 597 - Lite local CA bootstrap command

- Added `custodia-admin ca bootstrap-local` for single-node Lite bootstrap.
- The command writes local CA/cert/CRL/config artifacts, supports an existing passphrase file, can generate `ca.pass`, and refuses to overwrite existing files.

## Patch 599 - Lite CA bootstrap documentation sync

- Updated Lite CA/bootstrap docs and installation guidance to describe the implemented bootstrap command and passphrase-file behavior.

## Patch 602 - Lite to Full upgrade readiness checks

- Added a dedicated Lite-to-Full readiness checker that validates source Lite/SQLite settings and target Full/PostgreSQL-oriented settings.
- The checker does not perform data migration and keeps the opaque crypto boundary intact.

## Patch 604 - Lite to Full upgrade readiness CLI

- Added `custodia-admin lite upgrade-check --lite-env-file FILE --full-env-file FILE`.
- Critical findings fail the command; warnings allow staged migration planning.

## Patch 606 - Lite upgrade check helper

- Added `scripts/lite-upgrade-check.sh` and `make lite-upgrade-check` wrappers for operational use.

## Patch 609 - Full upgrade target env example

- Added `deploy/examples/checks/lite-upgrade-target-full.env.example` as a concrete target-side migration planning template.

## Patch 610 - Lite to Full upgrade readiness docs

- Documented the readiness command in the Lite-to-Full upgrade guide.

## Patch 611 - Lite migration readiness guide

- Added a dedicated migration-readiness guide clarifying what is checked and what remains an operator-controlled migration/evidence activity.

## Patch 612 - Phase 4 closure

- Added `docs/PHASE4_CLOSURE.md` summarizing the repository-level closure of Custodia Lite.

## Patch 615 - Lite upgrade helper source fallback

- Fixed `scripts/lite-upgrade-check.sh` so source checkouts can run the readiness helper through `go run ./cmd/custodia-admin` when `custodia-admin` is not installed in `PATH`.

## Patch 616 - SQLite Lite driver dependency

- Declared the `modernc.org/sqlite` module dependency required by the build-tagged SQLite Lite artifact.
- Standard builds remain unaffected because the SQLite implementation is behind the `sqlite` build tag.

## Patch 617 - Lite specification final sync

- Updated `docs/LITE_PROFILE.md` from planning language to the post-Phase-4 implementation baseline.
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

## Patch 632 - phase 5 client library specification

- Added `docs/CLIENT_LIBRARIES.md` as the Phase 5 client-library specification.
- Clarified that Go and Python are existing transport clients while crypto clients and additional languages remain planned.

## Patch 633 - client crypto specification

- Added `docs/CLIENT_CRYPTO_SPEC.md` defining the shared, versioned client-side crypto contract.
- Reaffirmed that Custodia server remains metadata/ciphertext/envelope-only and never becomes a public-key directory.

## Patch 634 - client crypto vector scaffold

- Added `testdata/client-crypto/v1/` schema fixtures for future deterministic crypto vectors.

## Patch 636 - Go public transport types

- Added public SDK-facing Go transport types under `pkg/client` so external consumers can avoid importing `custodia/internal/*` model types.

## Patch 637 - Go public transport methods

- Added public Go transport methods that wrap the monorepo internal-model methods for opaque payload operations.

## Patch 639 - external Go consumer compile guard

- Added a compile test that creates a temporary external Go module and imports `custodia/pkg/client` public transport types without importing internal packages.

## Patch 640 - Go client SDK guide

- Added `docs/GO_CLIENT_SDK.md` and README links for the Go transport SDK boundary.

## Patch 641 - Python client SDK guide

- Added `docs/PYTHON_CLIENT_SDK.md` and README links for the Python transport SDK boundary.

## Patch 642 - Phase 5 closure tracker

- Added `docs/PHASE5_CLOSURE.md` to track closed and open Phase 5 work.
- Phase 5 is not complete yet: deterministic crypto vectors and high-level crypto clients remain open.

## Patch 644 - Go client public type import cleanup

- Moved internal model conversion helpers out of the public Go SDK type file.
- `pkg/client/types.go` no longer imports `custodia/internal/*`.

## Patch 645 - Go public transport direct REST methods

- Reworked public Go transport methods so they call REST endpoints directly with public SDK payload/response types.
- The public transport path no longer depends on monorepo internal-model helpers.

## Patch 646 - Go client conversion cleanup

- Removed now-unused internal model conversion helpers from the public Go client path.

## Patch 647 - Go internal-model helper boundary docs

- Marked Go internal-model helper methods that expose internal model types as monorepo helpers.
- Pointed external consumers to the new public transport methods.

## Patch 648 - Go public surface guardrails

- Added tests that prevent `pkg/client/types.go` and `pkg/client/public_transport.go` from importing `custodia/internal/*`.
- Expanded the external consumer compile test to cover public transport method signatures.

## Patch 649 - Go client SDK boundary docs

- Updated Go SDK and client-library docs after the public transport cleanup.

## Patch 651 - Phase 5 closure tracker Go transport cleanup sync

- Updated `docs/PHASE5_CLOSURE.md` to reflect that Go public transport files no longer import `custodia/internal/*`.
- Documented the monorepo internal-model helpers as monorepo compatibility helpers.


## Patch 653 - Python public transport payload types

- Added typed Python transport payload dataclasses for clients, secrets, sharing, grants and versions.
- Exported permission constants and payload helpers from `custodia_client`.

## Patch 654 - Python typed transport helpers

- Added typed Python helper methods that convert public payload dataclasses into the existing REST transport calls.

## Patch 655 - Python typed transport tests

- Added unittest coverage for typed payload serialization and helper routing.

## Patch 656 - Python client test target

- Added `make test-python-client` and included it in the standard `check` target.

## Patch 657 - Python typed transport documentation

- Documented typed Python transport payload helpers in the SDK docs and client README.

## Patch 658 - client crypto metadata validator

- Added `internal/clientcrypto` constants and metadata validation for the shared v1 crypto scaffold.

## Patch 659 - client crypto metadata validator tests

- Covered accepted and rejected client crypto metadata combinations.

## Patch 660 - client crypto vector parser tests

- Routed schema fixture validation through the shared metadata parser.

## Patch 661 - client crypto validator docs

- Documented the metadata validator boundary: it validates schema metadata but is not yet a high-level crypto client.

## Patch 663 - Python client release check coverage

- Added Python client typed helper unittest execution to `scripts/release-check.sh`.
- Compiles both `custodia_client/__init__.py` and `custodia_client/types.py` during release checks.

## Patch 665 - client crypto canonical AAD builder

- Added `internal/clientcrypto.BuildCanonicalAAD` for deterministic v1 metadata/resource AAD serialization.

## Patch 666 - client crypto canonical AAD builder tests

- Covered stable canonical AAD JSON, persisted resource ids, missing bindings and unsupported metadata.

## Patch 667 - deterministic client crypto AAD fixtures

- Added deterministic metadata/AAD fixture fields under `testdata/client-crypto/v1`.
- Added the remaining minimum fixture names from the client-library specification as deterministic-AAD placeholders.

## Patch 668 - client crypto vector loader and validator

- Added `internal/clientcrypto.LoadVector` and `ValidateVector`.
- Routed client-crypto fixture validation through canonical AAD and SHA-256 checks.

## Patch 669 - client crypto vector error validation

- Added negative validation coverage for AAD hash mismatch, canonical AAD mismatch and expected metadata errors.

## Patch 670 - deterministic client crypto AAD documentation

- Documented that the current vectors are deterministic metadata/AAD fixtures, not full ciphertext/envelope crypto vectors.

## Patch 671 - client crypto test target

- Added `make test-client-crypto` for focused client crypto fixture validation.

## Patch 672 - Phase 5 deterministic AAD status

- Updated the Phase 5 closure tracker after deterministic metadata/AAD fixture validation.

## Patch 674 - Go client public operational response types

- Added public Go SDK response types for operational status, build info, diagnostics, revocation status and audit events.
- Moved audit export and revocation serial response types into the public type surface.

## Patch 675 - Go client public operational methods

- Added public Go SDK operational methods for status, version, diagnostics, revocation status, revocation serial status, audit metadata listing and audit export artifacts.

## Patch 676 - Go client public operational method tests

- Covered public operational method routing and external consumer compile signatures.

## Patch 677 - Go public operational SDK documentation

- Documented the public Go operational SDK methods and response types.

## Patch 678 - Go operational internal-model boundary docs

- Marked older operational helpers that return internal model types as monorepo compatibility helpers.

## Patch 679 - Phase 5 Go operational SDK status

- Updated Phase 5 status after closing the public Go operational SDK surface.
## Patch 680 - client crypto AES-GCM content codec

- Added internal AES-256-GCM seal/open helpers for deterministic client crypto vectors.
- Covered key length, nonce length and AAD authentication failure behavior.

## Patch 681 - client crypto HPKE envelope codec

- Added internal HPKE-v1 envelope seal/open helpers for deterministic recipient envelope vectors.
- Covered wrong recipient and AAD mismatch failures without exposing this as a public high-level SDK.

## Patch 682 - client crypto payload vector validation

- Extended `internal/clientcrypto.ValidateVector` to validate deterministic plaintext, DEK, nonce, ciphertext and recipient envelope fixtures.
- Kept older deterministic-AAD-only fixtures valid until they are upgraded.

## Patch 683 - deterministic client crypto payload fixtures

- Replaced placeholder ciphertext/envelope fixtures with deterministic AES-256-GCM and HPKE-v1 vectors.
- Added fixture-only recipient private keys, public keys, ephemeral keys and negative tamper/wrong-recipient/AAD-mismatch payloads.

## Patch 684 - client crypto payload vector validation tests

- Covered ciphertext mismatch, envelope mismatch and negative crypto fixture validation.

## Patch 685 - Go client crypto interface contracts

- Added public Go SDK interfaces for recipient public-key resolution, local private-key envelope opening, CSPRNG source and clock injection.
- Added external consumer compile coverage for the crypto interface contracts without adding a high-level crypto client yet.

## Patch 686 - deterministic client crypto payload vector docs

- Documented that the shared vectors now cover canonical AAD, AES-256-GCM ciphertext and HPKE-v1 recipient envelopes.

## Patch 687 - Go client crypto interface docs

- Documented the public Go crypto dependency interfaces and their trust boundary.

## Patch 688 - Phase 5 crypto vector status

- Updated the Phase 5 closure tracker after deterministic ciphertext/envelope vectors and Go crypto interfaces.

## Patch 689 - client crypto persisted AAD binding metadata

- Extended v1 client crypto metadata with optional persisted AAD binding and content nonce fields.
- Added helpers/tests so high-level clients can reproduce canonical AAD on read/share/version paths without relying on extra server plaintext metadata.

## Patch 690 - Go crypto client public types

- Added public Go SDK request/response types for high-level create, read, version and share crypto flows.
- Added public typed crypto errors for malformed metadata, unsupported ciphers/envelope schemes and random-source failures.

## Patch 691 - Go X25519 crypto key handles

- Added public Go X25519 helper functions for HPKE-v1 recipient public keys and local private-key envelope opening.
- Kept internal HPKE implementation hidden behind public SDK types.

## Patch 692 - Go high-level crypto client methods

- Added `NewCryptoClient`, `Client.WithCrypto`, `CreateEncryptedSecret`, `ReadDecryptedSecret`, `ShareEncryptedSecret` and `CreateEncryptedSecretVersion`.
- The methods encrypt/decrypt locally and send only opaque ciphertext, metadata and envelopes through the transport client.

## Patch 693 - Go high-level crypto client tests

- Covered create/read/share/version E2E behavior with deterministic local crypto material and httptest transport assertions.
- Verified that posted payloads remain opaque and creator self-envelopes are added automatically.

## Patch 694 - Go crypto external consumer guardrail

- Extended the external Go module compile guard to cover high-level crypto public types, constructors, methods and X25519 helpers.

## Patch 695 - Go high-level crypto client docs

- Documented the Go high-level crypto client, local trust dependencies and persisted AAD/nonce metadata boundary.

## Patch 696 - Phase 5 Go crypto status

- Updated Phase 5 client docs and closure tracker after adding the first Go high-level crypto client.

## Patch 697 - Python client crypto primitives

- Added Python AES-256-GCM, HPKE-v1, canonical AAD and metadata helpers matching the shared client crypto v1 vectors.
- Added `cryptography` as the Python client crypto dependency.

## Patch 698 - Python client crypto vector tests

- Covered Python canonical AAD, AES-256-GCM ciphertext, HPKE-v1 envelopes and negative vectors against `testdata/client-crypto/v1`.

## Patch 699 - Python crypto client public contracts

- Added Python public key resolver/private key provider contracts and X25519 helpers.
- Exported static resolver/provider helpers for tests and pinned local maps.

## Patch 700 - Python high-level crypto client methods

- Added `CryptoCustodiaClient` and `CustodiaClient.with_crypto(...)`.
- Added local create/read/share/version crypto flows that send only ciphertext, crypto metadata and opaque envelopes to the server.

## Patch 701 - Python high-level crypto client tests

- Covered Python create/read/share high-level crypto flows against deterministic fixtures and mocked transport payloads.

## Patch 702 - Python crypto client check targets

- Included `custodia_client/crypto.py` in Makefile and release-check Python syntax coverage.

## Patch 703 - Python high-level crypto client documentation

- Documented Python high-level crypto usage and the non-server key resolver boundary.

## Patch 704 - Phase 5 Python crypto client status

- Updated README, client specification and Phase 5 closure tracker after closing the Python high-level crypto client.


### Phase 5D Node.js / TypeScript high-level crypto status

Node high-level crypto wrapper is implemented in `clients/node` using Node built-ins only. It shares the same deterministic AES-256-GCM, HPKE-v1 and canonical AAD vectors used by Go and Python, keeps plaintext/DEKs/private keys client-side and sends only opaque payloads through the transport client.

## Patch 718 - Java transport client package scaffold

- Added `clients/java` documentation for the raw REST/mTLS Java transport SDK boundary.

## Patch 719 - Java transport client implementation

- Added Java transport client configuration, HTTP error type, audit export artifact type and opaque REST method coverage using `java.net.http`.
- Kept the Java SDK transport-only; it does not encrypt, decrypt or resolve recipient keys.

## Patch 720 - Java transport client tests

- Added a no-framework Java test target with injectable transport coverage for routing, headers, encoded paths, HTTP errors and audit export metadata.
- Included `make test-java-client` in standard checks.

## Patch 721 - C++ transport client package scaffold

- Added `clients/cpp` documentation for the raw REST/mTLS C++ transport SDK boundary.

## Patch 722 - C++ transport client implementation

- Added a C++20 transport client API backed by libcurl for HTTPS/mTLS and opaque REST payloads.
- Kept the C++ SDK transport-only; it does not encrypt, decrypt or resolve recipient keys.

## Patch 723 - C++ transport client tests

- Added injectable C++ transport tests for routing, headers, encoded paths, HTTP errors and audit export metadata.
- Included `make test-cpp-client` in standard checks.

## Patch 724 - Java and C++ transport SDK documentation

- Added Java and C++ SDK guides and README links.

## Patch 725 - Phase 5 Java/C++ transport status

- Updated client-library docs and Phase 5 closure tracker after adding Java and C++ transport clients.
- Java/C++ high-level crypto clients remain open and must use shared vectors before being marked official.


## Patch 726 - Java crypto primitives

- Added Java canonical AAD, AES-256-GCM and HPKE-v1/X25519 primitives matching the shared v1 vectors.
- Added Java public resolver/provider contracts and X25519 key handles for local client-side crypto.

## Patch 727 - Java high-level crypto client

- Added `CryptoCustodiaClient` and `CustodiaClient.withCrypto(...)`.
- Added local create/read/share/version flows that send only ciphertext, crypto metadata and opaque envelopes to the server.

## Patch 728 - Java crypto client tests

- Covered Java shared crypto vectors and high-level create/read flows with deterministic payloads.
- Extended `make test-java-client` to run both transport and crypto tests.

## Patch 729 - C++ crypto primitives

- Added C++ canonical AAD, AES-256-GCM and HPKE-v1/X25519 primitives backed by OpenSSL.
- Updated the C++ test target to link both libcurl and OpenSSL.

## Patch 730 - C++ high-level crypto client

- Added `custodia::CryptoClient` and `custodia::Client::with_crypto(...)`.
- Added local create/read/share/version flows that keep plaintext, DEKs and private keys client-side.

## Patch 731 - C++ crypto client tests

- Covered C++ shared crypto vectors and high-level create/read flows with deterministic payloads.

## Patch 732 - Java and C++ crypto client documentation

- Documented Java and C++ high-level crypto usage and the resolver/key-provider boundary.

## Patch 733 - Phase 5 Java/C++ crypto status

- Updated client-library docs and Phase 5 closure tracker after closing Java and C++ high-level crypto wrappers.
- Rust transport remains the only planned language still open in the broader roadmap.

## Patch 734 - Rust transport client package scaffold

- Added `clients/rust` with Cargo package metadata, README and initial public transport SDK types.
- Added the Rust transport boundary for opaque REST/mTLS payloads; Rust high-level crypto is closed by Patch 740.

## Patch 735 - Rust transport client implementation

- Added `CustodiaClient` transport methods for secrets, access grants, client metadata, operational status, revocation and audit export.
- Added reqwest/rustls-backed mTLS transport while preserving a testable `HttpTransport` trait.
- Added typed HTTP error mapping without logging or interpreting opaque crypto payloads.

## Patch 736 - Rust transport client tests

- Added fake-transport Rust tests for opaque secret payloads, operational paths, audit export headers and HTTP errors.
- Added `make test-rust-client` and wired it into repository checks with a clear skip when Cargo is unavailable.

## Patch 737 - Rust transport SDK documentation

- Added `docs/RUST_CLIENT_SDK.md` and linked it from the README.
- Updated the client-library specification to mark Rust transport as present; Patch 740 later closes Rust high-level crypto.

## Patch 738 - Phase 5 final closure

- Updated the Phase 5 closure tracker after adding Rust transport.
- Marked repository-level Phase 5 complete for Go, Python, Node.js/TypeScript, Java, C++ and Rust transport.
- Documented remaining work as future scope outside this Phase 5 closure; Patch 740 later removes Rust crypto from that future-work list.

## Patch 739 - Rust client test target skip guard

- Fixed `make test-rust-client` so environments without Cargo skip cleanly without trying to execute `cargo` on the next recipe line.
- Preserved `cargo test --manifest-path clients/rust/Cargo.toml` when Rust is installed.


## Patch 740 - Rust high-level crypto client

- Added Rust client crypto primitives for canonical AAD, AES-256-GCM and HPKE-v1/X25519.
- Added Rust `CryptoCustodiaClient` for local create/read/share/version flows.
- Added Rust resolver/provider/random-source contracts so recipient public keys stay application-owned and Custodia never becomes a key directory.
- Added Rust high-level crypto tests with deterministic local payloads.

## Patch 741 - Bash transport helper

- Added `clients/bash/custodia.sh` as a shell transport helper for CI, smoke tests and ops scripts.
- Kept Bash explicitly transport-only: no encryption, decryption, HPKE, DEK management or public-key resolution.
- Added `make test-bash-client` and wired it into release checks.

## Patch 742 - Phase 5 documentation consistency review

- Updated client capability matrices after closing Rust high-level crypto.
- Marked Bash as a transport helper rather than a crypto SDK.
- Removed stale transport-only language from Java, C++, Rust and Phase 5 closure docs.
- Kept package publishing and semver/release support policies as future work outside repository-level Phase 5.

## Patch 743 - Bash external crypto-provider bridge

- Added optional `CUSTODIA_CRYPTO_PROVIDER` support to the Bash helper.
- Added encrypted Bash commands for create/read/share/version flows that delegate all cryptography to a provider executable over stdin/stdout JSON.
- Kept native Bash explicitly non-crypto: no shell-side plaintext encryption, HPKE, DEK management or key resolution.
- Extended Bash tests with a fake provider to verify operation routing and raw REST payload submission.
- Updated Bash and Phase 5 documentation to describe the provider protocol and security boundary.


## Patch 744 - Linux DEB/RPM packaging

- Added `scripts/package-linux.sh` and Make targets for `package-deb`, `package-rpm` and `package-linux`.
- Added two installable package families: `custodia-server` for deployable binaries and `custodia-clients` for SDK source snapshots, shared vectors and the Bash helper.
- Kept per-language registry publication as future release work instead of pretending distro packages are language-native SDK releases.

## Patch 745 - CI release check and README badge

- Expanded GitHub Actions to install required system dependencies, run `make release-check`, build DEB/RPM packages and upload artifacts.
- Added the CI badge to `README.md`.
- Fixed package metadata drift for Node and Rust SDK descriptors.

## Patch 746 - Linux packaging documentation

- Documented DEB/RPM package layout, build commands, installation boundary and package split rationale.
- Updated release-check docs and README package pointers.

## Patch 855 - Phase 5 external client spec sync

- Marked `docs/CLIENT_LIBRARIES.md` as the canonical repository-level client specification after Phase 5 closure.
- Documented that older external planning notes describing missing or transport-only SDKs are historical and superseded by the current repository implementation matrix.
- Linked the README client SDK section to the canonical SDK matrix.
- Updated the Phase 5 closure tracker with a planning-spec reconciliation note.

## Patch 856 - Lite signer systemd and docs

- Added a Lite `custodia-signer.service` example using the file-backed local CA generated by `custodia-admin ca bootstrap-local`.
- Packaged a `custodia-signer.service` alongside `custodia-server.service` so first-run Lite installs can issue additional client mTLS certificates without manually inventing signer startup flags.
- Updated quickstart, Lite install, CA signing and client certificate lifecycle docs to clarify that signer `:9444` is a separate process and does not require HSM/PKCS#11 in Lite.

## Patch 857 - certificate extraction command

- Added `custodia-admin certificate extract` to materialize signer JSON responses into client certificate PEM files without ad-hoc `python`/`jq` snippets.
- Validates that `certificate_pem` contains exactly one client-auth certificate and writes output files exclusively with `0644` permissions.
- Updated certificate lifecycle and signer docs to keep Lite first-run certificate issuance copy/pasteable.

## Patch 858 - certificate bundle command

- Added `custodia-admin certificate bundle` to create a local-only zip archive with `client.crt`, `client.key`, `ca.crt` and a README for application handoff.
- Validates client certificate, private key and CA certificate inputs, writes the archive exclusively with `0600` permissions and keeps application encryption keys out of the bundle.
- Updated certificate lifecycle and signer docs to document the safer CLI handoff path after `certificate extract`.


## Patch 860 - custodia-client encrypted secrets CLI

- Added `cmd/custodia-client` for local encrypted secret put/get/share/version workflows.
- Added local X25519 key generation and public-key file handling for application-controlled recipient resolution.
- Updated packaging to ship the Go `custodia-client` binary instead of exposing the Bash helper as the primary `/usr/bin/custodia-client`.
- Added `docs/CUSTODIA_CLIENT_CLI.md` and linked the CLI from the client library matrix.

Verification:

```bash
go test ./cmd/custodia-client
make check
```


## Patch 861 - custodia-client metadata listing UX

- Added `custodia-client secret versions` for version metadata inspection.
- Added `custodia-client secret access list` for access grant metadata inspection.
- Kept both commands metadata-only: no plaintext, DEKs, recipient envelopes or private keys are rendered.
- Updated client CLI and package documentation so `/usr/bin/custodia-client` is consistently described as the Go encrypted secrets CLI.

Recommended verification:

```bash
go test ./cmd/custodia-client
make check
```

## Patch 862 - custodia-client destructive lifecycle UX

- Added `custodia-client secret access revoke` for explicit future access revocation.
- Added `custodia-client secret delete` for explicit destructive secret deletion.
- Required `--yes` for destructive client CLI operations before any transport call.
- Updated client CLI documentation to distinguish future access revocation from strong revocation via new encrypted versions.

Validation:

```bash
go test ./cmd/custodia-client
make check
```


## Patch 863 - custodia-client reusable config profiles

- Added `custodia-client config write` to create a local JSON config file for repeated mTLS and crypto path options.
- Added `--config FILE` and `CUSTODIA_CLIENT_CONFIG` support for secret commands.
- Preserved precedence so explicit flags and environment values override config file values.
- Added tests for config writing, merge behavior and explicit override safety.

Suggested verification:

```bash
go test ./cmd/custodia-client
make check
```


## Patch 864 - custodia-client local validation helpers

- Added `custodia-client config check` to validate reusable client profiles, HTTPS URLs, local mTLS certificate/key pairs, CA bundles and optional crypto key files before running secret operations.
- Added `custodia-client key inspect` to report local X25519 key metadata and public-key fingerprint without exposing private key material.
- Updated CLI and client library documentation for first-run troubleshooting.

Suggested verification:

```bash
go test ./cmd/custodia-client
make check
```


## Patch 865 - Alice/Bob encrypted secret smoke runbook

- Added `docs/CUSTODIA_ALICE_BOB_SMOKE.md` with a copy/paste Lite smoke test for Alice/Bob client registration, certificate issuance, local crypto key generation, encrypted secret put/get, sharing, versioning and access revocation.
- Linked the runbook from the README, client CLI docs and client library matrix.
- Kept the workflow explicit about the crypto boundary: plaintext, DEKs, private keys and recipient public keys remain outside the server.

Documentation-only patch; no runtime tests required.


## Patch 866 - admin client issue workflow

- Added `custodia-admin client issue` to orchestrate client metadata registration, local mTLS key/CSR generation, signer submission, certificate extraction and local bundle creation.
- Kept the signer boundary intact: `custodia-server` still does not hold CA private keys and application encryption keys remain separate from mTLS material.
- Updated signer, lifecycle, Lite install, quickstart and README docs with the copy/paste shortcut.

Suggested verification:

```bash
go test ./cmd/custodia-admin
make check
```

## Patch 872 - Makefile default all target

- Added an explicit `all` target as the default Make goal.
- Made `make` run the Go test suite and build the main binaries via `all: test build`.
- Updated README and quickstart wording so `make`, `make test` and `make check` have clear scopes.

Suggested verification:

```bash
make
make test
```

## Patch 873 - Makefile install target

- Added `make install` for locally built binaries.
- Added `PREFIX`, `BINDIR`, `DESTDIR` and `INSTALL` knobs for standard staged installs.
- Kept service units and runtime directory provisioning explicit in docs instead of hiding them behind a binary install target.

Suggested verification:

```bash
make
DESTDIR=/tmp/custodia-install-check make install
find /tmp/custodia-install-check -type f | sort
```

## Patch 874 - universal store build

- Made the default server build universal with `SERVER_BUILD_TAGS=sqlite postgres`.
- Kept `build-sqlite` and `build-postgres` as focused diagnostic/specialized targets, not the normal product split.
- Updated package builds to produce one server artifact that can run Lite or Full based on runtime configuration.
- Updated README and Lite/package docs so SQLite/PostgreSQL are described as configuration choices for the same binary.

Suggested verification:

```bash
make
make test-sqlite
# Optional, with TEST_CUSTODIA_POSTGRES_URL set:
make test-postgres
```

## Patch 876 - custodia-admin manual page

- Added `custodia-admin(1)` as a roff template with build metadata substitution.
- Added `scripts/build-manpages.sh` without external manpage generators.
- Added `make man` and `make install-man`; `make install` now installs generated manpages.
- Updated Linux packaging so DEB/RPM stages include compressed manpages when templates exist.

Suggested verification:

```bash
make man
make -n install
bash -n scripts/build-manpages.sh scripts/package-linux.sh
```

## Patch 877 - custodia-client manual page

- Added `custodia-client(1)` as a roff template with build metadata substitution.
- Documented encrypted CLI commands, reusable config profiles, key inspection, secret lifecycle commands, environment variables and crypto-boundary security notes.
- The existing manpage build/install/package pipeline automatically includes it in local installs and the `custodia-clients` DEB/RPM package.

Suggested verification:

```bash
make man
grep -R "custodia-client" build/man/man1/custodia-client.1
```

## Patch 878 - custodia-server manual page

- Added `custodia-server(1)` as a roff template with build metadata substitution.
- Documented runtime info commands, universal SQLite/PostgreSQL store selection, packaged files, systemd usage and the server crypto boundary.
- The existing manpage build/install/package pipeline automatically includes it in local installs and the `custodia-server` DEB/RPM package.

Suggested verification:

```bash
make man
grep -R "custodia-server" build/man/man1/custodia-server.1
```

## Patch 879 - custodia-signer manual page

- Added `custodia-signer(1)` as a roff template with build metadata substitution.
- Documented runtime info commands, signer environment, Lite CA files, systemd usage and signing-boundary security notes.
- The existing manpage build/install/package pipeline automatically includes it in local installs and the `custodia-server` DEB/RPM package.

Suggested verification:

```bash
make man
grep -R "custodia-signer" build/man/man1/custodia-signer.1
```

## Patch 880 - Make all builds manpages

- Included generated manual pages in the default `make all` path.
- Kept `make man` available for manual-page-only rebuilds.
- Updated README build wording so `make`, `make build`, `make man` and `make check` have distinct scopes.

Documentation/build metadata only. Suggested verification:

```bash
make -n
make -n man
make -n install
```


## Patch 886 - generic runtime config file names

- Renamed packaged server config examples to `custodia-server.lite.yaml` and `custodia-server.full.yaml`.
- Standardized live runtime config paths on `/etc/custodia/custodia-server.yaml` and `/etc/custodia/custodia-signer.yaml`.
- Extended Lite bootstrap output to include both server and signer YAML files.
- Updated systemd examples, package smoke checks and install docs for the generic server/signer config filenames.


## Patch 887 - package signer config and manpage sync

- Updated packaged `custodia-signer.service` to run `custodia-signer --config /etc/custodia/custodia-signer.yaml`.
- Updated package install docs to copy both server and signer YAML examples into `/etc/custodia`.
- Updated server/signer manpages for the generic runtime config paths.
- Documented signer YAML config as the primary packaged configuration path, with environment variables retained as overrides.


## Patch 891 - structured YAML config examples

- Renamed packaged server examples to `custodia-server.lite.yaml` and `custodia-server.full.yaml` where missing.
- Added `deploy/examples/custodia-signer.yaml` using structured `admin_subjects`.
- Updated Lite bootstrap output to emit structured `bootstrap_clients`, `admin_client_ids` and signer `admin_subjects`.
- Updated docs/manpage wording to describe supported structured YAML instead of flat-only YAML.

Suggested verification:

```bash
go test ./internal/config ./cmd/custodia-signer ./cmd/custodia-admin ./internal/certutil
bash -n scripts/package-linux.sh scripts/package-smoke.sh
```

## Patch 892 - real structured YAML config sections

- Added parser support for named nested server config sections: `server`, `storage`, `rate_limit`, `http`, `tls`, `web`, `deployment`, `signer`, `limits` and `security`.
- Added parser support for named nested signer config sections: `server`, `tls`, `admin`, `ca`, `audit` and `revocation`.
- Kept legacy flat YAML keys supported for compatibility while making nested YAML the recommended example format.
- Rewrote `deploy/examples/custodia-server.lite.yaml`, `deploy/examples/custodia-server.full.yaml`, generated Lite bootstrap YAML and `deploy/examples/custodia-signer.yaml` to use readable nested YAML sections.
- Added guardrail tests that parse the packaged deploy examples directly.

Recommended verification:

```bash
go test ./internal/config ./cmd/custodia-signer ./internal/certutil ./cmd/custodia-admin
make
make check
```

## Patch 893 - clarify checker env examples

- Renamed readiness and upgrade `.env.example` files under `deploy/examples/checks/` to make clear they are offline checker inputs, not runtime configuration.
- Added explicit headers warning that runtime configuration lives in `custodia-server.yaml` and `custodia-signer.yaml`.
- Updated docs, packaging and package smoke checks to use the non-runtime checker paths.

Suggested verification:

```bash
bash -n scripts/package-linux.sh scripts/package-smoke.sh
grep -R "deploy/examples/.*env.example" -n README.md docs scripts deploy
```


## Patch 895 - structured YAML configuration reference

- Added `docs/CONFIG_REFERENCE.md` covering structured server and signer YAML schemas.
- Clarified runtime YAML files versus offline `.env.example` checker inputs.
- Linked the reference from README, quickstart, Lite config and signer docs.

Documentation-only patch; no runtime tests required.


## Patch 896 - package smoke structured config guardrails

- Extended package smoke checks to validate that packaged runtime YAML examples use structured sections.
- Added stale flat-key guards for shipped server and signer YAML examples.
- Added a package-smoke guard that checker `.env.example` files carry the non-runtime warning.

Suggested verification:

```bash
bash -n scripts/package-smoke.sh
make package-smoke
```

## Patch 897 - release build metadata guardrails

- Added `scripts/check-build-metadata.sh` to block release builds with placeholder version metadata.
- Added `make release-metadata-check` and `make release`.
- Updated local Makefile builds to derive `COMMIT` and `DATE` automatically while keeping `VERSION=dev` unless explicitly set.
- Documented the release metadata gate in README and build metadata docs.

## Patch 898 - systemd hardening guardrails

- Added `scripts/check-systemd-hardening.sh` for deploy example unit hardening.
- Added `make systemd-hardening-check` and wired it into `make check`.
- Expanded package smoke checks so packaged systemd units retain the expected hardening lines.
