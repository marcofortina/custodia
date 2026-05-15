# API and compatibility policy

## Version and scope

This document defines Custodia's compatibility promise for the REST API, CLI, configuration, storage/schema migrations, packages and SDK-facing contracts before and after the stable 1.0 release.

The policy does not grant permission to weaken the security boundary. Plaintext, DEKs, application private keys and server-side public-key trust decisions remain excluded by `THREAT_MODEL.md` and `SECURITY_MODEL.md`.

## Stability phases

| Phase | Promise |
| --- | --- |
| Before 1.0 | Compatibility is best-effort. Breaking changes are allowed only when documented, tested and tied to release notes or migration docs. |
| 1.0 and later | Public APIs, CLI behavior, config keys, package layout and migration contracts should remain backward-compatible within a major version. Breaking changes require a major version or an explicit security exception. |

## Public contract surfaces

The following are public or operator-visible contracts:

- REST paths, methods, request/response fields and status-code semantics documented in `API.md`;
- namespace/key secret semantics documented in `SECRET_KEYSPACE_MODEL.md`;
- client crypto metadata, AAD and vector formats documented in `CLIENT_CRYPTO_SPEC.md` and `SDK_TEST_VECTORS.md`;
- CLI flags, config profile paths and JSON output documented in `CUSTODIA_CLIENT_CLI.md` and manpages;
- server/admin config keys documented in `CONFIG_REFERENCE.md` and install runbooks;
- database schema migration expectations for Lite and Full stores;
- Linux package names, service units, installed doc paths and helper scripts;
- Helm values that are documented as user-facing configuration.

Internal helper endpoints and implementation-only IDs can change before 1.0 when they are not documented as normal client workflows. Normal clients should prefer namespace/key routes over internal-id routes.

## API compatibility

Before 1.0, API changes are allowed when they preserve the metadata-only boundary and are documented in the release notes. After 1.0:

- adding optional request fields is compatible;
- adding response fields is compatible when clients can ignore unknown fields;
- adding new endpoints is compatible;
- removing fields, changing required fields, changing path semantics or changing authorization semantics is breaking;
- changing opaque crypto metadata, AAD, envelope semantics or vector format is breaking unless explicitly versioned and backward-compatible.

Error responses may gain more precise machine-readable reason metadata, but existing status-code classes should not change without a documented compatibility reason.

## CLI compatibility

Before 1.0, CLI flags and output can change when docs/tests are updated. After 1.0:

- existing documented flags should remain valid for the major version;
- new flags should be additive;
- JSON output should remain parseable and additive;
- human-readable text may change, but scripted examples should prefer documented JSON or stable command semantics;
- dangerous behavior changes require release notes and migration guidance.

## Configuration compatibility

Before 1.0, config keys can still be renamed or moved when release notes and examples are updated. After 1.0:

- existing documented config keys should remain accepted for the major version or emit a clear deprecation warning;
- new keys must have safe defaults;
- production fail-closed validation must not be relaxed silently;
- profile selection remains config-driven, not separate product binaries.

## Storage and schema migration policy

Lite and Full storage migrations must preserve the security boundary. Migrations must not require plaintext, DEKs or application private keys.

Before 1.0:

- destructive schema changes are allowed only with explicit migration/backup guidance;
- Lite SQLite users must have backup/restore guidance before risky changes;
- Full/PostgreSQL-compatible migrations must document rollback or stop conditions.

After 1.0:

- schema changes must be forward migration compatible within a major version;
- data-preserving migrations are preferred;
- downgrade support is not guaranteed unless explicitly documented;
- incompatible storage changes require a major version or a security exception.

## SDK and test-vector compatibility

SDK compatibility follows `SDK_RELEASE_POLICY.md`. Shared crypto vectors are the compatibility oracle for high-level crypto helpers. A change to canonical AAD, ciphertext format, envelope format, crypto metadata or package verification expectations must update:

- `CLIENT_CRYPTO_SPEC.md`;
- `SDK_TEST_VECTORS.md` and `testdata/client-crypto/manifest.json`;
- affected SDK tests/examples;
- release notes and migration guidance.

## Package and Helm compatibility

Linux package names `custodia-server`, `custodia-client` and `custodia-sdk` are public packaging contracts. Service unit names, primary binary paths and installed documentation paths should remain stable after 1.0 within a major version.

Helm values documented as operator inputs should remain backward-compatible within a major version unless unsafe behavior must fail closed. Security validation can become stricter in patch/minor releases when it prevents unsafe deployment.

## Security exceptions

A security fix may break compatibility when preserving old behavior would risk data exposure, private-key exposure, authentication bypass or unsafe production deployment. Such changes require:

- release notes that call out the exception;
- migration or operator remediation guidance;
- tests or evidence proving the unsafe behavior is closed;
- no weakening of the metadata-only server boundary.
