# Custodia SDK release and versioning policy

## Scope

This policy defines when a Custodia client library can be presented as an official SDK and how SDK releases are versioned, packaged and supported.

Custodia keeps the server crypto boundary strict: SDKs may implement client-side encryption, decryption and envelope creation, but the server continues to receive only opaque ciphertext, opaque envelopes and crypto metadata.

## Official SDK criteria

A language SDK can be marked official only when it has all of the following in the repository or in an approved dedicated repository:

1. Transport client for the documented `/v1/*` REST API.
2. mTLS configuration with custom CA support.
3. Timeout configuration and safe default user-agent.
4. Typed or clearly structured HTTP errors that do not leak request payloads.
5. Safe logging policy: no plaintext, DEK, private key, passphrase, ciphertext, envelope or bearer/session material in logs.
6. Retry policy: retries only for idempotent reads/status calls unless an explicit idempotency key or documented semantic exists.
7. Documentation with install, configuration and examples.
8. Reproducible verification command in CI or in `make` targets.
9. Shared crypto vector tests when the SDK includes high-level crypto.
10. Clear release channel or explicit “monorepo source snapshot only” status.

## Current release channels

| SDK | Repository status | Package release status | Crypto status |
| --- | --- | --- | --- |
| Go | Monorepo source | Go module path pending stable publication | Transport + high-level crypto |
| Python | Monorepo source | PyPI package pending | Transport + high-level crypto |
| Node.js / TypeScript | Monorepo source | npm package pending | Transport + high-level crypto |
| Java | Monorepo source | Maven coordinates pending | Transport + high-level crypto |
| C++ | Monorepo source | Source archive / distro packaging pending | Transport + high-level crypto |
| Rust | Monorepo source | crates.io package pending | Transport + high-level crypto |
| Bash | Monorepo source and Linux client package helper | Linux package helper only | Transport + optional external crypto provider bridge |

The Linux `custodia-clients` package installs source snapshots and the Bash helper. It is not a replacement for native language package registries.

## Versioning

Custodia uses semantic versioning for public release artifacts:

```text
MAJOR.MINOR.PATCH
```

Rules:

- `MAJOR`: breaking API, wire-format, package layout or crypto metadata/vector change.
- `MINOR`: backward-compatible SDK feature, new endpoint wrapper, new language SDK or new package artifact.
- `PATCH`: bug fix, documentation correction, CI/package hardening or security fix that preserves public APIs.

Release candidates and prereleases should use prerelease identifiers in source tags and package metadata where the target ecosystem supports them.

## Cross-language compatibility

High-level crypto SDKs must pass the shared client crypto vectors under:

```text
testdata/client-crypto/v1/
```

A change to canonical AAD, ciphertext format, envelope format or crypto metadata must update:

- `docs/CLIENT_CRYPTO_SPEC.md`;
- vector fixtures;
- Go/Python/Node/Java/C++/Rust vector tests;
- `docs/PHASE5_CLOSURE.md` or the current phase closure document.

## Release checklist

Before publishing SDK artifacts:

```bash
make release-check
VERSION=0.1.0 REVISION=1 make package-linux
VERSION=0.1.0 REVISION=1 make package-checksums
make package-smoke
VERSION=0.1.0 make sbom
```

Release artifacts should include:

- `.deb` and `.rpm` packages where applicable;
- `SHA256SUMS`;
- `artifacts-manifest.json`;
- `custodia-sbom.spdx.json`;
- release notes that call out compatibility, migration notes and known limitations.

## Deprecation policy

Public SDK APIs should not be removed without at least one minor release of deprecation notice unless the API is unsafe or incorrect in a way that risks data exposure.

Deprecated APIs must document the replacement and should keep safe behavior until removal.

## Security fixes

Security fixes may be released as patch versions. If a fix changes crypto behavior, envelope metadata, AAD construction or package verification expectations, the release notes must explicitly call it out and the shared vectors must be updated.
