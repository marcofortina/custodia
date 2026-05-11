# Custodia client libraries

Custodia client libraries allow applications to talk to the Custodia API while preserving the end-to-end crypto boundary. The server authenticates and authorizes clients, but it never receives plaintext, DEKs, private keys, or application-level decryption material.

This document is the canonical repository-level client specification for the implemented SDK and CLI surfaces. Use the implementation and verification matrix below as the source of truth for repository status.

The repository contains two client layers:

1. **Transport clients** send and receive already-opaque REST payloads over mTLS.
2. **High-level crypto clients** encrypt plaintext locally, build recipient envelopes locally, call the transport client, and decrypt authorized responses locally.

The Go `custodia-client` command is the repository-provided encrypted secrets CLI for end-user put/get/share/version, access revoke/delete, metadata inspection and standard per-user JSON profile UX. The Bash helper is a sourceable shell wrapper around that CLI; it does not implement native Bash cryptography.

## Repository status

Go, Python, Node.js/TypeScript, Java, C++ and Rust provide repository-level transport plus high-level crypto surfaces. Bash is included as a sourceable helper for CI, smoke tests and operational scripts that delegate encryption and transport to `custodia-client`.

The public registry publication status remains separate from repository implementation status. Until release channels are published, language packages are monorepo source snapshots governed by the SDK release policy.

## SDK capability matrix

| Client | Repository path | Transport REST/mTLS | High-level crypto | Notes |
| --- | --- | --- | --- | --- |
| Go | `pkg/client` | Yes | Yes | Public transport, operational, and crypto APIs. |
| Python | `clients/python` | Yes | Yes | Typed transport and HPKE-v1/AES-GCM crypto wrapper. |
| Node.js / TypeScript | `clients/node` | Yes | Yes | Dependency-free runtime JavaScript plus TypeScript declarations. |
| Java | `clients/java` | Yes | Yes | `java.net.http`, Java TLS configuration, and local crypto. |
| C++ | `clients/cpp` | Yes | Yes | libcurl transport and OpenSSL crypto. |
| Rust | `clients/rust` | Yes | Yes | reqwest/rustls transport and local crypto. |
| Go CLI | `cmd/custodia-client` | Yes | Yes | Encrypted put/get/share/version, access revoke/delete, metadata inspection and reusable JSON client profile UX. |
| Bash | `clients/bash` | Via `custodia-client` | Via `custodia-client` | Sourceable shell helper for CI and operational scripts. |

A client is considered repository-official when it has:

- source code in the repository;
- reproducible tests;
- documentation;
- safe logging defaults;
- timeout and retry policy;
- shared crypto vector coverage when it implements high-level crypto.

Publishing packages to external registries is a separate release activity and is governed by the SDK release policy.

## Transport client contract

Transport clients must treat secret material as opaque. They may serialize and send:

- `namespace`;
- `key`;
- `ciphertext`;
- `crypto_metadata`;
- recipient `envelopes`;
- access grants;
- operational request parameters.

Transport clients must not:

- decrypt ciphertext;
- parse envelope internals;
- log plaintext, ciphertext, envelopes, DEKs, private keys, passphrases, bearer material, or mTLS private keys;
- retry non-idempotent writes unless an explicit idempotency mechanism exists.

Recommended retry policy:

| Operation | Retry default |
| --- | --- |
| `GET`, list, status, diagnostics | Allowed with bounded backoff. |
| `POST`, `PUT`, `PATCH`, `DELETE` | Disabled by default unless idempotency is explicit. |

## High-level crypto client contract

High-level crypto clients use the shared client crypto specification and common vectors. They must provide:

- local DEK generation;
- AES-256-GCM content encryption;
- HPKE-v1 recipient envelopes;
- canonical AAD generation;
- versioned crypto metadata;
- public-key resolution outside the server;
- local private-key handling outside the server;
- clear errors for tampered ciphertext, AAD mismatch, wrong recipient, and unsupported crypto versions.

The server is never a public-key directory and never participates in application-level encryption or decryption.

## Shared crypto metadata

High-level crypto clients persist enough metadata for deterministic read/decrypt behavior without server-side interpretation:

```json
{
  "version": "custodia.client-crypto.v1",
  "content_cipher": "aes-256-gcm",
  "envelope_scheme": "hpke-v1",
  "content_nonce_b64": "base64url-or-base64-nonce",
  "aad": {
    "namespace": "db01",
    "key": "user:sys",
    "secret_version": 1
  }
}
```

The exact schema is defined by the client crypto specification and verified by shared vectors.

## Common operations

High-level clients expose equivalent operations across languages:

| Operation | Description |
| --- | --- |
| `CreateEncryptedSecret` with `namespace/key` request fields | Encrypt plaintext locally and create opaque server payloads. |
| `ReadDecryptedSecretByKey` | Fetch authorized opaque payloads by `namespace/key` and decrypt locally. |
| `ShareEncryptedSecretByKey` | Rewrap an existing DEK for a new recipient locally, addressed by `namespace/key`. |
| `CreateEncryptedSecretVersionByKey` | Create a new locally encrypted version for `namespace/key`. |

Transport clients expose raw equivalents that accept already prepared opaque payloads. Normal read/share/version/revoke/delete/access-request flows address secrets by `namespace` and `key`; generated server identifiers are internal storage/FK/audit correlation details and are not part of the public SDK workflow surface.

## Key resolution

Recipient public keys are resolved outside Custodia. Valid resolvers include:

- local files;
- application configuration;
- enterprise KMS or directory service;
- pinned keys;
- provisioning systems;
- out-of-band trust channels.

Custodia stores only the target `client_id` and opaque envelope payload.

## Bash helper and external crypto providers

`clients/bash/custodia.bash` is a sourceable Bash SDK helper around `custodia-client` profiles. It is useful for CI/CD and operational shell scripts that want functions instead of invoking raw commands directly.

The helper does not implement cryptography. It delegates to `custodia-client`, so crypto behavior follows the same shared vector contract as the Go client CLI.

## Package layout

Linux packages provide three installable groups:

| Package | Contents |
| --- | --- |
| `custodia-server` | server binaries, `custodia-admin`, signer, systemd units, server docs, YAML examples and SQLite backup helper. |
| `custodia-client` | `custodia-client` encrypted secrets CLI. |
| `custodia-sdk` | SDK source snapshots, sourceable Bash SDK helper, shared crypto vectors and SDK docs. |

External language registry publishing remains future release work.

## Canonical source of truth

Use these repository documents as the current source of truth:

- [`CLIENT_LIBRARIES.md`](CLIENT_LIBRARIES.md): SDK capability and boundary matrix.
- [`CUSTODIA_CLIENT_CLI.md`](CUSTODIA_CLIENT_CLI.md): encrypted secrets CLI usage.
- [`CLIENT_CRYPTO_SPEC.md`](CLIENT_CRYPTO_SPEC.md): shared crypto metadata, AAD, AEAD and envelope contract.
- [Project History Wiki](https://github.com/marcofortina/custodia/wiki/Project-History): development-history notes and phase closure records.
- [`SDK_RELEASE_POLICY.md`](SDK_RELEASE_POLICY.md): official SDK and public package release criteria.

Design notes outside the repository are non-authoritative until they are synchronized into this matrix and the SDK-specific documents.

## Verification targets

Useful targets:

```bash
make test-client-crypto
make test-python-client
make test-node-client
make test-java-client
make test-cpp-client
make test-rust-client
make test-bash-client
```

Release checks call the language-specific targets when the required toolchains are available.


## CLI validation helpers

`custodia-client config check --client-id ID` validates standard per-user profiles and referenced mTLS/crypto files. `custodia-client key inspect` reports a local X25519 key fingerprint without exposing private key material.


## End-to-end smoke test

The canonical copy/paste smoke workflow for the installable CLI is [`CUSTODIA_ALICE_BOB_SMOKE.md`](CUSTODIA_ALICE_BOB_SMOKE.md). It verifies Alice/Bob mTLS issuance, local X25519 keys, encrypted put/get, share, versioning and access revocation.
