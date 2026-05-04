# Custodia client libraries

Custodia client libraries allow applications to talk to the Custodia API while preserving the end-to-end crypto boundary. The server authenticates and authorizes clients, but it never receives plaintext, DEKs, private keys, or application-level decryption material.

The repository contains two client layers:

1. **Transport clients** send and receive already-opaque REST payloads over mTLS.
2. **High-level crypto clients** encrypt plaintext locally, build recipient envelopes locally, call the transport client, and decrypt authorized responses locally.

The Bash helper is intentionally different: it is a transport helper with an optional external crypto-provider bridge. It does not implement native Bash cryptography.

## SDK capability matrix

| Client | Repository path | Transport REST/mTLS | High-level crypto | Notes |
| --- | --- | --- | --- | --- |
| Go | `pkg/client` | Yes | Yes | Public transport, operational, and crypto APIs. |
| Python | `clients/python` | Yes | Yes | Typed transport and HPKE-v1/AES-GCM crypto wrapper. |
| Node.js / TypeScript | `clients/node` | Yes | Yes | Dependency-free runtime JavaScript plus TypeScript declarations. |
| Java | `clients/java` | Yes | Yes | `java.net.http`, Java TLS configuration, and local crypto. |
| C++ | `clients/cpp` | Yes | Yes | libcurl transport and OpenSSL crypto. |
| Rust | `clients/rust` | Yes | Yes | reqwest/rustls transport and local crypto. |
| Bash | `clients/bash` | Yes | External provider only | Shell helper for CI and operational scripts. |

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

- `name`;
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
    "schema": "custodia-secret-aad-v1",
    "secret_id": "...",
    "version_id": "..."
  }
}
```

The exact schema is defined by the client crypto specification and verified by shared vectors.

## Common operations

High-level clients expose equivalent operations across languages:

| Operation | Description |
| --- | --- |
| `CreateEncryptedSecret` | Encrypt plaintext locally and create opaque server payloads. |
| `ReadDecryptedSecret` | Fetch authorized opaque payloads and decrypt locally. |
| `ShareEncryptedSecret` | Rewrap an existing DEK for a new recipient locally. |
| `CreateEncryptedSecretVersion` | Create a new locally encrypted version. |

Transport clients expose raw equivalents that accept already prepared opaque payloads.

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

`clients/bash/custodia.sh` is useful for CI/CD, smoke tests, and operational scripts. It can call an external crypto provider through `CUSTODIA_CRYPTO_PROVIDER`.

Provider contract:

```text
$CUSTODIA_CRYPTO_PROVIDER create-encrypted-secret < request.json > create-payload.json
$CUSTODIA_CRYPTO_PROVIDER read-decrypted-secret < raw-secret-response.json > plaintext-response.json
$CUSTODIA_CRYPTO_PROVIDER share-encrypted-secret < request.json > share-payload.json
$CUSTODIA_CRYPTO_PROVIDER create-encrypted-secret-version < request.json > version-payload.json
```

The provider, not Bash, is responsible for cryptography and must follow the shared vector contract if used for production workflows.

## Package layout

Linux packages provide two installable groups:

| Package | Contents |
| --- | --- |
| `custodia-server` | server binaries, `custodia-admin`, signer, systemd unit, server docs and examples. |
| `custodia-clients` | SDK source snapshots, Bash helper, shared crypto vectors, and SDK docs. |

External language registry publishing remains future release work.

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
