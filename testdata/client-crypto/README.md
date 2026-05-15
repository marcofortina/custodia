# Custodia client crypto test vectors

The shared client crypto test vectors live under versioned directories:

```text
testdata/client-crypto/v1/
```

The current vector set is `custodia.client-crypto.v1`. It covers canonical AAD construction, namespace/key metadata, AES-256-GCM content ciphertext, HPKE-v1 recipient envelopes and negative decrypt paths.

These fixtures are for SDK compatibility tests only. Fixture private keys, DEKs, nonces and plaintext values are deterministic test material and must never be copied into production clients.

## Versioning model

A new vector directory is required when any of these change:

- crypto metadata version;
- canonical AAD field set or ordering;
- namespace/key semantics encoded into AAD;
- content cipher or nonce encoding;
- envelope scheme or recipient envelope format;
- expected negative error behavior for tampered ciphertext, AAD mismatch, wrong recipient or unsupported crypto versions.

Patch-level fixture additions can be made in the current directory only when they preserve the existing `custodia.client-crypto.v1` semantics.

## Metadata-only boundary

Vectors intentionally separate local client material from server-visible payloads:

- plaintext is local fixture input only;
- content DEKs and private keys are local fixture material only;
- server-visible payloads are limited to opaque ciphertext, opaque envelopes and crypto metadata;
- namespace/key and version fields are included in canonical AAD so SDKs bind ciphertext to the documented keyspace workflow.

## Current consumers

The initial v1 vectors are validated by multiple SDK test suites:

- Go/internal vector loader: `go test -p=1 -timeout 60s ./internal/clientcrypto`;
- Python SDK: `python3 -m unittest discover -s clients/python/tests`;
- Node SDK: `npm test --prefix clients/node`;
- Rust SDK: `make test-rust-client`.

Java currently validates the same deterministic crypto values in its Java test path; adding direct JSON fixture loading remains a future hardening option if needed.
