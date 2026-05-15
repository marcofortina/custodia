# Custodia SDK test vectors

Custodia SDK test vectors are versioned shared fixtures for cross-language compatibility. They are shipped with the repository and the Linux `custodia-sdk` package.

Current vectors:

```text
testdata/client-crypto/v1/
```

Manifest:

```text
testdata/client-crypto/manifest.json
```

## What v1 covers

`custodia.client-crypto.v1` covers:

- canonical AAD construction;
- namespace/key and secret version binding;
- AES-256-GCM content ciphertext;
- HPKE-v1 recipient envelopes;
- wrong-recipient, AAD-mismatch, ciphertext-tamper and unsupported-version failures.

The vectors intentionally bind ciphertext to the `namespace/key` workflow. SDKs must not reintroduce `secret_id`-centric public crypto APIs when validating or producing high-level crypto payloads.

## Metadata-only boundary

The vectors make the server boundary explicit:

- plaintext is local client input only;
- content DEKs are local client material only;
- recipient private keys and sender ephemeral private keys are fixture-only local material;
- the server-visible payload is limited to opaque ciphertext, opaque recipient envelopes and crypto metadata;
- public-key discovery metadata does not make the server a trust oracle.

Fixture private keys, DEKs, nonces and plaintext values are deterministic test material only. Never copy them into production clients or runbooks.

## Versioning rules

Add a new vector directory, for example `testdata/client-crypto/v2/`, when any of these change:

- crypto metadata version;
- canonical AAD field set or ordering;
- namespace/key semantics encoded into AAD;
- content cipher, nonce format or ciphertext encoding;
- envelope scheme or recipient envelope format;
- negative failure semantics that SDKs must distinguish.

Add fixtures to the current version only when they preserve the current semantics.

When a new vector version is introduced, update:

- `testdata/client-crypto/manifest.json`;
- `docs/CLIENT_CRYPTO_SPEC.md`;
- `docs/SDK_RELEASE_POLICY.md`;
- SDK vector tests for languages that ship high-level crypto;
- release notes for the affected release.

## Current validation commands

Run the shared vector checks with:

```bash
make test-client-crypto
python3 -m unittest discover -s clients/python/tests
npm test --prefix clients/node
make test-rust-client
make test-java-client
```

The first v1 consumers are Go/internal, Python, Node and Rust. Java validates the same deterministic crypto values in its Java test path; direct JSON fixture loading can be added later if the Java client needs stronger fixture-level parity.

## Publishing gate

Registry publishing remains blocked unless the SDK publishing readiness checklist confirms that shared vector tests pass for SDKs that ship high-level crypto.
