# Custodia SDK examples and compatibility matrix

This document is the developer-facing entry point for the Custodia SDK examples and language compatibility status. It complements [`CLIENT_LIBRARIES.md`](CLIENT_LIBRARIES.md), [`SDK_PUBLISHING_READINESS.md`](SDK_PUBLISHING_READINESS.md) and [`SDK_TEST_VECTORS.md`](SDK_TEST_VECTORS.md).

All SDKs must preserve the Custodia security boundary: clients may encrypt, decrypt and create recipient envelopes locally, but the server receives only metadata, opaque ciphertext, opaque envelopes and crypto metadata. SDK documentation and examples must not teach workflows that send plaintext, DEKs or private keys to the server.

## Example index

| Language | Transport example | High-level crypto example | Documentation |
| --- | --- | --- | --- |
| Go | `pkg/client/examples_test.go` | `pkg/client/examples_test.go` | [`GO_CLIENT_SDK.md`](GO_CLIENT_SDK.md) |
| Python | `clients/python/examples/keyspace_transport.py` | `clients/python/examples/high_level_crypto.py` | [`PYTHON_CLIENT_SDK.md`](PYTHON_CLIENT_SDK.md) |
| Node.js / TypeScript | `clients/node/examples/keyspace_transport.mjs` | `clients/node/examples/high_level_crypto.mjs` | [`NODE_CLIENT_SDK.md`](NODE_CLIENT_SDK.md) |
| Java | `clients/java/examples/KeyspaceTransportExample.java` | `clients/java/examples/HighLevelCryptoExample.java` | [`JAVA_CLIENT_SDK.md`](JAVA_CLIENT_SDK.md) |
| C++ | `docs/CPP_CLIENT_SDK.md` | `docs/CPP_CLIENT_SDK.md` | [`CPP_CLIENT_SDK.md`](CPP_CLIENT_SDK.md) |
| Rust | `clients/rust/examples/keyspace_transport.rs` | `clients/rust/examples/high_level_crypto.rs` | [`RUST_CLIENT_SDK.md`](RUST_CLIENT_SDK.md) |
| Bash | `clients/bash/README.md` | Delegates to `custodia-client` | [`BASH_SDK.md`](BASH_SDK.md) |

The repository examples intentionally use source-tree paths instead of registry install commands. Native package registry publication remains blocked by the SDK publishing readiness checklist until every remaining gate is explicitly approved as part of a release.

## Compatibility matrix

| Feature | Go | Python | Node.js / TypeScript | Java | C++ | Rust | Bash |
| --- | --- | --- | --- | --- | --- | --- | --- |
| mTLS transport client | Yes | Yes | Yes | Yes | Yes | Yes | Via `custodia-client` |
| `namespace/key` create/read/share/version helpers | Yes | Yes | Yes | Yes | Yes | Yes | Via `custodia-client` |
| High-level client-side crypto helpers | Yes | Yes | Yes | Yes | Yes | Yes | Via `custodia-client` |
| Shared v1 crypto vector coverage | Yes | Yes | Yes | Yes | Yes | Yes | Via `custodia-client` |
| Package metadata reviewed for registry readiness | Go module pending | PyPI pending | npm pending | Maven pending | Source snapshot only | crates.io pending | Linux helper only |
| Native registry publishing enabled | No | No | No | No | No | No | No |

## Transport-only limitations

No language SDK in the 0.5.0 maturity target is documented as transport-only for its repository status: Go, Python, Node.js, Java, C++ and Rust all have high-level client-side crypto documentation. Bash remains a helper layer that delegates transport and encryption to the `custodia-client` CLI rather than implementing native Bash cryptography.

Applications may still choose the transport layer directly when they already create opaque ciphertext, envelopes and crypto metadata outside the SDK. In that mode the SDK must treat secret material as opaque and must not inspect, decrypt or log ciphertext and envelopes.

## Compatibility rules

- Public SDK flows use `namespace/key`; generated storage ids are internal storage, audit or FK details.
- High-level crypto SDKs bind canonical AAD to `namespace`, `key` and `secret_version`.
- Server-side workflows remain metadata-only.
- Public-key trust remains an application decision; Custodia server-published public keys are discovery metadata only.
- Shared vector changes must update [`SDK_TEST_VECTORS.md`](SDK_TEST_VECTORS.md), `testdata/client-crypto/manifest.json` and the affected SDK tests.
- Registry publishing remains blocked until the remaining gates in [`SDK_PUBLISHING_READINESS.md`](SDK_PUBLISHING_READINESS.md) are completed and explicitly approved as part of a release.

## Verification commands

Use these commands when changing SDK examples or compatibility claims:

```bash
go test -p=1 -timeout 60s ./internal/clientcrypto ./pkg/client
python3 -m unittest discover -s clients/python/tests
npm test --prefix clients/node
make test-rust-client
make test-java-client
make build-sdk
VERSION=0.5.0 REVISION=1 PACKAGE_NAMES=sdk PACKAGE_FORMATS=deb ./scripts/package-smoke.sh
```

Run language-specific commands only when the required toolchain is installed. CI must report toolchain skips explicitly rather than silently treating missing tools as full language coverage.
