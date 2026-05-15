# Custodia Rust client SDK

`clients/rust` contains the Rust SDK. It includes a raw REST/mTLS transport client for opaque Custodia payloads and a high-level client-side crypto wrapper.

The high-level wrapper uses the shared v1 crypto contract: canonical AAD, AES-256-GCM content encryption and HPKE-v1 recipient envelopes. Plaintext, DEKs and private keys remain local to the caller.

For 0.5.0 the Rust SDK target is no longer transport-only. The supported repository surface includes opaque transport, high-level create/read/share encrypted helpers, checked examples, crate metadata and shared client-crypto vector tests.

## TLS configuration

The default client uses `reqwest` blocking with rustls and local PEM files:

```rust
let client = CustodiaClient::new(CustodiaClientConfig::new(
    "https://vault:8443",
    "client.crt",
    "client.key",
    "ca.crt",
))?;
```

## Package readiness

`clients/rust/Cargo.toml` documents the intended crates.io package metadata, repository and documentation links while keeping `publish = false`. Registry publication remains blocked by the SDK publishing readiness checklist until ownership, release evidence and compatibility gates are complete and explicitly approved as part of a release.

## Opaque secret payloads

```rust
let payload = serde_json::json!({
    "namespace": "default",
    "key": "db",
    "ciphertext": "base64cipher",
    "envelopes": [{"client_id": "self", "envelope": "base64env"}],
});
let response = client.create_secret_payload(&payload)?;
let secret = client.get_secret_payload_by_key("default", "db")?;
let versions = client.list_secret_version_metadata_by_key("default", "db", Some(50))?;
let access = client.list_secret_access_metadata_by_key("default", "db", Some(50))?;
client.share_secret_payload_by_key("default", "db", &serde_json::json!({"target_client_id":"client_bob","envelope":"base64env","permissions":4}))?;
client.create_secret_version_payload_by_key("default", "db", &serde_json::json!({"ciphertext":"base64cipher2","envelopes":[{"client_id":"self","envelope":"base64env2"}],"permissions":7}))?;
client.revoke_access_by_key("default", "db", "client_bob")?;
client.delete_secret_by_key("default", "db", true)?;
```

The transport client exposes methods for:

- client metadata;
- secret create/read/list/version/share/delete flows;
- pending access grants by `namespace/key`;
- operational status/version/diagnostics;
- revocation status;
- audit event metadata and export artifacts.

## High-level crypto flow

```rust
use custodia_client::{
    CryptoOptions, StaticPrivateKeyProvider, StaticPublicKeyResolver,
    X25519PrivateKeyHandle,
};
use std::sync::Arc;

let private_key = Arc::new(X25519PrivateKeyHandle::new("client_alice", &alice_private_key_bytes)?);
let crypto = client.with_crypto(CryptoOptions::new(
    Arc::new(resolve_public_keys_out_of_band()),
    Arc::new(StaticPrivateKeyProvider::new(private_key)),
));

crypto.create_encrypted_secret_by_key(
    "default",
    "db/password",
    plaintext_bytes,
    &["client_bob".to_string()],
    custodia_client::PERMISSION_ALL,
    None,
)?;
let decrypted = crypto.read_decrypted_secret_by_key("default", "db/password")?;
crypto.share_encrypted_secret_by_key("default", "db/password", "client_charlie", custodia_client::PERMISSION_READ, None)?;

```

The application must provide recipient public keys through `PublicKeyResolver`; Custodia public-key metadata can be one discovery source, but the application remains responsible for trust and pinning.

## Security boundary

The Rust SDK must not log plaintext, ciphertext, envelopes, DEKs, private keys, PEM key material, passphrases or bearer/session material.

It does not fetch Custodia server-published recipient public keys automatically yet; applications provide a resolver and may choose Custodia metadata, pinned files or another trust source.

## Examples

- `clients/rust/examples/keyspace_transport.rs` covers the opaque transport surface.
- `clients/rust/examples/high_level_crypto.rs` covers local high-level encryption, read and share helpers.

## Shared vectors

`clients/rust/tests/vector_test.rs` checks canonical AAD, AES-256-GCM ciphertext and HPKE-v1 envelopes against `testdata/client-crypto/v1/` where applicable.

## Verification

```bash
make test-rust-client
```

## Dependency lockfile

`clients/rust/Cargo.lock` is intentionally committed after it is generated on a Rust-enabled workstation. The lockfile keeps the Rust client reproducible on the documented minimum toolchain, Cargo/Rust 1.86, and prevents dependency drift toward crates that require Edition 2024.

`clients/rust/target/` is local build output and must not be committed.
