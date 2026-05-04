# Custodia Rust client SDK

`clients/rust` contains the Rust SDK. It includes a raw REST/mTLS transport client for opaque Custodia payloads and a high-level client-side crypto wrapper.

The high-level wrapper uses the shared v1 crypto contract: canonical AAD, AES-256-GCM content encryption and HPKE-v1 recipient envelopes. Plaintext, DEKs and private keys remain local to the caller.

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

## Opaque secret payloads

```rust
let payload = serde_json::json!({
    "name": "db",
    "ciphertext": "base64cipher",
    "envelopes": [{"client_id": "self", "envelope": "base64env"}],
});
let response = client.create_secret_payload(&payload)?;
let secret = client.get_secret_payload("550e8400-e29b-41d4-a716-446655440000")?;
```

The transport client exposes methods for:

- client metadata;
- secret create/read/list/version/share flows;
- pending access grants;
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

crypto.create_encrypted_secret(
    "db/password",
    plaintext_bytes,
    &["client_bob".to_string()],
    custodia_client::PERMISSION_ALL,
    None,
)?;
let decrypted = crypto.read_decrypted_secret(secret_id)?;
crypto.share_encrypted_secret(secret_id, "client_charlie", custodia_client::PERMISSION_READ, None)?;
```

The application must provide recipient public keys through `PublicKeyResolver`; Custodia is not a key directory.

## Security boundary

The Rust SDK must not log plaintext, ciphertext, envelopes, DEKs, private keys, PEM key material, passphrases or bearer/session material.

It does not contact Custodia for recipient public keys and does not treat the server as a key directory.

## Verification

```bash
make test-rust-client
```

## Dependency lockfile

`clients/rust/Cargo.lock` is intentionally committed after it is generated on a Rust-enabled workstation. The lockfile keeps the Rust client reproducible on the documented minimum toolchain, Cargo/Rust 1.75, and prevents dependency drift toward crates that require Edition 2024.

`clients/rust/target/` is local build output and must not be committed.
