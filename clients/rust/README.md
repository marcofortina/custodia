# Custodia Rust client

`clients/rust` is the repository Rust client for Custodia opaque REST/mTLS payloads and local client-side crypto flows.

It includes:

- a transport REST/mTLS client for already-opaque payloads;
- a high-level crypto wrapper using the shared v1 contract: canonical AAD, AES-256-GCM content encryption and HPKE-v1 recipient envelopes.

The crypto wrapper encrypts/decrypts locally and must not log plaintext, ciphertext, envelopes, DEKs, private keys or passphrases. Recipient public keys are resolved by the application, not by Custodia.

## Boundary

- mTLS is configured with local client cert/key and Custodia CA files.
- Transport methods keep payloads opaque.
- Crypto methods keep plaintext, DEKs and private keys local to the caller.
- No plaintext, DEK, private key, passphrase, ciphertext or envelope is logged.
- Retry policy is left to the caller; mutating requests are not retried automatically.

## Example

```rust
use custodia_client::{
    CustodiaClient, CustodiaClientConfig, CryptoOptions, StaticPrivateKeyProvider,
    StaticPublicKeyResolver, X25519PrivateKeyHandle,
};
use std::sync::Arc;

let client = CustodiaClient::new(CustodiaClientConfig::new(
    "https://vault:8443",
    "client.crt",
    "client.key",
    "ca.crt",
))?;

let private_key = Arc::new(X25519PrivateKeyHandle::new("client_alice", &alice_private_key_bytes)?);
let crypto = client.with_crypto(CryptoOptions::new(
    Arc::new(resolve_public_keys_out_of_band()),
    Arc::new(StaticPrivateKeyProvider::new(private_key)),
));

crypto.create_encrypted_secret_by_key(
    "default",
    "db/password",
    b"local plaintext",
    &["client_bob".to_string()],
    custodia_client::PERMISSION_ALL,
    None,
)?;

let decrypted = crypto.read_decrypted_secret_by_key("default", "db/password")?;
crypto.share_encrypted_secret_by_key("default", "db/password", "client_charlie", custodia_client::PERMISSION_READ, None)?;
```

## Test

```bash
make test-rust-client
```

The repository target runs `cargo test` when Cargo is installed and skips with a clear message otherwise.

## Dependency lockfile

`clients/rust/Cargo.lock` is intentionally committed after it is generated on a Rust-enabled workstation. The lockfile keeps the Rust client reproducible on the documented minimum toolchain, Cargo/Rust 1.85, and prevents dependency drift toward crates that require Edition 2024.

`clients/rust/target/` is local build output and must not be committed.
