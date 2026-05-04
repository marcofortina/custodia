# Custodia Rust client SDK

`clients/rust` is the repository Rust transport client for Custodia. It is a Phase 5 transport SDK for opaque REST/mTLS payloads.

## Boundary

The Rust client is transport-only:

- it authenticates to Custodia with mTLS;
- it sends and receives already-opaque `ciphertext`, `crypto_metadata` and recipient `envelope` fields;
- it does not encrypt or decrypt payloads;
- it does not resolve recipient public keys;
- it does not log plaintext, DEKs, private keys, passphrases, ciphertext or envelopes;
- it does not retry mutating requests automatically.

High-level Rust crypto helpers are intentionally left for a later phase. The shared crypto vectors remain the contract that any future Rust crypto wrapper must pass.

## Configuration

```rust
use custodia_client::{CustodiaClient, CustodiaClientConfig};

let config = CustodiaClientConfig::new(
    "https://vault.example.test:8443",
    "client.crt",
    "client.key",
    "ca.crt",
);
let client = CustodiaClient::new(config)?;
```

## Transport operations

The client exposes opaque payload methods for:

- client metadata: `current_client_info`, `list_client_infos`, `get_client_info`, `create_client_info`, `revoke_client_info`;
- secrets: `create_secret_payload`, `get_secret_payload`, `list_secret_metadata`, `list_secret_version_metadata`, `list_secret_access_metadata`, `create_secret_version_payload`;
- grants and sharing: `share_secret_payload`, `create_access_grant`, `activate_access_grant_payload`, `revoke_access`, `list_access_grant_metadata`;
- operations: `status_info`, `version_info`, `diagnostics_info`, `revocation_status_info`, `revocation_serial_status_info`;
- audit: `list_audit_event_metadata`, `export_audit_event_artifact`.

## Example

```rust
use custodia_client::{CustodiaClient, CustodiaClientConfig, PERMISSION_ALL};
use serde_json::json;

let client = CustodiaClient::new(CustodiaClientConfig::new(
    "https://vault.example.test:8443",
    "client.crt",
    "client.key",
    "ca.crt",
))?;

let created = client.create_secret_payload(&json!({
    "name": "db/password",
    "ciphertext": "base64-already-encrypted-data",
    "crypto_metadata": { "format": "client-defined" },
    "envelopes": [
        { "client_id": "client_alice", "envelope": "base64-envelope-for-alice" }
    ],
    "permissions": PERMISSION_ALL
}))?;
```

## Verification

```bash
make test-rust-client
```

The target runs `cargo test --manifest-path clients/rust/Cargo.toml` when Cargo is installed. In environments without Cargo it exits successfully with a clear skip message so the repository release check remains usable on Go/Python/Node/Java/C++ builders.
