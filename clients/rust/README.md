# Custodia Rust client

`clients/rust` is the repository Rust transport client for Custodia opaque REST/mTLS payloads.

The client is intentionally transport-only in Phase 5. It sends ciphertext, `crypto_metadata` and recipient envelopes that were already produced outside the server. It does not implement high-level client-side encryption and does not resolve recipient public keys through Custodia.

## Boundary

- mTLS is configured with local client cert/key and Custodia CA files.
- Payloads remain opaque to the transport client.
- No plaintext, DEK, private key, passphrase, ciphertext or envelope is logged.
- Retry policy is left to the caller; mutating requests are not retried automatically.

## Test

```bash
make test-rust-client
```

The repository target runs `cargo test` when Cargo is installed and skips with a clear message otherwise.
