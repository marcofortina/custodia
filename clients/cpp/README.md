# Custodia C++ client

This package contains the C++ client for Custodia. It includes the raw REST/mTLS transport client and a high-level client-side crypto wrapper for AES-256-GCM content encryption plus HPKE-v1 recipient envelopes.

The implementation uses libcurl for HTTPS and client certificate handling, and OpenSSL for local high-level crypto. It must not log plaintext, ciphertext, envelopes, DEKs, private keys or passphrases.

## Build check

```bash
make test-cpp-client
```

The check requires a C++20 compiler, `pkg-config` and libcurl development headers.

## Example

```cpp
#include <custodia/client.hpp>

custodia::Client client(custodia::Config{
    .server_url = "https://vault:8443",
    .cert_file = "client.crt",
    .key_file = "client.key",
    .ca_file = "ca.crt",
});

std::string response = client.create_secret_payload(
    R"({"name":"db","ciphertext":"base64cipher","envelopes":[{"client_id":"self","envelope":"base64env"}]})"
);
```

## Boundary

Transport methods are opaque and do not inspect ciphertext, envelopes or `crypto_metadata`. High-level crypto methods encrypt/decrypt locally, use application-provided recipient public keys and never contact Custodia for key material.


## High-level crypto example

```cpp
auto private_key = custodia::X25519PrivateKeyHandle("client_alice", alice_private_key_bytes);
auto crypto = client.with_crypto(custodia::CryptoOptions{
    .public_key_resolver = [](const std::string& recipient_id) {
      return resolve_recipient_public_key_out_of_band(recipient_id);
    },
    .private_key = private_key,
});

crypto.create_encrypted_secret("db", {'l','o','c','a','l',' ','p','l','a','i','n','t','e','x','t'}, {"client_bob"});
auto decrypted = crypto.read_decrypted_secret(secret_id);
```

Recipient public keys are still resolved by the application, not by Custodia.
