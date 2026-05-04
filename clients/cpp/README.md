# Custodia C++ transport client

This package contains the initial C++ transport client for Custodia. It is a raw REST/mTLS client: callers send and receive opaque payloads that already contain ciphertext, envelopes and crypto metadata produced by application-side crypto code.

The implementation uses libcurl for HTTPS and client certificate handling. It does not implement high-level encryption yet and must not log plaintext, ciphertext, envelopes, DEKs, private keys or passphrases.

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

This package is transport-only. It does not resolve recipient public keys, decrypt envelopes, decrypt ciphertext or contact the server for key material.
