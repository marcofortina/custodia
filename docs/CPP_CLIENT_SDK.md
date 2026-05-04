# Custodia C++ transport SDK

`clients/cpp` contains the initial C++ transport SDK. It is a raw REST/mTLS client for opaque Custodia payloads.

The C++ SDK does not implement high-level client-side crypto yet. Applications must encrypt plaintext, create recipient envelopes and decrypt responses outside the server boundary.

## TLS configuration

The default client uses libcurl for HTTPS/mTLS:

```cpp
custodia::Client client(custodia::Config{
    .server_url = "https://vault:8443",
    .cert_file = "client.crt",
    .key_file = "client.key",
    .ca_file = "ca.crt",
});
```

The build check requires a C++20 compiler, `pkg-config` and libcurl development headers.

## Opaque secret payloads

```cpp
std::string response = client.create_secret_payload(
    R"({"name":"db","ciphertext":"base64cipher","envelopes":[{"client_id":"self","envelope":"base64env"}]})"
);

std::string secret = client.get_secret_payload("550e8400-e29b-41d4-a716-446655440000");
```

The client exposes transport methods for:

- client metadata;
- secret create/read/list/version/share flows;
- pending access grants;
- operational status/version/diagnostics;
- revocation status;
- audit event metadata and export artifacts.

## Security boundary

The C++ SDK must not log plaintext, ciphertext, envelopes, DEKs, private keys or passphrases.

It does not contact Custodia for recipient public keys and does not treat the server as a key directory.

## Verification

```bash
make test-cpp-client
```
