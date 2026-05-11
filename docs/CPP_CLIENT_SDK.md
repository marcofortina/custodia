# Custodia C++ SDK

`clients/cpp` contains the C++ SDK. It includes a raw REST/mTLS transport client for opaque Custodia payloads and a high-level client-side crypto wrapper.

The high-level wrapper uses the shared v1 crypto contract: canonical AAD, AES-256-GCM content encryption and HPKE-v1 recipient envelopes. Plaintext, DEKs and private keys remain local to the caller.

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

The build check requires a C++20 compiler, `pkg-config`, libcurl development headers and OpenSSL development headers.

## Opaque secret payloads

```cpp
std::string response = client.create_secret_payload(
    R"({"namespace":"default","key":"db","ciphertext":"base64cipher","envelopes":[{"client_id":"self","envelope":"base64env"}]})"
);

std::string secret = client.get_secret_payload_by_key("default", "db");
std::string versions = client.list_secret_version_metadata_by_key("default", "db", 50);
std::string access = client.list_secret_access_metadata_by_key("default", "db", 50);
client.share_secret_payload_by_key("default", "db", R"({"target_client_id":"client_bob","envelope":"base64env","permissions":4})");
client.create_secret_version_payload_by_key("default", "db", R"({"ciphertext":"base64cipher2","envelopes":[{"client_id":"self","envelope":"base64env2"}],"permissions":7})");
client.revoke_access_by_key("default", "db", "client_bob");
client.delete_secret_by_key("default", "db", true);
```

The client exposes transport methods for:

- client metadata;
- secret create/read/list/version/share/delete flows;
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


## High-level crypto flow

```cpp
auto crypto = client.with_crypto(custodia::CryptoOptions{
    .public_key_resolver = [](const std::string& recipient_id) {
      return resolve_recipient_public_key_out_of_band(recipient_id);
    },
    .private_key = custodia::X25519PrivateKeyHandle("client_alice", alice_private_key_bytes),
});

crypto.create_encrypted_secret_by_key("default", "db", plaintext_bytes, {"client_bob"});
auto decrypted = crypto.read_decrypted_secret_by_key("default", "db");
crypto.share_encrypted_secret_by_key("default", "db", "client_charlie", custodia::permission_read);
crypto.create_encrypted_secret_version_by_key("default", "db", rotated_plaintext_bytes, {"client_bob"});
```

The application must provide recipient public keys through `public_key_resolver`; Custodia is not a key directory.
