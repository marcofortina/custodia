# Custodia Python client SDK

`clients/python/custodia_client` is the repository Python client for Custodia. Phase 5 adds typed transport payload helpers and a high-level crypto wrapper while keeping the server payloads opaque.

## Current scope

The Python client is importable and speaks the Custodia REST API over mTLS. It now has two layers:

- raw transport helpers for callers that already provide opaque ciphertext and envelopes;
- a high-level crypto wrapper that encrypts/decrypts locally, creates HPKE-v1 envelopes and uses application-provided key resolvers.

The server still receives only ciphertext, `crypto_metadata` and recipient envelopes. It never receives plaintext, DEK material or private keys.

## Install from the monorepo

```bash
pip install ./clients/python
```

## Typed transport payloads

For new code, prefer the typed payload helpers. They still transport opaque ciphertext and envelope strings; they do not perform local encryption or decryption.

```python
from custodia_client import (
    CustodiaClient,
    CreateSecretPayload,
    PermissionRead,
    RecipientEnvelope,
)

client = CustodiaClient(
    server_url="https://vault.example:8443",
    cert_file="client.crt",
    key_file="client.key",
    ca_file="ca.crt",
)

created = client.create_secret_payload(
    CreateSecretPayload(
        name="database-password",
        ciphertext="base64-opaque-ciphertext",
        envelopes=[RecipientEnvelope("client_alice", "base64-opaque-envelope")],
        permissions=PermissionRead,
    )
)
```

## High-level crypto wrapper

Use `CustodiaClient.with_crypto(CryptoOptions(...))` when the application wants
the SDK to encrypt/decrypt locally. The wrapper supports:

- `create_encrypted_secret(...)`;
- `read_decrypted_secret(...)`;
- `share_encrypted_secret(...)`;
- `create_encrypted_secret_version(...)`.

```python
from custodia_client import (
    CryptoOptions,
    CustodiaClient,
    StaticPrivateKeyProvider,
    StaticPublicKeyResolver,
    X25519PrivateKeyHandle,
    derive_x25519_recipient_public_key,
)

alice_private = load_alice_private_key_from_local_storage()
bob_public = load_bob_public_key_from_pinned_directory()

client = CustodiaClient("https://vault.example:8443", "client.crt", "client.key", "ca.crt")
crypto = client.with_crypto(CryptoOptions(
    public_key_resolver=StaticPublicKeyResolver({
        "client_bob": bob_public,
        "client_alice": derive_x25519_recipient_public_key("client_alice", alice_private),
    }),
    private_key_provider=StaticPrivateKeyProvider(
        X25519PrivateKeyHandle("client_alice", alice_private),
    ),
))

created = crypto.create_encrypted_secret(
    name="database-password",
    plaintext=b"correct horse battery staple",
    recipients=["client_bob"],
)
```

`StaticPublicKeyResolver` is a small helper for pinned/local maps and tests.
Production code should plug in a resolver backed by trusted local provisioning,
KMS or an enterprise directory outside Custodia.

## Raw dictionary example

```python
from custodia_client import CustodiaClient

client = CustodiaClient(
    server_url="https://vault.example:8443",
    cert_file="client.crt",
    key_file="client.key",
    ca_file="ca.crt",
)

created = client.create_secret({
    "name": "database-password",
    "ciphertext": "base64-opaque-ciphertext",
    "envelopes": [
        {"client_id": "client_alice", "envelope": "base64-opaque-envelope"},
    ],
    "permissions": 4,
})
```

Do not pass plaintext or client key material to the transport client.

## Verification

Run:

```bash
make test-python-client
python3 -m py_compile clients/python/custodia_client/__init__.py clients/python/custodia_client/types.py clients/python/custodia_client/crypto.py
```
