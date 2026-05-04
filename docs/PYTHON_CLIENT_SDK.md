# Custodia Python client SDK

`clients/python/custodia_client` is the repository Python transport client for Custodia. Phase 5 adds typed transport payload helpers while keeping the server payloads opaque.

## Current scope

The Python client is importable and speaks the Custodia REST API over mTLS. It is still a transport client:

- callers provide already-opaque ciphertext and envelopes;
- the client sends JSON payloads to `/v1/*`;
- the client returns server JSON responses;
- the client does not encrypt plaintext, unwrap envelopes or resolve recipient public keys.

High-level crypto helpers are planned after the shared client crypto specification and deterministic test vectors are completed.

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
python3 -m py_compile clients/python/custodia_client/__init__.py clients/python/custodia_client/types.py
```
