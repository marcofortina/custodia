# Python client

This client provides both the raw transport helpers and the Phase 5 high-level crypto wrapper. The crypto wrapper encrypts/decrypts locally and still does not fetch public keys from Custodia or ask the server to decrypt anything.

Implemented helpers:

- `me()` authenticated client metadata
- `list_clients()` admin metadata-only
- `get_client(client_id)` admin metadata-only
- `create_client(payload)` admin metadata-only; certificate signing remains external
- `revoke_client(payload)` admin metadata-only
- `list_access_grant_requests(namespace=None, key=None)` admin metadata-only, no envelopes
- `create_secret(payload)`
- `list_secrets()` metadata-only, no ciphertext or envelopes
- `get_secret_by_key(namespace, key)` user-facing lookup
- `list_secret_versions_by_key(namespace, key)` metadata-only, no ciphertext or crypto metadata
- `list_secret_access_by_key(namespace, key)` metadata-only, no envelopes
- `status()` admin metadata-only operational status
- `share_secret_by_key(namespace, key, payload)` user-facing lookup
- `revoke_access_by_key(namespace, key, client_id)` user-facing revoke
- `request_access_grant_by_key(namespace, key, payload)`
- `activate_access_grant_by_key(namespace, key, client_id, payload)`
- `create_secret_version_by_key(namespace, key, payload)` user-facing lookup
- `delete_secret_by_key(namespace, key, cascade=False)` user-facing lookup

Dynamic path segments are URL-escaped. Raw transport payloads remain caller-defined JSON with base64 ciphertext/envelope strings. The high-level crypto wrapper requires an application-provided public-key resolver and local private-key provider; Custodia never acts as a public-key directory.

## High-level crypto wrapper

The high-level wrapper is available through `client.with_crypto(...)` or
`CryptoCustodiaClient(...)`. It uses AES-256-GCM content encryption and HPKE-v1
recipient envelopes, matching the shared deterministic test vectors under
`testdata/client-crypto/v1/`.

```python
from custodia_client import (
    CryptoOptions,
    CustodiaClient,
    StaticPrivateKeyProvider,
    StaticPublicKeyResolver,
    X25519PrivateKeyHandle,
    derive_x25519_recipient_public_key,
)

alice_private = b"...32 bytes from local key storage..."
bob_private_for_example_only = b"...32 bytes from bob/out-of-band fixture..."

client = CustodiaClient(
    server_url="https://vault.example:8443",
    cert_file="client.crt",
    key_file="client.key",
    ca_file="ca.crt",
)

crypto = client.with_crypto(CryptoOptions(
    public_key_resolver=StaticPublicKeyResolver({
        "client_alice": derive_x25519_recipient_public_key("client_alice", alice_private),
        "client_bob": derive_x25519_recipient_public_key("client_bob", bob_private_for_example_only),
    }),
    private_key_provider=StaticPrivateKeyProvider(
        X25519PrivateKeyHandle("client_alice", alice_private),
    ),
))

created = crypto.create_encrypted_secret_by_key(
    namespace="db01",
    key="user:sys",
    plaintext=b"correct horse battery staple",
    recipients=["client_bob"],
)

secret = crypto.read_decrypted_secret_by_key("db01", "user:sys")
```

The static resolver above is only a minimal example. Production applications
should resolve recipient public keys from local pinned files, KMS, enterprise
directory, provisioning or another trusted channel outside Custodia.

## Audit export

`CustodiaClient.export_audit_events(...)` returns server-generated JSONL text for
metadata-only audit export workflows. It does not expose plaintext, ciphertext or
recipient envelopes.

Use `client.version()` to read server build metadata through the authenticated API.

## Audit export metadata

`CustodiaClient.export_audit_events_with_metadata(...)` returns a dictionary containing:

- `body`: JSONL export text;
- `sha256`: `X-Custodia-Audit-Export-SHA256` response header;
- `event_count`: `X-Custodia-Audit-Export-Events` response header.

Persist these values together when forwarding audit exports to offline storage, SIEM or WORM retention.


## Typed transport payloads

Phase 5 adds typed payload dataclasses such as `CreateSecretPayload`, `RecipientEnvelope`, `ShareSecretPayload`, `AccessGrantPayload` and `CreateSecretVersionPayload`. These helpers only build transport JSON for opaque ciphertext/envelope values; they do not encrypt plaintext or resolve recipient keys.

Run the Python client tests with:

```bash
make test-python-client
```
