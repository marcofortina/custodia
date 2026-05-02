# Python client

This client only transports already encrypted ciphertext and opaque envelopes. It does not fetch public keys from Custodia and does not ask the server to decrypt anything.

Implemented helpers:

- `me()` authenticated client metadata
- `list_clients()` admin metadata-only
- `get_client(client_id)` admin metadata-only
- `create_client(payload)` admin metadata-only; certificate signing remains external
- `revoke_client(payload)` admin metadata-only
- `list_access_grant_requests(secret_id=None)` admin metadata-only, no envelopes
- `create_secret(payload)`
- `list_secrets()` metadata-only, no ciphertext or envelopes
- `get_secret(secret_id)`
- `list_secret_versions(secret_id)` metadata-only, no ciphertext or crypto metadata
- `list_secret_access(secret_id)` metadata-only, no envelopes
- `status()` admin metadata-only operational status
- `share_secret(secret_id, payload)`
- `request_access_grant(secret_id, payload)`
- `activate_access_grant(secret_id, client_id, payload)`
- `revoke_access(secret_id, client_id)`
- `create_secret_version(secret_id, payload)`
- `delete_secret(secret_id)`

Dynamic path segments are URL-escaped. Payloads remain caller-defined JSON with base64 ciphertext/envelope strings; the Python client does not perform key discovery or server-side crypto.

## Audit export

`CustodiaClient.export_audit_events(...)` returns server-generated JSONL text for
metadata-only audit export workflows. It does not expose plaintext, ciphertext or
recipient envelopes.
