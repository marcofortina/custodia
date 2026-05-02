# Python client

This client only transports already encrypted ciphertext and opaque envelopes. It does not fetch public keys from Custodia and does not ask the server to decrypt anything.

Implemented helpers:

- `create_secret(payload)`
- `list_secrets()` metadata-only, no ciphertext or envelopes
- `get_secret(secret_id)`
- `share_secret(secret_id, payload)`
- `request_access_grant(secret_id, payload)`
- `activate_access_grant(secret_id, client_id, payload)`
- `revoke_access(secret_id, client_id)`
- `create_secret_version(secret_id, payload)`
- `delete_secret(secret_id)`

Dynamic path segments are URL-escaped. Payloads remain caller-defined JSON with base64 ciphertext/envelope strings; the Python client does not perform key discovery or server-side crypto.
