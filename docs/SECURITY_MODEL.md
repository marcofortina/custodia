# Security model

## Cryptographic boundary

The server never receives plaintext, DEKs, private keys, public encryption keys or interpretable cryptographic material. It stores and returns only opaque transport fields:

- `ciphertext`
- `crypto_metadata`
- `envelope`

The server does not expose a public-key directory and does not mediate trust between clients. It validates base64 transport syntax for opaque blobs only; this is not cryptographic interpretation.

## Authentication and authorization

- mTLS authenticates the caller.
- The `clients` table maps certificate subject to `client_id`.
- `secret_access` authorizes each `(secret_id, version_id, client_id)` tuple.
- Permissions use a bitmask: share=1, write=2, read=4.

## Revocation semantics

Server-side revocation prevents future reads. Strong revocation requires a new secret version with new client-side ciphertext and new envelopes for the remaining authorized clients. When a new version is created, older active versions are superseded for future server-side operations and pending grants on superseded versions are cancelled.

## Audit semantics

Successful and failed authentication, authorization and metadata operations are audit-recorded. Failure events include a machine-readable reason in audit metadata and remain hash-chained like successful events.

## Admin boundary

Admin metadata APIs are restricted to configured admin client IDs. This does not grant decryption capability.
