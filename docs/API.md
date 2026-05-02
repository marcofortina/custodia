# Custodia API

All `/v1/*` routes require mTLS. The authenticated `client_id` is extracted from the client certificate SAN/CN and mapped to an active row in `clients`.

## Secret create

`POST /v1/secrets`

Stores a ciphertext and opaque recipient envelopes. The caller must include its own envelope.

## Secret read

`GET /v1/secrets/{secret_id}`

Returns the latest readable version for the caller only:

```json
{
  "secret_id": "...",
  "version_id": "...",
  "ciphertext": "base64-or-client-defined-string",
  "crypto_metadata": {},
  "envelope": "caller-envelope-only",
  "permissions": 7
}
```

## Secret share

`POST /v1/secrets/{secret_id}/share`

Requires the caller to have `share` on the selected version. The request must include an envelope generated client-side for the target client.

## Secret new version

`POST /v1/secrets/{secret_id}/versions`

Requires `write`. Used for strong revocation and client-side cryptographic rotation by uploading new ciphertext and new opaque envelopes.

## Revocation

`DELETE /v1/secrets/{secret_id}/access/{client_id}`

Stops future reads for the target client. Previously downloaded ciphertext and envelope remain outside server control.
