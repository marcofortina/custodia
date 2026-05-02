# Custodia API

All `/v1/*` routes require mTLS. The authenticated `client_id` is extracted from the client certificate SAN/CN and mapped to an active row in `clients`.


## Client metadata create

`POST /v1/clients`

Requires an admin mTLS client. Registers a client id and the certificate SAN/CN subject that will be accepted for that client. This endpoint does not generate or sign certificates; CA/signing remains an external administrative service.

```json
{
  "client_id": "client_bob",
  "mtls_subject": "client_bob"
}
```

## Secret create

`POST /v1/secrets`

Stores a base64-encoded ciphertext and base64-encoded opaque recipient envelopes. The caller must include its own envelope. Requests with more than `CUSTODIA_MAX_ENVELOPES_PER_SECRET` recipients are rejected with `413 Payload Too Large`; the default limit is `100`.

## Secret read

`GET /v1/secrets/{secret_id}`

Returns the latest readable version for the caller only:

```json
{
  "secret_id": "...",
  "version_id": "...",
  "ciphertext": "Y2lwaGVydGV4dA==",
  "crypto_metadata": {},
  "envelope": "ZW52ZWxvcGUtZm9yLWFsaWNl",
  "permissions": 7
}
```

## Secret share

`POST /v1/secrets/{secret_id}/share`

Requires the caller to have `share` on the selected version. The request must include a base64-encoded envelope generated client-side for the target client.

## Secret new version

`POST /v1/secrets/{secret_id}/versions`

Requires `write`. Used for strong revocation and client-side cryptographic rotation by uploading new base64-encoded ciphertext and new opaque envelopes. Creating a new version supersedes previous active versions and cancels pending access grants for those versions, so future reads and activations use only the latest client-side material. Requests with more than `CUSTODIA_MAX_ENVELOPES_PER_SECRET` recipients are rejected with `413 Payload Too Large`; the default limit is `100`.

## Access grant request

`POST /v1/secrets/{secret_id}/access-requests`

Requires an admin mTLS client. Creates a pending access request for the latest active version, or for `version_id` when supplied. This does not activate access and does not accept an envelope.

```json
{
  "target_client_id": "client_bob",
  "permissions": 4
}
```

## Access grant activation

`POST /v1/secrets/{secret_id}/access/{client_id}/activate`

Requires the caller to have `share` on the pending request version. The request uploads only the base64 opaque envelope generated client-side for the target client.

```json
{
  "envelope": "ZW52ZWxvcGUtZm9yLWJvYg=="
}
```

## Revocation

`DELETE /v1/secrets/{secret_id}/access/{client_id}`

Stops future reads for the target client. Previously downloaded ciphertext and envelope remain outside server control.

## Permission bitmask

Custodia accepts only explicit permission bitmasks made from the documented bits:

- `1` = `share`
- `2` = `write`
- `4` = `read`

Valid requests must use a non-zero combination of these bits, for example `4` for read-only or `7` for read/write/share. Unknown bits and `0` are rejected instead of being silently stored.

## Opaque payload encoding

`ciphertext` and `envelope` are cryptographic blobs owned by clients, but the JSON transport format is base64. Custodia validates only base64 syntax and duplicate recipients; it does not decrypt, unwrap, parse algorithms, inspect DEKs or infer key material from the decoded bytes.
