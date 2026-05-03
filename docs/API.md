# Custodia API

All `/v1/*` routes require mTLS. The authenticated `client_id` is extracted from the client certificate SAN/CN and mapped to an active row in `clients`. JSON request bodies must use `Content-Type: application/json`, are capped at 1 MiB and must contain a single JSON value.


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

## Secret metadata list

`GET /v1/secrets`

Returns metadata for secrets whose latest active version is readable by the caller. The response does not include ciphertext, envelopes, plaintext or key material.

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

## Audit events

`GET /v1/audit-events?limit=100`

Requires an admin mTLS client. Returns recent hash-chained audit events for operational review. `limit` must be between `1` and `500`; the default is `100`.

`GET /v1/audit-events/verify?limit=500`

Requires an admin mTLS client. Recomputes and verifies the recent audit hash-chain without exposing secret ciphertext or envelopes. The response includes `valid`, `verified_events`, `head_hash` and optional failure diagnostics.

## Permission bitmask

Custodia accepts only explicit permission bitmasks made from the documented bits:

- `1` = `share`
- `2` = `write`
- `4` = `read`

Valid requests must use a non-zero combination of these bits, for example `4` for read-only or `7` for read/write/share. Unknown bits and `0` are rejected instead of being silently stored.

## Optional access expiration

Create, share, new-version and pending grant request payloads may include `expires_at` as an RFC3339 timestamp. Expirations must be in the future. Expired grants stop future reads; already downloaded ciphertext and envelope remain outside server control.


## Opaque payload encoding

`ciphertext` and `envelope` are cryptographic blobs owned by clients, but the JSON transport format is base64. Custodia validates only base64 syntax and duplicate recipients; it does not decrypt, unwrap, parse algorithms, inspect DEKs or infer key material from the decoded bytes.


## Web console

`GET /web/`

The current web console shell is protected by the same mTLS admin guard as admin APIs until the dedicated username/password + MFA/passkey web authentication flow is implemented. It is metadata-only and must not expose plaintext, ciphertext reads, envelopes or client-side key material.


## Request correlation

Every HTTP response includes an `X-Request-ID` header. If the caller sends a bounded printable `X-Request-ID`, Custodia propagates it; otherwise the server generates one. Audit metadata includes the same `request_id` so operators can correlate API responses, web-console requests and immutable audit events without exposing plaintext, ciphertext internals or client-side key material.


## Runtime diagnostics

`GET /v1/diagnostics` is admin-only and returns operational runtime metadata: start time, uptime, goroutine count and memory counters. It does not expose secret payloads, envelopes or client-side cryptographic material.

## Signer revocation serial status

When pointed at `custodia-signer`, admin clients may query CRL-backed certificate status by serial number:

```text
GET /v1/revocation/serial?serial_hex=<hex>
```

The response is JSON and returns `good` or `revoked` plus CRL update metadata. This endpoint is an operational JSON responder backed by the configured CRL, not a binary OCSP responder.

## Web passkey challenge preverification

When passkeys are enabled, the metadata-only web console exposes challenge preverification endpoints:

```text
POST /web/passkey/register/verify
POST /web/passkey/authenticate/verify
```

The request body contains base64url-encoded `clientDataJSON`:

```json
{"client_data_json":"..."}
```

The server checks `type`, `challenge`, `origin`, TTL and consume-once semantics. These endpoints do not replace full WebAuthn credential registration/assertion verification.

### Passkey credential metadata preverification

`POST /web/passkey/register/verify` accepts `credential_id` together with
`client_data_json`. After challenge, type and origin preverification, the server
stores metadata for the credential id and owning client. It may also accept
`authenticator_data` as base64url WebAuthn authenticator data; when present, the
parsed signature counter is stored with credential metadata.

`POST /web/passkey/authenticate/verify` also requires `credential_id`. The
credential id must already be registered for the mTLS/web client before the
challenge can be consumed successfully. When `authenticator_data` is present, the
parsed signature counter must increase over the stored counter for that
credential.

This API remains a passkey preverification boundary. It parses authenticator data
headers and enforces counters when supplied, but it does not verify COSE public
keys, attestation objects or WebAuthn signatures.
