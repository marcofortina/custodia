# Custodia web passkey support

Custodia exposes server-side WebAuthn/passkey challenge options for the metadata-only web console.

## Configuration

```bash
CUSTODIA_WEB_PASSKEY_ENABLED=true
CUSTODIA_WEB_PASSKEY_RP_ID=vault.example.com
CUSTODIA_WEB_PASSKEY_RP_NAME=Custodia
CUSTODIA_WEB_PASSKEY_CHALLENGE_TTL_SECONDS=300
```

## Endpoints

The endpoints require admin mTLS and, when enabled, the same MFA web session required by the metadata console.

- `GET /web/passkey/register/options`
- `GET /web/passkey/authenticate/options`

They return metadata-only JSON challenge options:

- challenge;
- relying party ID/name;
- user ID/name derived from the authenticated admin mTLS client;
- timeout;
- required user verification policy.

## Security boundary

- Passkey challenge options do not expose plaintext, ciphertext, envelopes or client-side key material.
- The mTLS admin identity remains the server authorization identity.
- Browser-side WebAuthn ceremonies must bind returned options to the authenticated admin session.
- Full assertion attestation/signature verification should be implemented with a dedicated WebAuthn library or reviewed CBOR/COSE verifier before disabling TOTP fallback.

## Current implementation status

TOTP web MFA is complete in the server. Passkey support is implemented up to challenge/options generation and web-console integration points. This closes the server-side phase-2 boundary without changing the vault cryptographic model; production deployments should keep TOTP enabled until assertion verification is completed and audited.

## Challenge preverification endpoints

Custodia now stores issued passkey challenges with TTL and consumes each challenge at most once. This closes replay gaps around the server-side challenge/options boundary.

Registration challenge preverification:

```text
POST /web/passkey/register/verify
```

Authentication challenge preverification:

```text
POST /web/passkey/authenticate/verify
```

Request body:

```json
{
  "client_data_json": "base64url(clientDataJSON)"
}
```

The server validates the WebAuthn `clientDataJSON` fields that are safe to verify without credential storage: `type`, `challenge` and `origin`. A successful response is `verified_challenge` and consumes the challenge so it cannot be replayed.

This is still not full WebAuthn assertion verification. Credential public-key storage, COSE/CBOR handling and signature verification remain the next production passkey milestone.

## Credential metadata store

Passkey registration preverification now records credential metadata after a valid
challenge has been consumed. The stored metadata is intentionally limited to the
credential id, owning client id and timestamps. It does not store COSE public keys,
authenticator data or attestation statements yet.

Authentication preverification requires the supplied credential id to exist for the
calling client before the challenge can be accepted. This prevents unknown
credential ids from being treated as valid passkey assertions while keeping the
server-side cryptographic boundary honest.

This is still not full WebAuthn assertion verification. The remaining production
work is COSE/CBOR parsing, authenticatorData validation, signature verification
and signature-counter clone detection.


## Authenticator data and sign counter scaffold

Passkey preverification now accepts optional `authenticator_data` as base64url encoded WebAuthn authenticator data. The server parses the RP ID hash, flags and signature counter from the standard authenticator data header.

Registration stores the parsed signature counter with credential metadata when authenticator data is supplied. Authentication rejects a non-increasing signature counter for known credentials, which provides a server-side clone-detection scaffold before full COSE signature verification is added.

Request body with authenticator data:

```json
{
  "client_data_json": "base64url(clientDataJSON)",
  "credential_id": "credential-id",
  "authenticator_data": "base64url(authenticatorData)"
}
```

This is still not full WebAuthn assertion verification. Custodia now parses authenticator data and enforces stored counters when provided, but it still does not parse attestation objects, store COSE public keys or verify authenticator signatures.

## Authenticator data RP ID and user-verification enforcement

Passkey preverification now validates supplied `authenticator_data` when present:

- the authenticator RP ID hash must match `CUSTODIA_WEB_PASSKEY_RP_ID`;
- the user-present flag must be set;
- the user-verified flag must be set because generated passkey options require user verification;
- the signature counter must increase for known credentials.

This is still not full WebAuthn assertion verification. The server does not yet verify the authenticator signature over `authenticatorData || SHA256(clientDataJSON)` because credential public-key COSE/CBOR parsing is still intentionally out of scope for this scaffold.

## Credential public key metadata

Registration preverification now requires `public_key_cose`, a base64url-encoded opaque COSE public key blob. Custodia stores this metadata with the credential id and client id, then requires the stored public-key metadata before authentication preverification can succeed.

This is still not signature verification. The server stores the COSE bytes as opaque metadata and does not yet parse CBOR/COSE or verify authenticator signatures against the stored key.
