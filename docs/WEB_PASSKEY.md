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

TOTP web MFA is complete in the server. Passkey support includes challenge/options generation, consume-once challenge preverification, credential metadata, authenticator-data validation, COSE credential-key metadata parsing and a fail-closed external assertion verifier adapter. This closes the repository-side phase-2 boundary without changing the vault cryptographic model; production deployments must configure an audited assertion verifier command before relying on passkeys as the primary web factor.

## Challenge preverification endpoints

Custodia stores issued passkey challenges with TTL and consumes each challenge at most once. This closes replay gaps around the server-side challenge/options boundary.

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

This is an early section of the passkey implementation history. Later patches add credential metadata, authenticator-data validation, COSE credential-key parsing and an external assertion verifier adapter.

## Credential metadata store

Passkey registration preverification records credential metadata after a valid
challenge has been consumed. The stored metadata is intentionally limited to the
credential id, owning client id and timestamps. Later patches add COSE credential-key metadata and authenticator-data validation. Attestation statements remain outside the repository verifier boundary.

Authentication preverification requires the supplied credential id to exist for the
calling client before the challenge can be accepted. This prevents unknown
credential ids from being treated as valid passkey assertions while keeping the
server-side cryptographic boundary honest.

This section describes the metadata milestone. Later patches add authenticator-data parsing, RP ID/user verification checks, sign-counter handling, COSE credential-key parsing and external assertion verification delegation.


## Authenticator data and sign counter scaffold

Passkey preverification accepts optional `authenticator_data` as base64url encoded WebAuthn authenticator data. The server parses the RP ID hash, flags and signature counter from the standard authenticator data header.

Registration stores the parsed signature counter with credential metadata when authenticator data is supplied. Authentication rejects a non-increasing signature counter for known credentials, which provides a server-side clone-detection scaffold before full COSE signature verification is added.

Request body with authenticator data:

```json
{
  "client_data_json": "base64url(clientDataJSON)",
  "credential_id": "credential-id",
  "authenticator_data": "base64url(authenticatorData)"
}
```

Custodia parses authenticator data and enforces stored counters when provided. Later patches add RP ID/user-verification checks, COSE credential-key parsing and fail-closed external assertion verification delegation.

## Authenticator data RP ID and user-verification enforcement

Passkey preverification validates supplied `authenticator_data` when present:

- the authenticator RP ID hash must match `CUSTODIA_WEB_PASSKEY_RP_ID`;
- the user-present flag must be set;
- the user-verified flag must be set because generated passkey options require user verification;
- the signature counter must increase for known credentials.

The server validates RP ID and user-verification fields before the final assertion-signature boundary. Later patches add COSE credential-key parsing and an external assertion verifier adapter for the cryptographic signature check.

## Credential credential key metadata

Registration preverification requires `credential_key_cose`, a base64url-encoded opaque COSE credential key blob. Custodia stores this metadata with the credential id and client id, then requires the stored credential-key metadata before authentication preverification can succeed.

This section describes the credential-key metadata milestone. Later patches parse supported COSE_Key metadata shapes and delegate final authenticator signature verification to an external audited command.

## COSE credential-key parser

Registration preverification parses the supplied `credential_key_cose` as a COSE_Key CBOR map before storing it as opaque credential-key metadata.

Supported metadata forms:

- EC2/P-256/ES256 COSE keys (`kty=2`, `alg=-7`, `crv=1`, 32-byte x/y coordinates)
- RSA/RS256 COSE keys (`kty=3`, `alg=-257`, modulus and exponent byte strings)

The parser validates the shape and supported algorithm metadata. Final authenticator signature verification is delegated to the external assertion verifier adapter when configured.

## External assertion verification command

Custodia can delegate the final WebAuthn assertion signature check to an external audited verifier by setting:

```bash
CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND=/usr/local/bin/verify-passkey-assertion
```

When configured, `/web/passkey/authenticate/verify` requires `authenticator_data` and `signature` in addition to the existing `client_data_json`, `credential_id` and `credential_key_cose` metadata. The server sends a JSON payload to the command over stdin and expects:

```json
{"valid":true}
```

Any command error, malformed response or `valid:false` fails closed with `invalid_assertion_signature`.

The repository includes `scripts/passkey-assertion-verify-command.sh` as a fail-closed template. It is not a verifier. Production must replace it with an audited WebAuthn verifier implementation.
