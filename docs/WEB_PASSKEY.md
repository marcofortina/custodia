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
