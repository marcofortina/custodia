# Custodia Lite local CA bootstrap

Lite defaults to a local file-backed CA. This keeps the single-node profile free
from HSM/PKCS#11 dependencies while preserving mTLS.

## Current state

Custodia already supports file-backed signing material through the signer key
provider. A dedicated `vault-admin setup lite` helper is a future convenience
block; until then, operators provide the CA, server certificate, client CA and
CRL files explicitly in `config.lite.yaml`.

For development only, `scripts/dev-certs.sh` creates throwaway certificates:

```bash
./scripts/dev-certs.sh ./.dev-certs
```

Do not use these generated development certificates for production Lite.

## Recommended production Lite flow

1. Generate or import a local/offline CA outside the running service.
2. Store the CA key with restrictive permissions.
3. Prefer an encrypted CA key or keep the CA key offline.
4. Issue the server TLS certificate and initial admin client certificate.
5. Create an empty local CRL file and configure `client_crl_file`.
6. Rotate the bootstrap admin certificate after initial setup.

## Passphrase handling

Phase 4 should add file-provider passphrase support with:

```text
CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE=/etc/custodia/ca.pass
```

A passphrase file is safer than placing a passphrase directly in an environment
variable because it avoids process-list and shell-history leaks.

## FULL transition

When moving to FULL production, switch from:

```text
CUSTODIA_SIGNER_KEY_PROVIDER=file
```

to:

```text
CUSTODIA_SIGNER_KEY_PROVIDER=pkcs11
```

and provide HSM/PKCS#11/TPM evidence through the production evidence gate.
