# Custodia Lite local CA bootstrap

Lite defaults to a local file-backed CA. This keeps the single-node profile free
from HSM/PKCS#11 dependencies while preserving mTLS.

## Current state

Custodia supports file-backed signing material through the signer key provider and provides a Lite local bootstrap command:

```bash
custodia-admin ca bootstrap-local --out-dir /etc/custodia --admin-client-id admin --server-name localhost --generate-ca-passphrase
```

The command writes a local self-signed CA, server certificate, initial admin client certificate, empty CRL and `config.lite.yaml`. It refuses to overwrite existing files.

For development only, `scripts/dev-certs.sh` also creates throwaway certificates:

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

The file-backed CA provider supports passphrase-protected CA keys through:

```text
CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE=/etc/custodia/ca.pass
```

A passphrase file is safer than placing a passphrase directly in an environment variable because it avoids process-list and shell-history leaks. The bootstrap command can generate `/etc/custodia/ca.pass` with `--generate-ca-passphrase`, or can read an existing file with `--ca-passphrase-file FILE`.

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
