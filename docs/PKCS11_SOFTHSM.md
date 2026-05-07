# PKCS#11 and SoftHSM signer bridge

Custodia supports a concrete PKCS#11 signing boundary without adding HSM private-key material to the vault API process.

## Runtime model

`custodia-signer` can run with:

```bash
CUSTODIA_SIGNER_KEY_PROVIDER=pkcs11
CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND=/usr/local/bin/custodia-pkcs11-sign
```

The signer process passes the certificate digest to the configured command as JSON on stdin:

```json
{"digest":"...base64...","hash":"SHA-256"}
```

The command must return:

```json
{"signature":"...base64..."}
```

This allows production deployments to wrap `pkcs11-tool`, a vendor HSM CLI, or an audited internal PKCS#11 signer without linking HSM libraries into the vault API server.

## Development with SoftHSM

SoftHSM is a development and CI harness, not production security. Initialize a local token with:

```bash
make softhsm-dev-token
```

The helper prints the required environment variables, including `SOFTHSM2_CONF`, `CUSTODIA_SIGNER_KEY_PROVIDER`, `CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND` and the token label/key label settings.

## Production requirements

- Replace SoftHSM with a real HSM, TPM-backed signer or vendor PKCS#11 module.
- Store token PINs in a secret manager, not in the repository.
- Keep the signer mTLS-only.
- Capture signer audit logs and forward them to WORM/SIEM archival.
- Include PKCS#11/HSM attestation in the external evidence gate.

## Boundary

The PKCS#11 bridge signs certificate digests for client mTLS certificates only. It does not handle plaintext secrets, ciphertext payloads, envelope decryption, client-side encryption keys or key discovery.
