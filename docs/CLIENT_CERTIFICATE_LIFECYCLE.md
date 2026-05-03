# Client certificate lifecycle

Custodia separates client metadata registration from certificate issuance.

## 1. Register metadata in the vault API

```bash
vault-admin client create \
  --client-id client_alice \
  --mtls-subject client_alice
```

This only creates the `clients` metadata row. It does not create keys and does not sign certificates.

## 2. Generate a private key and CSR locally

```bash
vault-admin client csr \
  --client-id client_alice \
  --private-key-out client_alice.key \
  --csr-out client_alice.csr
```

The private key is generated locally and written with `0600` permissions. The vault API never sees this private key.

## 3. Submit the CSR to the signer

Point `--server-url` at `custodia-signer`, not the vault API:

```bash
vault-admin \
  --server-url https://signer.internal:9444 \
  --cert admin.crt \
  --key admin.key \
  --ca signer-ca.crt \
  certificate sign \
  --client-id client_alice \
  --csr-file client_alice.csr
```

The signer returns a client-auth certificate bound to `client_alice`.

## 4. Use the certificate for vault API mTLS

Configure client applications with:

- signed client certificate;
- locally generated private key;
- vault server CA.

The certificate identity must match the metadata `mtls_subject` registered in the vault API.

## Security boundary

- The vault API process does not hold the CA private key.
- The signer service does not handle plaintext secrets, ciphertext, envelopes or application encryption keys.
- The signer validates CSR identity binding but does not become a key directory.
- Production deployments should back signing with TPM/HSM/PKCS#11 instead of file-backed CA keys.
