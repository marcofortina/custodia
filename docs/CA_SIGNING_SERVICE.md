# Custodia CA signing service design

The vault server must not directly hold the CA private key. Certificate lifecycle belongs to a dedicated signing service backed by TPM/HSM or an offline CA workflow.

## Responsibilities

- Accept authenticated administrative CSR signing requests.
- Validate requested `client_id` and mTLS subject policy.
- Sign client certificates using TPM/HSM/PKCS#11 or offline CA material.
- Publish CRL updates through the revocation distribution channel.
- Append signing/revocation events to an immutable audit destination.

## Non-goals

- No client-side encryption key registry.
- No publication of recipient encryption public keys.
- No decrypt/unwrap operation for secret payloads.
- No CA private key in the Custodia API process.

## Suggested API boundary

- `POST /ca/v1/csr/sign` for CSR signing.
- `POST /ca/v1/certificates/revoke` for revocation.
- `GET /ca/v1/crl.pem` for CRL distribution.

The current Custodia API can consume the resulting client certificates and CRL file without changing the secret storage model.
