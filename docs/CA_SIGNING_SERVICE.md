# Custodia CA signing service

The vault API process must not hold the client CA private key. Certificate lifecycle belongs to the dedicated `custodia-signer` process, backed by TPM/HSM/PKCS#11 or an isolated offline CA workflow.

## Implemented boundary

`custodia-signer` exposes a minimal admin-only API:

- `GET /health`
- `GET /live`
- `POST /v1/certificates/sign`

The signing request body is:

```json
{
  "client_id": "client_alice",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "ttl_hours": 24
}
```

The response contains only the signed mTLS client certificate and validity window. The signer never receives, stores, publishes or validates client-side encryption keys.

## Production authentication

Production mode requires mTLS:

- `CUSTODIA_SIGNER_TLS_CERT_FILE`
- `CUSTODIA_SIGNER_TLS_KEY_FILE`
- `CUSTODIA_SIGNER_CLIENT_CA_FILE`
- `CUSTODIA_SIGNER_ADMIN_SUBJECTS`

Only admin certificate subjects listed in `CUSTODIA_SIGNER_ADMIN_SUBJECTS` may submit CSR signing requests.

## CA material and key providers

Current implementation supports explicit signer key providers:

- `CUSTODIA_SIGNER_KEY_PROVIDER=file` uses `CUSTODIA_SIGNER_CA_CERT_FILE` and `CUSTODIA_SIGNER_CA_KEY_FILE`.
- `CUSTODIA_SIGNER_KEY_PROVIDER=pkcs11` delegates certificate digest signing to `CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND`.

The `file` provider is acceptable for development, isolated bootstrap and tests. Production deployments should use the PKCS#11 command bridge with an HSM/TPM/vendor module before exposing signing in a live environment. The signer process must fail closed rather than silently falling back to file-backed CA material when an unsupported provider is requested. SoftHSM is supported only as a development/test harness.

## CSR policy

The signer validates that:

- `client_id` follows Custodia client-id rules;
- the CSR signature is valid;
- the CSR contains the same `client_id` in Common Name, DNS SAN or URI SAN;
- the requested TTL is positive and does not exceed the signer maximum.

The issued certificate is client-auth only and carries the requested `client_id` as CN and DNS SAN so the vault API can map it to the `clients.mtls_subject` metadata.

## Non-goals

- No client-side encryption key registry.
- No publication of recipient encryption public keys.
- No decrypt/unwrap operation for secret payloads.
- No CA private key in the Custodia API process.
- No plaintext secret handling.

## Remaining production gap

CA key unseal workflow, production HSM attestation, CRL publication automation and OCSP responder integration are still separate deployment/evidence steps. The repository includes a PKCS#11 command bridge and SoftHSM development harness, but it cannot prove the existence of a physical HSM without external evidence.

## Audit trail

`custodia-signer` can append JSONL audit events when `CUSTODIA_SIGNER_AUDIT_LOG_FILE` is set. Certificate signing attempts record:

- action `certificate.sign`;
- outcome `success` or `failure`;
- admin actor subject;
- target `client_id`;
- request correlation id;
- failure reason metadata when available.

The signer audit file is intentionally separate from the vault API audit chain. Production deployments should forward signer JSONL to the same SIEM/WORM retention path used for vault audit exports.

## CRL distribution

When `CUSTODIA_SIGNER_CRL_FILE` is configured, the signer serves the PEM CRL at `/v1/crl.pem`. This lets internal clients and operators retrieve the same revocation artifact used by the vault API. OCSP remains a separate production hardening step.
