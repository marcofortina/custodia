# Custodia CRL and OCSP operations

Custodia currently supports local client CRL enforcement. This runbook defines the production revocation distribution path expected by the Fort Knox analysis.

## Local CRL mode

- Mount the trusted PEM CRL at `CUSTODIA_CLIENT_CRL_FILE`.
- The server reloads the CRL when the file changes.
- Invalid or untrusted replacement CRLs fail closed.

## Production distribution

1. CA signing service writes a new CRL after certificate revocation.
2. CRL is distributed through a signed object store, config management or secret sync.
3. Pods receive the updated file atomically.
4. Operators verify revocation with a blocked client certificate.
5. Audit events are exported after revocation propagation.

## OCSP gap

OCSP stapling is not implemented in the API process yet. Until then, CRL enforcement is the implemented revocation control and must be monitored as a production dependency.

## Revocation status API

Custodia exposes an admin-only revocation monitor endpoint:

```bash
vault-admin revocation status
```

The endpoint is backed by `GET /v1/revocation/status` and reports whether a client CRL is configured, valid, trusted by the configured client CA, how many entries it contains and when the CRL expires.

This does not replace OCSP. It is a production guardrail for the currently implemented fail-closed CRL path.

## Signer CRL distribution endpoint

`custodia-signer` can publish the configured PEM CRL from:

```text
GET /v1/crl.pem
```

Configure it with:

```bash
CUSTODIA_SIGNER_CRL_FILE=/path/to/client.crl
```

The endpoint returns `application/pkix-crl` and includes `X-Custodia-CRL-Revoked-Count`. It is a CRL distribution helper, not a full OCSP responder.

## Revocation serial status responder

`custodia-signer` also exposes a JSON revocation responder for lab and operator checks:

```bash
vault-admin \
  --server-url https://signer.internal:9444 \
  --cert admin.crt \
  --key admin.key \
  --ca signer-ca.crt \
  revocation check-serial --serial-hex 01af
```

The endpoint is `GET /v1/revocation/serial?serial_hex=<hex>` and evaluates the currently configured signer CRL file. It returns `good` or `revoked` with CRL metadata and revoked-count context.

This is not a full RFC 6960 OCSP responder. It is a deterministic JSON responder over the CRL-backed revocation state, useful for smoke tests, operational dashboards and revocation drills while keeping the OCSP protocol itself out of the vault API process.
