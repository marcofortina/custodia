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
