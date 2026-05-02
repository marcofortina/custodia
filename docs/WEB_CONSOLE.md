# Custodia Web Console

The Custodia web console is an admin-only, metadata-only surface.

## Security boundary

- Access requires an authenticated admin mTLS identity.
- The console never renders plaintext.
- The console never renders ciphertext.
- The console never renders recipient envelopes.
- The console never exposes client-side encryption keys or key discovery endpoints.

## Pages

- `/web/` — metadata console landing page.
- `/web/status` — operational status.
- `/web/clients` — client metadata.
- `/web/access-requests` — pending grant metadata.
- `/web/audit` — latest audit metadata.
- `/web/audit/verify` — audit hash-chain verification summary.

The API remains the source of truth for automation; the web console is intentionally small until MFA/passkey support is implemented.
