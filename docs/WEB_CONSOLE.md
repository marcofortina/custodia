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

The API remains the source of truth for automation; the web console is intentionally small and metadata-only even when TOTP/passkey web authentication is enabled.

## Query filters

The metadata console supports bounded query filters for operational views:

- `/web/audit?limit=100&outcome=failure&action=secret.read&actor_client_id=client_alice&resource_type=secret&resource_id=<id>`
- `/web/audit/verify?limit=500`
- `/web/clients?active=true`
- `/web/access-requests?limit=100&secret_id=<id>&status=pending&client_id=client_bob&requested_by_client_id=admin`

Invalid filters return `400` and are audited as failures. These filters only affect metadata records already visible to an admin mTLS identity; the web console still never renders ciphertext, envelopes, plaintext or key material.


## Runtime diagnostics

`/web/diagnostics` mirrors the admin diagnostics endpoint as metadata-only HTML. It is protected by admin mTLS and intentionally renders only runtime counters and uptime metadata.
