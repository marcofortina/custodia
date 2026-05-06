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
- `/web/diagnostics` — runtime counters and uptime metadata only.
- `/web/clients` — client metadata.
- `/web/access-requests` — pending grant metadata.
- `/web/audit` — latest audit metadata.
- `/web/audit/verify` — audit hash-chain verification summary.
- `POST /web/logout` — clears the web MFA session cookie and redirects back to login.

Unknown HTML console routes and handled web-console `4xx`/`5xx` responses render the shared styled error page instead of Go's plain fallback bodies. JSON-only passkey endpoints remain JSON/error surfaces and must not render the HTML console shell.

The API remains the source of truth for automation. The web console is a responsive, metadata-only operator surface even when TOTP/passkey web authentication is enabled. Authenticated pages include a logout button that clears only the web MFA session cookie; mTLS identity remains controlled by the browser certificate.

## Local assets and refresh behavior

The console serves local embedded assets only:

- `/web/assets/console.css`;
- `/web/assets/console.js`;
- `/web/assets/favicon.svg`.

The web CSP allows local scripts/styles only and does not require inline styles. Authenticated console pages include an AJAX refresh control with a default 10-second interval and selectable 5/10/15/30-second intervals. Refreshes swap only `#console-main`, preserve the current URL/query string, pause when the tab is hidden and avoid refreshing while a filter input is focused.

Client-side pagination is enabled for bounded data tables on Clients, Access Requests and Audit Events with 10 rows per page.

## Query filters

The metadata console supports bounded query filters for operational views:

- `/web/audit?limit=100&outcome=failure&action=secret.read&actor_client_id=client_alice&resource_type=secret&resource_id=<id>`
- `/web/audit/verify?limit=500`
- `/web/clients?active=true`
- `/web/access-requests?limit=100&secret_id=<id>&status=pending&client_id=client_bob&requested_by_client_id=admin`

Invalid filters return `400` and are audited as failures. These filters only affect metadata records already visible to an admin mTLS identity; the web console still never renders ciphertext, envelopes, plaintext or key material.


## Runtime diagnostics

`/web/diagnostics` mirrors the admin diagnostics endpoint as metadata-only HTML. It is protected by admin mTLS and intentionally renders only runtime counters and uptime metadata.

## Verification

Useful focused checks:

```bash
go test ./internal/httpapi
make check
```
