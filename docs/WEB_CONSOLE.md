# Custodia Web Console

The Custodia web console is an admin-only, metadata-only surface.

## Security boundary

- Access requires an authenticated admin mTLS identity.
- The console never renders plaintext.
- The console never renders ciphertext.
- The console never renders recipient envelopes.
- The console never exposes client-side encryption keys or key discovery endpoints.

## Browser mutation guardrails

The Web Console uses admin mTLS plus the configured web MFA/session layer for authenticated pages. Mutating browser requests under `/web/` also enforce same-origin `Origin`/`Referer` guardrails when those headers are present. Cross-origin form posts and JavaScript mutations are rejected before the handler runs. CLI/API callers are unaffected because the guard applies only to Web Console paths and mutating HTTP methods.

The pre-session `POST /web/login` handoff is intentionally exempt from this origin guard. It still requires an authenticated admin mTLS identity and a valid Web MFA assertion, but it must not fail closed on browser-origin quirks before the session cookie exists. Authenticated Web Console mutations after login remain covered by the same-origin guard.

This guard complements, rather than replaces, the existing `SameSite=Strict`, `HttpOnly` web session cookie, Content Security Policy and metadata-only page boundary.

## Pages

- `/web/` — metadata console landing page.
- `/web/status` — operational status.
- `/web/diagnostics` — runtime counters and uptime metadata only.
- `/web/clients` — client metadata, active/revoked state and public-key publication status.
- `/web/clients/{client_id}` — client detail drilldown with metadata-only lifecycle, public-key, revocation, visible keyspace, ownership and share summaries.
- `/web/client-enrollments` — create one-shot client enrollment tokens without shell access to a server or Kubernetes pod.
- `/web/revocation` — client CRL health, PEM download and certificate serial checks.
- `/web/revocation/client.crl.pem` — browser-downloadable client CRL PEM after CA signature verification.
- `/web/revocation/check-serial` — form-backed serial status check against the configured client CRL.
- `POST /web/clients/{client_id}/revoke` — future client revocation from the client detail page.
- `/web/secret-metadata` — namespace/key lookup for secret versions and active access grants.
- `POST /web/secret-metadata/revoke` — future access-grant revocation from the Secret Metadata page.
- `/web/access-requests` — pending grant metadata.
- `/web/audit` — latest audit metadata with a JSONL download action.
- `/web/audit/export` — browser-downloadable JSONL audit export with SHA-256 and event-count headers.
- `/web/audit/verify` — audit hash-chain verification summary.
- `POST /web/logout` — clears the web MFA session cookie and redirects back to login.

Unknown HTML console routes and handled web-console `4xx`/`5xx` responses render the shared styled error page instead of Go's plain fallback bodies. JSON-only passkey endpoints remain JSON/error surfaces and must not render the HTML console shell.

The API remains the source of truth for automation. The web console is a responsive, metadata-only operator surface even when TOTP/passkey web authentication is enabled. Authenticated pages include a logout button that clears only the web MFA session cookie; mTLS identity remains controlled by the browser certificate.

Client enrollment token creation mirrors `custodia-admin client enrollment create`: it returns the configured server URL, a one-shot enrollment token and the expiry time. The token is shown once, the server URL and token have browser copy controls, and the values must be transferred through a trusted channel. The workflow does not expose client private keys because clients still generate their mTLS key and CSR locally. Token creation is audited as a Web Console action. In disposable lab flows using an untrusted bootstrap CA, the client may add `--insecure`; real remote clients should trust the Custodia CA and avoid `--insecure`.

Client detail pages are scoped by client because `namespace/key` is not globally unique. The admin drilldown shows lifecycle metadata, active/revoked state, public-key publication status and fingerprint metadata, CRL status/serial-check links, the keyspace visible to that client, whether each entry is owned by the client or shared with the client, and share metadata for secrets owned by that client. Active client detail pages include a future-revocation form so Kubernetes operators do not need shell access to run `custodia-admin client revoke`. Client revocation requires explicit confirmation, is audited, and does not claw back already downloaded material; strong revocation still requires a new encrypted version excluding the revoked client. The page still never renders plaintext, ciphertext, recipient envelopes, DEKs, private keys or client-side private key material. The current client registry does not persist issued certificate serial numbers; operators can use the linked Revocation Status serial check with certificate/CRL evidence when serial verification is required.

Secret Metadata provides the Web Console equivalent of `custodia-admin secret versions`, `custodia-admin access list` and `custodia-admin access revoke` for online Kubernetes operations. Operators search by `namespace/key`, optionally pin the owner client id when required, inspect version/access metadata and revoke a target client's future access from the browser. The page intentionally uses owner client id in the revoke form so an operator cannot revoke an ambiguous keyspace record by accident. It still never renders plaintext, ciphertext, recipient envelopes, DEKs or client-side key material.

Revocation Status includes a `Download client CRL PEM` action and a serial-check form. The server verifies the configured client CRL against the configured client CA before serving the PEM or checking a serial. This gives Kubernetes operators the Web Console equivalent of `custodia-admin revocation fetch-crl` and `custodia-admin revocation check-serial` without entering a pod.

Audit Events includes a `Download JSONL` action that uses the same bounded filters as the page and returns `X-Custodia-Audit-Export-SHA256` plus `X-Custodia-Audit-Export-Events` headers. This is the Web Console equivalent of capturing audit export evidence without entering a Kubernetes pod. The export body remains metadata-only and never includes plaintext, ciphertext, recipient envelopes, DEKs or private keys.

## Local assets and refresh behavior

The console serves local embedded assets only:

- `/web/assets/console.css`;
- `/web/assets/console.js`;
- `/web/assets/favicon.svg`.

The web CSP allows local scripts/styles only and does not require inline styles. Authenticated console pages include an AJAX refresh control with a default 10-second interval and selectable 5/10/15/30-second intervals. Refreshes swap only `#console-main`, preserve the current URL/query string, pause when the tab is hidden and avoid refreshing while a filter input is focused.

Client-side pagination is enabled for bounded data tables on Clients, Client Detail, Secret Metadata, Access Requests and Audit Events with 10 rows per page.

## Query filters

The metadata console supports bounded query filters for operational views. Client detail drilldown is intentionally path-based and always scoped to one client id, because namespace/key pairs are not globally unique. Access-request workflows use public `namespace/key` filters and intentionally do not expose internal secret-id filters:

- `/web/audit?limit=100&outcome=failure&action=secret.read&actor_client_id=client_alice&resource_type=secret&resource_id=<id>`
- `/web/audit/export?limit=500&outcome=failure&action=secret.read`
- `/web/audit/verify?limit=500`
- `/web/clients?active=true`
- `/web/clients/client_alice`
- `/web/client-enrollments` plus `POST /web/client-enrollments` with form field `ttl=15m`
- `/web/revocation`
- `/web/revocation/client.crl.pem`
- `/web/revocation/check-serial?serial_hex=64`
- `/web/clients?active=true` and `POST /web/clients/{client_id}/revoke` with form fields `reason=...&confirm=yes`
- `/web/secret-metadata?namespace=db01&key=user:sys&owner_client_id=client_alice` and `POST /web/secret-metadata/revoke` with form fields `namespace=...&key=...&owner_client_id=...&target_client_id=...&confirm=yes`
- `/web/access-requests?limit=100&namespace=db01&key=user:sys&status=pending&client_id=client_bob&requested_by_client_id=admin`

Invalid filters return `400` and are audited as failures. These filters only affect metadata records already visible to an admin mTLS identity; the web console still never renders ciphertext, envelopes, plaintext or key material. Client detail pages show `namespace/key`, relationship, owner, permissions and active share metadata only.

## Runtime diagnostics

`/web/diagnostics` mirrors the admin diagnostics endpoint as metadata-only HTML. It is protected by admin mTLS and intentionally renders only runtime counters and uptime metadata.

## Verification

Useful focused checks:

```bash
go test ./internal/httpapi
make check
```
