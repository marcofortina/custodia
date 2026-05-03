# Custodia web MFA

Custodia's web console remains metadata-only. When web MFA is enabled, every protected `/web/*` page still requires admin mTLS and additionally requires a short-lived TOTP-backed web session.

## Configuration

```bash
CUSTODIA_WEB_MFA_REQUIRED=true
CUSTODIA_WEB_TOTP_SECRET=<base32 secret>
CUSTODIA_WEB_SESSION_SECRET=<at least 32 random bytes/chars>
CUSTODIA_WEB_SESSION_TTL_SECONDS=900
```

`CUSTODIA_WEB_SESSION_SECRET` signs the HttpOnly web session cookie. Rotate it to invalidate all web sessions.

## Login flow

1. Admin connects with an active mTLS certificate.
2. Admin opens `/web/login`.
3. Admin submits a current TOTP code.
4. Custodia issues `custodia_web_session` with `HttpOnly`, `SameSite=Strict`, `Path=/web` and `Secure` outside insecure development mode.
5. Protected metadata pages require both admin mTLS and a valid matching session.

## Security boundary

- MFA unlocks metadata-only admin pages.
- Web pages never render plaintext, ciphertext, envelopes or client-side key material.
- mTLS identity remains the primary server-side authorization identity.
- TOTP is a second factor for web console access, not an application encryption key.
