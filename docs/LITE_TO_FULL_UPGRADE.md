# Custodia Lite to Full upgrade path

Lite and Full use the same codebase and configuration vocabulary. Upgrades are
configuration changes plus explicit data/infrastructure migration steps.

## Typical path

1. `profile: lite` -> `profile: custom`.
2. SQLite -> PostgreSQL or CockroachDB.
3. Memory rate limiting -> Valkey.
4. File-backed CA -> PKCS#11/HSM signer.
5. Local audit export -> S3 Object Lock/WORM shipment.
6. TOTP-only -> passkey/WebAuthn with external assertion verifier if required.
7. Manual checks -> production readiness and evidence gates.

## Database migration

SQLite to PostgreSQL/CockroachDB requires a dedicated migration tool. Do not use
`sqlite3 .dump` as a production migration procedure. Until that tool exists,
treat migration as a planned maintenance operation with export, validation and
rollback evidence.

## Configuration transition

Start from `deploy/examples/config.full.yaml`, then explicitly copy over only the
values that remain valid in the target environment.

## Gates

Before declaring the upgraded deployment production-ready, run:

```bash
make release-check
CUSTODIA_PRODUCTION_ENV_FILE=.env.production make production-check
CUSTODIA_PRODUCTION_ENV_FILE=.env.production make production-evidence-check
```
