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


## Readiness check

Before planning the data move, compare the source Lite environment and target Full environment:

```bash
custodia-admin lite upgrade-check \
  --lite-env-file deploy/examples/lite.env.example \
  --full-env-file deploy/examples/full-upgrade-target.env.example
```

or through Make:

```bash
CUSTODIA_LITE_ENV_FILE=deploy/examples/lite.env.example \
CUSTODIA_FULL_ENV_FILE=deploy/examples/full-upgrade-target.env.example \
make lite-upgrade-check
```

The check validates that the source is actually Lite/SQLite and that the target is PostgreSQL/Full-oriented with Valkey, PKCS#11 and audit shipment planned. Warnings are allowed for staged upgrades; critical findings must be resolved before migration.

When the helper script is used instead of calling the binary directly, set `CUSTODIA_ADMIN_BIN` to point at a non-standard admin binary path.

## Database migration

SQLite to PostgreSQL/CockroachDB requires a dedicated data-migration tool. Do not use
`sqlite3 .dump` as a production migration procedure. Until that tool exists,
treat migration as a planned maintenance operation with export, validation,
read-only verification and rollback evidence.

## Configuration transition

Start from `deploy/examples/custodia-server.full.yaml`, then explicitly copy over only the
values that remain valid in the target environment.

## Gates

Before declaring the upgraded deployment production-ready, run:

```bash
make release-check
CUSTODIA_PRODUCTION_ENV_FILE=.env.production make production-check
CUSTODIA_PRODUCTION_ENV_FILE=.env.production make production-evidence-check
```
