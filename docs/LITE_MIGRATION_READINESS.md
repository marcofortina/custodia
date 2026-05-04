# Custodia Lite migration readiness

This document describes what Custodia can verify before a Lite to Full migration.
It does not move secret data by itself.

## What the readiness check validates

The readiness check compares two environment files:

- source Lite environment;
- target Full environment.

It verifies that the source is SQLite/Lite-oriented and that the target is ready
for Full infrastructure: PostgreSQL/CockroachDB, Valkey, PKCS#11/HSM planning,
audit shipment and HA database target naming.

## What it does not do

The check does not:

- copy SQLite data into PostgreSQL;
- transform secrets;
- decrypt, unwrap or interpret ciphertext/envelope material;
- validate HSM or WORM evidence;
- replace `production-check` or `production-evidence-check`.

## Required operator evidence

Before executing the final migration window, capture:

- SQLite backup artifact and checksum;
- target PostgreSQL/CockroachDB backup/PITR configuration;
- audit export/verify artifact;
- target production readiness output;
- target external evidence output;
- rollback procedure.

## Migration principle

Custodia must preserve the opaque crypto boundary during migration. The migration
path may move serialized server state, metadata and opaque blobs; it must not
attempt to decrypt, unwrap, reinterpret or normalize client-owned cryptographic
material.
