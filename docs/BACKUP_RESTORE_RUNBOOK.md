# Custodia backup and restore runbook

Backups protect only server-side metadata, ciphertext blobs and recipient envelopes. They never contain plaintext or client-side decryption keys unless an operator has violated the security model elsewhere.

## Backup scope

- PostgreSQL/CockroachDB data directory or logical backups.
- Migration files and deployed image digest.
- mTLS CA public material and CRL snapshots.
- Audit JSONL exports with SHA-256 headers.


## Release-candidate Lite smoke

For Lite releases, run the disposable backup/restore smoke before promoting a
release candidate:

```bash
make lite-backup-restore-smoke
./scripts/lite-backup-restore-smoke.sh smoke
```

This validates the committed SQLite schema, backup helper and restore integrity
procedure without touching live services. It complements, but does not replace,
off-host backup retention and live restore drills.

## Restore checks

1. Restore into an isolated environment first.
2. Run migrations against the restored database.
3. Start Custodia with production-equivalent mTLS config.
4. Run `custodia-admin audit verify`.
5. Compare archived JSONL export SHA-256 values with `custodia-admin audit verify-export`.
6. Confirm the restored archive bundle manifest was produced by `custodia-admin audit archive-export`.
7. Perform a metadata-only read with a known active client.
8. Never test restore by uploading plaintext to the server.

## Retention notes

Backup retention must match the business audit-retention policy. Deleting a server-side grant only blocks future reads; clients may already have downloaded ciphertext and envelopes.

## Audit shipment restore check

When restoring archived audit evidence, verify `manifest.json` and `shipment.json` together. The archive manifest proves the export body matched its sidecars before archive creation; the shipment manifest proves the bundle copied to the sink without per-file digest drift.
