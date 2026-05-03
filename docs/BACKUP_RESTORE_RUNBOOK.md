# Custodia backup and restore runbook

Backups protect only server-side metadata, ciphertext blobs and recipient envelopes. They never contain plaintext or client-side decryption keys unless an operator has violated the security model elsewhere.

## Backup scope

- PostgreSQL/CockroachDB data directory or logical backups.
- Migration files and deployed image digest.
- mTLS CA public material and CRL snapshots.
- Audit JSONL exports with SHA-256 headers.

## Restore checks

1. Restore into an isolated environment first.
2. Run migrations against the restored database.
3. Start Custodia with production-equivalent mTLS config.
4. Run `vault-admin audit verify`.
5. Compare archived JSONL export SHA-256 values with `vault-admin audit verify-export`.
6. Confirm the restored archive bundle manifest was produced by `vault-admin audit archive-export`.
7. Perform a metadata-only read with a known active client.
8. Never test restore by uploading plaintext to the server.

## Retention notes

Backup retention must match the business audit-retention policy. Deleting a server-side grant only blocks future reads; clients may already have downloaded ciphertext and envelopes.
