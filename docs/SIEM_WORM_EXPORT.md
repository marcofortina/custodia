# Custodia SIEM and WORM audit export

Custodia writes an internal hash-chained audit log and can export JSONL with integrity headers. Production archival should push those exports to SIEM and WORM storage.

## Export contract

- Endpoint: `GET /v1/audit-events/export`.
- Format: JSON Lines.
- Integrity headers:
  - `X-Custodia-Audit-Export-SHA256`.
  - `X-Custodia-Audit-Export-Events`.

## Recommended archival job

1. Call the export endpoint with an admin mTLS client.
2. Persist the body as immutable JSONL.
3. Persist response headers next to the body.
4. Recompute SHA-256 before upload to WORM storage.
5. Run `vault-admin audit archive-export` to verify the JSONL, `.sha256` and `.events` artifacts and create an archive bundle.
6. Run `vault-admin audit ship-archive` to copy the verified bundle into the configured sink directory and write `shipment.json`.
7. Upload or mirror the sink directory to WORM object storage or forward it to SIEM.
8. Alert on audit chain verification failure, hash mismatch, event-count mismatch or missing shipment manifest.

## Security boundary

Audit exports may contain metadata, actor IDs, resource IDs and operation outcomes. They must not contain plaintext, envelopes or client-side key material.


## S3 Object Lock shipment

For S3-compatible WORM sinks, use `vault-admin audit ship-archive-s3` after `vault-admin audit archive-export`. The command verifies the archive body, digest and event count before uploading objects with SigV4 and Object Lock retention headers. MinIO Object Lock is suitable for development and smoke testing; production compliance still depends on the external storage provider enforcing retention.
