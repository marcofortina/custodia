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
5. Forward the same JSONL to SIEM.
6. Alert on audit chain verification failure or hash mismatch.

## Security boundary

Audit exports may contain metadata, actor IDs, resource IDs and operation outcomes. They must not contain plaintext, envelopes or client-side key material.
