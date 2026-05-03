# Audit Export Integrity

Custodia exports audit events as newline-delimited JSON from `GET /v1/audit-events/export`.

The export endpoint is metadata-only: it emits audit event records and never includes plaintext secrets, ciphertext payloads, recipient envelopes or client-side key material.

## Integrity headers

Every export response includes:

- `Content-Type: application/x-ndjson; charset=utf-8`
- `Content-Disposition: attachment; filename="custodia-audit.jsonl"`
- `X-Custodia-Audit-Export-SHA256`: SHA-256 digest of the exact JSONL response body.
- `X-Custodia-Audit-Export-Events`: number of events included in the response body.

Operators should persist both the JSONL file and the SHA-256 header value when forwarding exports to offline storage, SIEM ingestion or WORM/ledger systems.

## Verification

The header digest can be checked locally:

```bash
sha256sum custodia-audit.jsonl
```

The printed digest must match `X-Custodia-Audit-Export-SHA256`.

The audit hash-chain can still be verified separately with:

```bash
vault-admin audit verify --limit 500
```

The export digest protects the exported transport artifact; audit-chain verification protects the event sequence semantics.

## SDK and CLI artifact helpers

Go callers can use `ExportAuditEventsWithMetadata(...)` to receive the JSONL body together with the SHA-256 and event-count response headers.

Python callers can use `export_audit_events_with_metadata(...)` for the same artifact bundle.

`vault-admin audit export` can write the body and headers to separate files:

```bash
vault-admin audit export \
  --out-file custodia-audit.jsonl \
  --sha256-out custodia-audit.sha256 \
  --events-out custodia-audit.events
```

Persist the three files together before forwarding to SIEM or WORM storage.


## Verifying exported artifacts with vault-admin

When an export is written with sidecar files, verify the body, digest and event count together:

```bash
vault-admin audit verify-export \
  --file custodia-audit.jsonl \
  --sha256-file custodia-audit.jsonl.sha256 \
  --events-file custodia-audit.jsonl.events
```

The command recomputes SHA-256 over the exact JSONL body and compares the non-empty JSONL line count with the recorded event-count header. It returns a JSON verification result and exits non-zero on digest or count mismatch.
