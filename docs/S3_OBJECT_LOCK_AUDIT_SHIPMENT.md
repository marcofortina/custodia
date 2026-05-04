# S3 Object Lock audit shipment

Custodia can ship verified audit archive bundles to an S3-compatible bucket with Object Lock retention headers. This is intended for MinIO development/smoke testing and AWS S3 Object Lock or compatible production sinks.

## Command

```bash
custodia-admin audit ship-archive-s3 \
  --archive-dir ./audit-archive/20260102T030405Z \
  --endpoint http://127.0.0.1:9000 \
  --region us-east-1 \
  --bucket custodia-audit \
  --prefix custodia/audit \
  --access-key-id "$CUSTODIA_AUDIT_S3_ACCESS_KEY_ID" \
  --secret-access-key "$CUSTODIA_AUDIT_S3_SECRET_ACCESS_KEY" \
  --object-lock-mode COMPLIANCE \
  --retain-until 2036-01-02T03:04:05Z
```

The command verifies the audit archive bundle before uploading any object. It uploads:

- `custodia-audit.jsonl`
- `custodia-audit.jsonl.sha256`
- `custodia-audit.jsonl.events`
- `manifest.json`

Each PUT request is SigV4-signed and includes:

- `X-Amz-Object-Lock-Mode`
- `X-Amz-Object-Lock-Retain-Until-Date`
- `X-Amz-Content-Sha256`

## MinIO development profile

Start the local Object Lock profile:

```bash
docker compose -f deploy/docker-compose.yml --profile worm up minio minio-init
```

Then run:

```bash
CUSTODIA_AUDIT_S3_ENDPOINT=http://127.0.0.1:9000 \
CUSTODIA_AUDIT_S3_ACCESS_KEY_ID=minioadmin \
CUSTODIA_AUDIT_S3_SECRET_ACCESS_KEY=minioadmin \
make minio-object-lock-smoke
```

## Security boundary

The repository can verify bundle integrity and send Object Lock headers. It cannot prove legal immutability unless the external sink actually enforces retention. Production evidence must come from the storage provider or MinIO/S3 Object Lock configuration artifacts.
