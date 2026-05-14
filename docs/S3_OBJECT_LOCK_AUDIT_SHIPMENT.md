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

## Kubernetes MinIO lab profile

For Kubernetes smoke rehearsal, use the lab-only manifests under `deploy/k3s/minio/`. They create a PVC-backed MinIO pod, internal ClusterIP Service and init Job that creates the `custodia-audit` bucket with Object Lock retention enabled.

```bash
kubectl apply -f deploy/k3s/minio/custodia-minio-secret.example.yaml
kubectl apply -f deploy/k3s/minio/custodia-minio-pvc.yaml
kubectl apply -f deploy/k3s/minio/custodia-minio-deployment.yaml
kubectl apply -f deploy/k3s/minio/custodia-minio-service.yaml
kubectl -n custodia rollout status deploy/custodia-lab-minio --timeout=180s
kubectl apply -f deploy/k3s/minio/custodia-minio-init-job.yaml
kubectl -n custodia wait --for=condition=complete job/custodia-lab-minio-init --timeout=180s
```

Use a temporary port-forward for the workstation smoke helper:

```bash
kubectl -n custodia port-forward svc/custodia-lab-minio 9000:9000
```

Then run:

```bash
CUSTODIA_AUDIT_S3_ENDPOINT=http://127.0.0.1:9000 \
CUSTODIA_AUDIT_S3_ACCESS_KEY_ID=custodia-minio-lab \
CUSTODIA_AUDIT_S3_SECRET_ACCESS_KEY=custodia-minio-lab-CHANGE-ME \
CUSTODIA_AUDIT_S3_BUCKET=custodia-audit \
make minio-object-lock-smoke
```

## Security boundary

The repository can verify bundle integrity and send Object Lock headers. It cannot prove legal immutability unless the external sink actually enforces retention. Production evidence must come from the storage provider or MinIO/S3 Object Lock configuration artifacts.
