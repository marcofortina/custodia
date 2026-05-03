#!/usr/bin/env bash
set -euo pipefail

alias_name="${MINIO_ALIAS:-custodia-minio}"
endpoint="${CUSTODIA_AUDIT_S3_ENDPOINT:-http://127.0.0.1:9000}"
access_key="${CUSTODIA_AUDIT_S3_ACCESS_KEY_ID:-minioadmin}"
secret_key="${CUSTODIA_AUDIT_S3_SECRET_ACCESS_KEY:-minioadmin}"
bucket="${CUSTODIA_AUDIT_S3_BUCKET:-custodia-audit}"

if ! command -v mc >/dev/null 2>&1; then
  echo "mc is required for MinIO Object Lock smoke checks" >&2
  exit 2
fi

mc alias set "${alias_name}" "${endpoint}" "${access_key}" "${secret_key}" >/dev/null
mc stat "${alias_name}/${bucket}" >/dev/null
mc retention info "${alias_name}/${bucket}" >/dev/null
