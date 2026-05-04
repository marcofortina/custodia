#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

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
