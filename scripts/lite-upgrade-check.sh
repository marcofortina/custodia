#!/usr/bin/env bash
set -euo pipefail

lite_env="${CUSTODIA_LITE_ENV_FILE:-}"
full_env="${CUSTODIA_FULL_ENV_FILE:-}"

if [ -z "${lite_env}" ]; then
  echo "CUSTODIA_LITE_ENV_FILE is required" >&2
  exit 2
fi
if [ -z "${full_env}" ]; then
  echo "CUSTODIA_FULL_ENV_FILE is required" >&2
  exit 2
fi

vault_admin_bin="${CUSTODIA_VAULT_ADMIN_BIN:-vault-admin}"
exec "${vault_admin_bin}" lite upgrade-check --lite-env-file "${lite_env}" --full-env-file "${full_env}"
