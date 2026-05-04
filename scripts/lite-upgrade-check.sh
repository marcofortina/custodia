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

if [ -n "${CUSTODIA_ADMIN_BIN:-}" ]; then
  exec "${CUSTODIA_ADMIN_BIN}" lite upgrade-check --lite-env-file "${lite_env}" --full-env-file "${full_env}"
fi

if command -v custodia-admin >/dev/null 2>&1; then
  exec custodia-admin lite upgrade-check --lite-env-file "${lite_env}" --full-env-file "${full_env}"
fi

if [ -f "go.mod" ] && [ -d "cmd/custodia-admin" ]; then
  exec go run ./cmd/custodia-admin lite upgrade-check --lite-env-file "${lite_env}" --full-env-file "${full_env}"
fi

echo "custodia-admin was not found; set CUSTODIA_ADMIN_BIN or run from the repository root" >&2
exit 127
