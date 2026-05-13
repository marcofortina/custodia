#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

chart_dir="deploy/helm/custodia"
full_values="$chart_dir/values-full.example.yaml"
lite_values="$chart_dir/values-lite.example.yaml"

if ! command -v helm >/dev/null 2>&1; then
  printf 'helm-render-check: helm not found; skipping chart render checks\n' >&2
  exit 0
fi

for required in "$full_values" "$lite_values"; do
  if [ ! -f "$required" ]; then
    printf 'helm-render-check: missing required example values file: %s\n' "$required" >&2
    exit 1
  fi
done

printf 'helm-render-check: linting chart\n'
helm lint "$chart_dir"

printf 'helm-render-check: rendering full example\n'
helm template custodia-full "$chart_dir" \
  --values "$full_values" \
  >/dev/null

printf 'helm-render-check: rendering lite example\n'
lite_render="$(helm template custodia-lite "$chart_dir" \
  --values "$lite_values")"
printf '%s\n' "$lite_render" >/dev/null

if ! printf '%s\n' "$lite_render" | awk '
  /^[[:space:]]+strategy:[[:space:]]*$/ {
    in_strategy = 1
    saw_recreate = 0
    saw_rolling_update = 0
    next
  }
  in_strategy && /^[^[:space:]]/ {
    if (saw_recreate && saw_rolling_update) { exit 1 }
    in_strategy = 0
  }
  in_strategy && /^[[:space:]]+type:[[:space:]]*Recreate[[:space:]]*$/ { saw_recreate = 1 }
  in_strategy && /^[[:space:]]+rollingUpdate:[[:space:]]*$/ { saw_rolling_update = 1 }
  END {
    if (in_strategy && saw_recreate && saw_rolling_update) { exit 1 }
  }
'; then
  printf 'helm-render-check: lite Recreate strategy rendered rollingUpdate fields\n' >&2
  exit 1
fi

for required_security_field in \
  'runAsNonRoot: true' \
  'runAsUser: 65532' \
  'runAsGroup: 65532' \
  'fsGroup: 65532'; do
  if ! printf '%s\n' "$lite_render" | grep -F "$required_security_field" >/dev/null; then
    printf 'helm-render-check: lite chart is missing numeric non-root security field: %s\n' "$required_security_field" >&2
    exit 1
  fi
done

expect_failure() {
  local description="$1"
  shift
  local output
  set +e
  output="$($@ 2>&1)"
  local status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    printf 'helm-render-check: expected failure but command passed: %s\n' "$description" >&2
    exit 1
  fi
  printf 'helm-render-check: expected failure observed: %s\n' "$description"
  printf '%s\n' "$output" | sed 's/^/  /'
}

expect_failure 'lite without PVC' \
  helm template custodia-lite-unsafe "$chart_dir" \
    --values "$lite_values" \
    --set persistence.enabled=false

expect_failure 'full with sqlite store' \
  helm template custodia-full-unsafe "$chart_dir" \
    --values "$full_values" \
    --set config.storeBackend=sqlite

expect_failure 'full pkcs11 without command delivery' \
  helm template custodia-full-pkcs11-unsafe "$chart_dir" \
    --values "$full_values" \
    --set signer.pkcs11SignCommandDelivery=

expect_failure 'web enabled without MFA secret' \
  helm template custodia-web-unsafe "$chart_dir" \
    --values "$lite_values" \
    --set web.mfaSecretName=

printf 'helm-render-check: OK\n'
