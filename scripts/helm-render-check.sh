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
helm template custodia-lite "$chart_dir" \
  --values "$lite_values" \
  >/dev/null

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

printf 'helm-render-check: OK\n'
