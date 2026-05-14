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
softhsm_values="deploy/k3s/softhsm/custodia-values.example.yaml"
full_dependency_values="deploy/k3s/cockroachdb/custodia-values.example.yaml"

if ! command -v helm >/dev/null 2>&1; then
  printf 'helm-render-check: helm not found; skipping chart render checks\n' >&2
  exit 0
fi

for required in "$full_values" "$lite_values" "$full_dependency_values" "$softhsm_values"; do
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

printf 'helm-render-check: rendering bootstrap job pattern\n'
bootstrap_job_render="$(helm template custodia-bootstrap "$chart_dir" \
  --values "$lite_values" \
  --set bootstrapJob.enabled=true)"
bootstrap_job_manifest="$(printf '%s\n' "$bootstrap_job_render" | awk '
  /^---/ {
    if (doc ~ /kind: Job/ && doc ~ /app.kubernetes.io\/component: bootstrap/) { print doc }
    doc=""
    next
  }
  { doc = doc $0 "\n" }
  END {
    if (doc ~ /kind: Job/ && doc ~ /app.kubernetes.io\/component: bootstrap/) { print doc }
  }
')"
if [ -z "$bootstrap_job_manifest" ]; then
  printf 'helm-render-check: bootstrap job manifest did not render\n' >&2
  exit 1
fi

for required_bootstrap_job_field in \
  'kind: Job' \
  'app.kubernetes.io/component: bootstrap' \
  'custodia non-secret bootstrap check OK' \
  'configMapRef:'; do
  if ! printf '%s\n' "$bootstrap_job_manifest" | grep -F "$required_bootstrap_job_field" >/dev/null; then
    printf 'helm-render-check: bootstrap job chart is missing field: %s\n' "$required_bootstrap_job_field" >&2
    exit 1
  fi
done

for forbidden_bootstrap_job_field in \
  'secretKeyRef:' \
  'CUSTODIA_WEB_TOTP_SECRET' \
  'CUSTODIA_DATABASE_URL' \
  'CUSTODIA_VALKEY_URL'; do
  if printf '%s\n' "$bootstrap_job_manifest" | grep -F "$forbidden_bootstrap_job_field" >/dev/null; then
    printf 'helm-render-check: bootstrap job must not render secret-sensitive field: %s\n' "$forbidden_bootstrap_job_field" >&2
    exit 1
  fi
done

printf 'helm-render-check: rendering Full dependency lab example\n'
full_dependency_render="$(helm template custodia-full-deps "$chart_dir" \
  --values "$full_dependency_values")"
printf '%s\n' "$full_dependency_render" >/dev/null

for required_full_dependency_field in \
  'CUSTODIA_STORE_BACKEND: "postgres"' \
  'CUSTODIA_RATE_LIMIT_BACKEND: "valkey"' \
  'custodia-database' \
  'custodia-valkey'; do
  if ! printf '%s\n' "$full_dependency_render" | grep -F "$required_full_dependency_field" >/dev/null; then
    printf 'helm-render-check: Full dependency lab chart is missing field: %s\n' "$required_full_dependency_field" >&2
    exit 1
  fi
done
printf 'helm-render-check: rendering SoftHSM lab example\n'
softhsm_render="$(helm template custodia-softhsm "$chart_dir" \
  --values "$softhsm_values")"
printf '%s\n' "$softhsm_render" >/dev/null

for required_softhsm_field in \
  'CUSTODIA_SIGNER_KEY_PROVIDER' \
  'CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND' \
  'CUSTODIA_PKCS11_MODULE' \
  'CUSTODIA_PKCS11_TOKEN_LABEL' \
  'custodia-softhsm-tokens' \
  'custodia-softhsm-pin'; do
  if ! printf '%s\n' "$softhsm_render" | grep -F "$required_softhsm_field" >/dev/null; then
    printf 'helm-render-check: SoftHSM lab chart is missing field: %s\n' "$required_softhsm_field" >&2
    exit 1
  fi
done

for required_server_resource in \
  'name: custodia-lite-custodia-server' \
  'app.kubernetes.io/component: server' \
  'name: custodia-server' \
  'name: custodia-lite-custodia-signer'; do
  if ! printf '%s\n' "$lite_render" | grep -F "$required_server_resource" >/dev/null; then
    printf 'helm-render-check: lite chart is missing component naming field: %s\n' "$required_server_resource" >&2
    exit 1
  fi
done

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

if ! printf '%s\n' "$lite_render" | grep -F 'CUSTODIA_LOG_FILE: ""' >/dev/null; then
  printf 'helm-render-check: lite chart must disable server file logging for hardened containers\n' >&2
  exit 1
fi

if printf '%s\n' "$lite_render" | grep -F 'tcpSocket:' >/dev/null; then
  printf 'helm-render-check: signer probes must not use tcpSocket against the TLS listener\n' >&2
  exit 1
fi

if ! printf '%s\n' "$lite_render" | grep -F 'exec:' >/dev/null; then
  printf 'helm-render-check: signer probes must render exec checks to avoid TLS probe noise\n' >&2
  exit 1
fi

if ! printf '%s\n' "$lite_render" | grep -F 'CUSTODIA_BOOTSTRAP_CLIENTS: "admin:admin"' >/dev/null; then
  printf 'helm-render-check: lite chart must bootstrap the initial admin client mapping\n' >&2
  exit 1
fi

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
