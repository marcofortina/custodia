#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/operational-readiness-smoke.sh COMMAND

Commands:
  check-only       Verify local helper wiring without contacting a server.
  endpoint-check   Run read-only operational endpoint checks against a running server.
  help             Show this help.

endpoint-check requires:
  export CUSTODIA_OPERATIONAL_CONFIRM=YES

Optional environment:
  CUSTODIA_SERVER_URL             Server API base URL. Default: https://localhost:8443
  CUSTODIA_WEB_URL                Web Console base URL. Default: https://localhost:9443
  CUSTODIA_ADMIN_CERT             Admin mTLS certificate. Default: /etc/custodia/admin.crt
  CUSTODIA_ADMIN_KEY              Admin mTLS private key. Default: /etc/custodia/admin.key
  CUSTODIA_CA_CERT                CA bundle for TLS verification. Default: /etc/custodia/ca.crt
  CUSTODIA_OPERATIONAL_TIMEOUT    curl max-time seconds. Default: 10
  CUSTODIA_OPERATIONAL_INSECURE   Set to YES only for disposable lab CA tests.
  CUSTODIA_CHECK_WEB_LOGIN        Set to YES to check /web/login with admin mTLS. Default: YES

This helper is read-only, but admin API status/diagnostics requests are audited by
Custodia. It does not perform secret operations, create clients, mutate access or
read Kubernetes Secrets. The runbook is docs/OPERATIONAL_READINESS_SMOKE.md.
USAGE
}

die() {
  echo "operational-readiness-smoke: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

operator_identity() {
  id -un 2>/dev/null || printf '%s\n' "${USER:-current user}"
}

require_readable_file() {
  var_name="$1"
  path="$2"
  if [ ! -r "$path" ]; then
    die "$var_name is not readable by $(operator_identity): $path. For bare-metal installs /etc/custodia is intentionally restricted; run this smoke with sudo -E or copy admin.crt, admin.key and ca.crt into an operator-only temporary directory and point the environment variables there."
  fi
}

require_confirm() {
  if [ "${CUSTODIA_OPERATIONAL_CONFIRM:-}" != "YES" ]; then
    die "refusing endpoint-check without CUSTODIA_OPERATIONAL_CONFIRM=YES"
  fi
}

check_only() {
  test -f docs/OPERATIONAL_READINESS_SMOKE.md || die "missing docs/OPERATIONAL_READINESS_SMOKE.md"
  test -f scripts/operational-readiness-smoke.sh || die "missing scripts/operational-readiness-smoke.sh"
  need_cmd bash
  echo "operational-readiness-smoke: check-only OK"
}

curl_tls_args() {
  if [ "${CUSTODIA_OPERATIONAL_INSECURE:-}" = "YES" ]; then
    printf '%s\n' "--insecure"
    return
  fi
  if [ -n "${CUSTODIA_CA_CERT:-}" ]; then
    require_readable_file CUSTODIA_CA_CERT "$CUSTODIA_CA_CERT"
    printf '%s\n' "--cacert" "$CUSTODIA_CA_CERT"
  fi
}

curl_base_args() {
  printf '%s\n' "--fail" "--silent" "--show-error" "--connect-timeout" "$CUSTODIA_OPERATIONAL_TIMEOUT" "--max-time" "$CUSTODIA_OPERATIONAL_TIMEOUT"
  curl_tls_args
}

curl_public() {
  url="$1"
  curl $(curl_base_args) "$url"
}

curl_admin() {
  url="$1"
  require_readable_file CUSTODIA_ADMIN_CERT "$CUSTODIA_ADMIN_CERT"
  require_readable_file CUSTODIA_ADMIN_KEY "$CUSTODIA_ADMIN_KEY"
  curl $(curl_base_args) --cert "$CUSTODIA_ADMIN_CERT" --key "$CUSTODIA_ADMIN_KEY" "$url"
}

require_json_contains() {
  label="$1"
  payload="$2"
  pattern="$3"
  if ! printf '%s' "$payload" | grep -Eq "$pattern"; then
    die "$label returned unexpected payload: $payload"
  fi
}

check_endpoint() {
  label="$1"
  command_name="$2"
  url="$3"
  pattern="$4"
  echo "operational-readiness-smoke: checking $label ($url)"
  payload="$($command_name "$url")"
  require_json_contains "$label" "$payload" "$pattern"
}

endpoint_check() {
  require_confirm
  need_cmd curl
  need_cmd grep

  CUSTODIA_SERVER_URL="${CUSTODIA_SERVER_URL:-https://localhost:8443}"
  CUSTODIA_WEB_URL="${CUSTODIA_WEB_URL:-https://localhost:9443}"
  CUSTODIA_ADMIN_CERT="${CUSTODIA_ADMIN_CERT:-/etc/custodia/admin.crt}"
  CUSTODIA_ADMIN_KEY="${CUSTODIA_ADMIN_KEY:-/etc/custodia/admin.key}"
  CUSTODIA_CA_CERT="${CUSTODIA_CA_CERT:-/etc/custodia/ca.crt}"
  CUSTODIA_OPERATIONAL_TIMEOUT="${CUSTODIA_OPERATIONAL_TIMEOUT:-10}"
  CUSTODIA_CHECK_WEB_LOGIN="${CUSTODIA_CHECK_WEB_LOGIN:-YES}"

  case "$CUSTODIA_SERVER_URL" in
    http://*|https://*) ;;
    *) die "CUSTODIA_SERVER_URL must be an http(s) URL" ;;
  esac
  case "$CUSTODIA_WEB_URL" in
    http://*|https://*) ;;
    *) die "CUSTODIA_WEB_URL must be an http(s) URL" ;;
  esac

  echo "operational-readiness-smoke: server=$CUSTODIA_SERVER_URL web=$CUSTODIA_WEB_URL"

  check_endpoint "live" curl_public "$CUSTODIA_SERVER_URL/live" '"status"[[:space:]]*:[[:space:]]*"live"'
  check_endpoint "ready" curl_public "$CUSTODIA_SERVER_URL/ready" '"status"[[:space:]]*:[[:space:]]*"ready"'
  check_endpoint "admin status" curl_admin "$CUSTODIA_SERVER_URL/v1/status" '"status"[[:space:]]*:'
  check_endpoint "admin diagnostics" curl_admin "$CUSTODIA_SERVER_URL/v1/diagnostics" '"uptime_seconds"[[:space:]]*:'
  check_endpoint "revocation status" curl_admin "$CUSTODIA_SERVER_URL/v1/revocation/status" '"configured"[[:space:]]*:'

  if [ "$CUSTODIA_CHECK_WEB_LOGIN" = "YES" ]; then
    echo "operational-readiness-smoke: checking web login ($CUSTODIA_WEB_URL/web/login)"
    payload="$(curl_admin "$CUSTODIA_WEB_URL/web/login")"
    require_json_contains "web login" "$payload" 'Custodia|Web|login|TOTP|passkey'
  else
    echo "operational-readiness-smoke: skipping web login check"
  fi

  echo "operational-readiness-smoke: OK"
}

command_name="${1:-help}"
case "$command_name" in
  check-only)
    check_only
    ;;
  endpoint-check)
    endpoint_check
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "unknown command: $command_name" >&2
    usage >&2
    exit 2
    ;;
esac
