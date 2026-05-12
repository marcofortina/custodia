#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/operator-e2e-smoke.sh ROLE

Roles:
  check-only   Verify local helper wiring without changing the host.
  server       Print the server/admin host checklist and require explicit confirmation.
  alice        Print the Alice client host checklist and require explicit confirmation.
  bob          Print the Bob client host checklist and require explicit confirmation.
  help         Show this help.

Destructive roles require:
  export CUSTODIA_E2E_CONFIRM=YES

The executable runbook is docs/END_TO_END_OPERATOR_SMOKE.md. This helper is
intentionally conservative: it does not hide setup behind magic automation.
USAGE
}

require_confirm() {
  if [ "${CUSTODIA_E2E_CONFIRM:-}" != "YES" ]; then
    echo "refusing to run role '$1' without CUSTODIA_E2E_CONFIRM=YES" >&2
    echo "read docs/END_TO_END_OPERATOR_SMOKE.md and run on disposable hosts" >&2
    exit 2
  fi
}

check_only() {
  test -f docs/END_TO_END_OPERATOR_SMOKE.md
  test -f scripts/operator-e2e-smoke.sh
  command -v bash >/dev/null 2>&1
  echo "operator-e2e-smoke: check-only OK"
}

print_role() {
  role="$1"
  require_confirm "$role"
  cat <<EOF2
operator-e2e-smoke: role '$role' is opt-in and documented in docs/END_TO_END_OPERATOR_SMOKE.md
operator-e2e-smoke: run the commands from the matching section on the matching host
operator-e2e-smoke: stop at the first mismatch between docs, binaries and runtime behavior
EOF2
}

role="${1:-help}"
case "$role" in
  check-only)
    check_only
    ;;
  server|alice|bob)
    print_role "$role"
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "unknown role: $role" >&2
    usage >&2
    exit 2
    ;;
esac
