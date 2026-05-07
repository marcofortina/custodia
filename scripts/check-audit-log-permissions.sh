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

fail() {
  printf 'audit-log-permissions-check: %s\n' "$*" >&2
  exit 1
}

require_contains() {
  local file="$1"
  local text="$2"
  grep -Fq -- "$text" "$file" || fail "$file is missing: $text"
}

require_not_contains() {
  local file="$1"
  local text="$2"
  if grep -Fq -- "$text" "$file"; then
    fail "$file contains forbidden text: $text"
  fi
}

require_contains deploy/examples/custodia-signer.yaml "log_file: /var/log/custodia/signer-audit.jsonl"
require_contains deploy/examples/custodia-signer.service "ReadWritePaths=/var/log/custodia"
require_not_contains deploy/examples/custodia-signer.service "ReadWritePaths=/etc/custodia"
require_contains docs/FILE_PERMISSIONS.md '| `/var/log/custodia/signer-audit.jsonl` | `custodia:custodia` | `0600` | Signer security audit JSONL; created by `custodia-signer`.'
require_contains internal/signeraudit/recorder.go 'os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600'

printf 'audit-log-permissions-check: OK\n'
