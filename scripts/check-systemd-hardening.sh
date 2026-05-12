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
  printf 'systemd-hardening-check: %s\n' "$*" >&2
  exit 1
}

require_line() {
  local file="$1"
  local line="$2"
  grep -Fxq -- "$line" "$file" || fail "$file missing hardening line: $line"
}

require_absent() {
  local file="$1"
  local needle="$2"
  if grep -Fq -- "$needle" "$file"; then
    fail "$file contains forbidden text: $needle"
  fi
}

check_common() {
  local file="$1"
  [ -f "$file" ] || fail "missing unit: $file"
  require_line "$file" 'User=custodia'
  require_line "$file" 'Group=custodia'
  require_line "$file" 'NoNewPrivileges=true'
  require_line "$file" 'PrivateTmp=true'
  require_line "$file" 'ProtectSystem=strict'
  require_line "$file" 'ProtectHome=true'
  require_line "$file" 'PrivateDevices=true'
  require_line "$file" 'ProtectClock=true'
  require_line "$file" 'ProtectControlGroups=true'
  require_line "$file" 'ProtectKernelModules=true'
  require_line "$file" 'ProtectKernelTunables=true'
  require_line "$file" 'LockPersonality=true'
  require_line "$file" 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
  require_line "$file" 'RestrictRealtime=true'
  require_line "$file" 'RestrictSUIDSGID=true'
  require_line "$file" 'SystemCallArchitectures=native'
  require_line "$file" 'ReadOnlyPaths=/etc/custodia'
  require_absent "$file" 'Environment=CUSTODIA_'
  require_absent "$file" 'Alias=custodia.service'
}

check_common deploy/examples/custodia-server.service
require_line deploy/examples/custodia-server.service 'ReadWritePaths=/var/lib/custodia /var/log/custodia'
require_line deploy/examples/custodia-server.service 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE'
require_line deploy/examples/custodia-server.service 'AmbientCapabilities=CAP_NET_BIND_SERVICE'

check_common deploy/examples/custodia-signer.service
require_line deploy/examples/custodia-signer.service 'ReadWritePaths=/var/log/custodia'
require_line deploy/examples/custodia-signer.service 'CapabilityBoundingSet='
require_line deploy/examples/custodia-signer.service 'AmbientCapabilities='

printf 'systemd-hardening-check: OK\n' >&2
