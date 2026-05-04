#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

db_path="${CUSTODIA_SQLITE_DB:-/var/lib/custodia/custodia.db}"
backup_dir="${CUSTODIA_SQLITE_BACKUP_DIR:-/var/lib/custodia/backups}"
timestamp="$(date -u +%Y%m%d-%H%M%S)"
backup_path="${backup_dir}/custodia-${timestamp}.db"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "sqlite3 is required for Lite backups" >&2
  exit 2
fi

if [ ! -f "${db_path}" ]; then
  echo "SQLite database not found: ${db_path}" >&2
  exit 1
fi

mkdir -p "${backup_dir}"
sqlite3 "${db_path}" ".backup '${backup_path}'"
chmod 0640 "${backup_path}"
echo "SQLite backup written to ${backup_path}"
