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

: "${CUSTODIA_LITE_BACKUP_RESTORE_KEEP:=false}"
cleanup_workdir=""

log() {
  printf 'lite-backup-restore-smoke: %s\n' "$*" >&2
}

fail() {
  printf 'lite-backup-restore-smoke: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF_USAGE'
Usage: scripts/lite-backup-restore-smoke.sh <action>

Actions:
  check-only  Validate local helper wiring without creating a test database.
  smoke       Create a disposable SQLite Lite database, back it up and restore it.
  help        Show this help.

Environment:
  CUSTODIA_LITE_BACKUP_RESTORE_KEEP  Set true to keep the temporary smoke directory.
                                     Default: false.

This smoke is intentionally synthetic and disposable. It validates the repository
SQLite Lite schema, the installed backup helper logic and the restore verification
procedure without touching /var/lib/custodia or live services.
EOF_USAGE
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

check_only() {
  test -f migrations/sqlite/001_init.sql || fail "missing migrations/sqlite/001_init.sql"
  test -x scripts/sqlite-backup.sh || fail "missing executable scripts/sqlite-backup.sh"
  command -v bash >/dev/null 2>&1 || fail "bash is required"
  log "check-only OK"
}

sqlite_scalar() {
  local db="$1"
  local sql="$2"
  sqlite3 -batch -noheader "$db" "$sql"
}

validate_db() {
  local db="$1"
  local expected_payload="$2"
  local integrity payload
  integrity="$(sqlite_scalar "$db" 'PRAGMA integrity_check;')"
  [ "$integrity" = "ok" ] || fail "SQLite integrity_check failed for $db: $integrity"
  payload="$(sqlite_scalar "$db" 'SELECT payload FROM custodia_state WHERE id = 1;')"
  [ "$payload" = "$expected_payload" ] || fail "restored payload mismatch for $db"
}

run_smoke() {
  require_command sqlite3
  check_only

  local workdir db backup_dir backup_file restored_db expected_payload
  workdir="$(mktemp -d "${TMPDIR:-/tmp}/custodia-lite-backup-restore.XXXXXX")"
  if [ "$CUSTODIA_LITE_BACKUP_RESTORE_KEEP" != "true" ]; then
    cleanup_workdir="$workdir"
    trap 'rm -rf "${cleanup_workdir:-}"' EXIT
  else
    log "keeping temporary directory: $workdir"
  fi

  db="$workdir/source.db"
  backup_dir="$workdir/backups"
  restored_db="$workdir/restored.db"
  expected_payload='{"smoke":"lite-backup-restore","version":1}'

  log "creating disposable Lite database at $db"
  sqlite3 "$db" < migrations/sqlite/001_init.sql
  sqlite3 "$db" "INSERT OR REPLACE INTO custodia_state (id, payload, updated_at) VALUES (1, '$expected_payload', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));"
  validate_db "$db" "$expected_payload"

  log "running SQLite online backup helper"
  CUSTODIA_SQLITE_DB="$db" CUSTODIA_SQLITE_BACKUP_DIR="$backup_dir" ./scripts/sqlite-backup.sh >/dev/null

  backup_file="$(find "$backup_dir" -maxdepth 1 -type f -name 'custodia-*.db' | sort | tail -n 1)"
  [ -n "$backup_file" ] || fail "backup helper did not create a backup file"
  [ -s "$backup_file" ] || fail "backup file is empty: $backup_file"
  validate_db "$backup_file" "$expected_payload"

  log "restoring backup into disposable database"
  cp "$backup_file" "$restored_db"
  validate_db "$restored_db" "$expected_payload"

  log "OK"
}

action="${1:-help}"
case "$action" in
  check-only)
    check_only
    ;;
  smoke)
    run_smoke
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "unknown action: $action" >&2
    usage >&2
    exit 2
    ;;
esac
