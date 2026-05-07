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

: "${MAKE:=make}"
: "${PREFIX:=/usr}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

log() {
  printf 'install-smoke: %s\n' "$*" >&2
}

fail() {
  printf 'install-smoke: %s\n' "$*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [ -e "$tmp/root/$path" ] || fail "missing $path"
}

require_executable() {
  local path="$1"
  require_file "$path"
  [ -x "$tmp/root/$path" ] || fail "$path is not executable"
}

log "installing into temporary DESTDIR=$tmp/root PREFIX=$PREFIX"
"$MAKE" install DESTDIR="$tmp/root" PREFIX="$PREFIX"

for binary in custodia-server custodia-admin custodia-signer custodia-client; do
  require_executable "${PREFIX#/}/bin/$binary"
  "$tmp/root/${PREFIX#/}/bin/$binary" version >/dev/null
  require_file "${PREFIX#/}/share/man/man1/$binary.1"
  grep -Fq "$binary" "$tmp/root/${PREFIX#/}/share/man/man1/$binary.1" || fail "manpage for $binary does not mention the command name"
done

log "temporary install smoke passed"
