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

require_contains() {
  local root="$1"
  local path="$2"
  local needle="$3"
  [ -e "$root/$path" ] || fail "missing $path"
  grep -Fq -- "$needle" "$root/$path" || fail "$path does not contain expected text: $needle"
}

require_executable() {
  local path="$1"
  require_file "$path"
  [ -x "$tmp/root/$path" ] || fail "$path is not executable"
}

log "building install inputs as the current user"
"$MAKE" build man build-sdk

log "installing into temporary DESTDIR=$tmp/root PREFIX=$PREFIX"
"$MAKE" install DESTDIR="$tmp/root" PREFIX="$PREFIX"

for binary in custodia-server custodia-admin custodia-signer custodia-client; do
  require_executable "${PREFIX#/}/bin/$binary"
  "$tmp/root/${PREFIX#/}/bin/$binary" version >/dev/null
  require_file "${PREFIX#/}/share/man/man1/$binary.1"
  grep -Fq "$binary" "$tmp/root/${PREFIX#/}/share/man/man1/$binary.1" || fail "manpage for $binary does not mention the command name"
done

require_file "etc/systemd/system/custodia-server.service"
require_file "etc/systemd/system/custodia-signer.service"
require_contains "$tmp/root" etc/systemd/system/custodia-server.service "ExecStart=$PREFIX/bin/custodia-server"
require_contains "$tmp/root" etc/systemd/system/custodia-signer.service "ExecStart=$PREFIX/bin/custodia-signer"
require_executable "${PREFIX#/}/sbin/custodia-sqlite-backup"
require_file "${PREFIX#/}/share/doc/custodia/custodia-server.lite.yaml.example"
require_file "${PREFIX#/}/share/doc/custodia/custodia-server.full.yaml.example"
require_file "${PREFIX#/}/share/doc/custodia/custodia-signer.yaml.example"
require_file "${PREFIX#/}/share/doc/custodia/LITE_BACKUP_RESTORE.md"
require_file "${PREFIX#/}/share/custodia/sdk/clients/bash/custodia.bash"
require_file "${PREFIX#/}/share/custodia/sdk/clients/go/pkg/client/client.go"
require_file "${PREFIX#/}/share/custodia/sdk/clients/python/custodia_client/__init__.py"
require_file "${PREFIX#/}/share/custodia/sdk/clients/node/src/index.js"
require_file "${PREFIX#/}/share/custodia/sdk/clients/java/src/main/java/dev/custodia/client/CustodiaClient.java"
require_file "${PREFIX#/}/share/custodia/sdk/clients/cpp/include/custodia/client.hpp"
require_file "${PREFIX#/}/share/custodia/sdk/clients/rust/Cargo.toml"
require_file "${PREFIX#/}/share/custodia/sdk/testdata/client-crypto/v1/create_secret_single_recipient.json"
require_file "${PREFIX#/}/share/doc/custodia-client/CUSTODIA_CLIENT_CLI.md"
require_file "${PREFIX#/}/share/doc/custodia-client/CLIENT_TRUSTED_CA.md"
require_file "${PREFIX#/}/share/doc/custodia-sdk/CLIENT_LIBRARIES.md"
require_file "${PREFIX#/}/share/doc/custodia-sdk/SDK_PUBLISHING_READINESS.md"

log "temporary install smoke passed"
