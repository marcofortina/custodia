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

: "${PACKAGE_DIR:=$root_dir/dist/packages}"

log() {
  printf 'package-smoke: %s\n' "$*" >&2
}

fail() {
  printf 'package-smoke: %s\n' "$*" >&2
  exit 1
}

require_file() {
  local root="$1"
  local path="$2"
  [ -e "$root/$path" ] || fail "missing $path in $root"
}

require_executable() {
  local root="$1"
  local path="$2"
  require_file "$root" "$path"
  [ -x "$root/$path" ] || fail "$path is not executable in $root"
}

smoke_extracted_tree() {
  local root="$1"
  local package_name="$2"
  case "$package_name" in
    custodia-server)
      require_executable "$root" usr/bin/custodia-server
      require_executable "$root" usr/bin/custodia-admin
      require_executable "$root" usr/bin/custodia-signer
      require_file "$root" usr/lib/systemd/system/custodia.service
      require_file "$root" usr/lib/systemd/system/custodia-signer.service
      require_file "$root" usr/share/custodia/examples/config.lite.yaml
      require_file "$root" usr/share/custodia/examples/config.full.yaml
      require_file "$root" usr/share/custodia/examples/custodia-signer-lite.service
      require_file "$root" usr/share/doc/custodia-server/README.md
      "$root/usr/bin/custodia-admin" version >/dev/null
      ;;
    custodia-clients)
      require_executable "$root" usr/bin/custodia-client
      require_file "$root" usr/share/custodia/clients/go/go.mod
      require_file "$root" usr/share/custodia/clients/go/pkg/client/client.go
      require_file "$root" usr/share/custodia/clients/go/internal/clientcrypto/metadata.go
      require_file "$root" usr/share/custodia/clients/python/custodia_client/__init__.py
      require_file "$root" usr/share/custodia/clients/node/src/index.js
      require_file "$root" usr/share/custodia/clients/java/src/main/java/dev/custodia/client/CustodiaClient.java
      require_file "$root" usr/share/custodia/clients/cpp/include/custodia/client.hpp
      require_file "$root" usr/share/custodia/clients/rust/Cargo.toml
      require_file "$root" usr/share/custodia/testdata/client-crypto/v1/create_secret_single_recipient.json
      "$root/usr/bin/custodia-client" help >/dev/null
      ;;
    *)
      fail "unknown package tree: $package_name"
      ;;
  esac
}

package_name_from_artifact() {
  local artifact="$1"
  case "$(basename "$artifact")" in
    custodia-server_*.deb|custodia-server-*.rpm) printf custodia-server ;;
    custodia-clients_*.deb|custodia-clients-*.rpm) printf custodia-clients ;;
    *) return 1 ;;
  esac
}

# Smoke tests inspect package payloads in a temporary root instead of installing
# them on the host. This keeps CI safe while still validating shipped paths.
smoke_deb() {
  local artifact="$1"
  command -v dpkg-deb >/dev/null 2>&1 || fail "dpkg-deb is required to smoke .deb artifacts"
  local package_name tmp
  package_name="$(package_name_from_artifact "$artifact")"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  dpkg-deb --info "$artifact" >/dev/null
  dpkg-deb --contents "$artifact" >/dev/null
  dpkg-deb -x "$artifact" "$tmp/root"
  smoke_extracted_tree "$tmp/root" "$package_name"
  rm -rf "$tmp"
  trap - RETURN
}

smoke_rpm() {
  local artifact="$1"
  command -v rpm >/dev/null 2>&1 || fail "rpm is required to smoke .rpm artifacts"
  command -v rpm2cpio >/dev/null 2>&1 || fail "rpm2cpio is required to extract .rpm artifacts"
  command -v cpio >/dev/null 2>&1 || fail "cpio is required to extract .rpm artifacts"
  local package_name tmp
  package_name="$(package_name_from_artifact "$artifact")"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  rpm -qpi "$artifact" >/dev/null
  rpm -qpl "$artifact" >/dev/null
  (cd "$tmp" && rpm2cpio "$artifact" | cpio -id --quiet)
  smoke_extracted_tree "$tmp" "$package_name"
  rm -rf "$tmp"
  trap - RETURN
}

if [ ! -d "$PACKAGE_DIR" ]; then
  fail "package directory not found: $PACKAGE_DIR"
fi

mapfile -t artifacts < <(find "$PACKAGE_DIR" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) | sort)
if [ "${#artifacts[@]}" -eq 0 ]; then
  fail "no .deb or .rpm artifacts found in $PACKAGE_DIR"
fi

# Package directories often contain artifacts from earlier local runs. If release
# artifacts are present, ignore dev artifacts so smoke checks validate the current
# release output instead of stale files. Dev-only directories are still supported.
release_artifacts=()
for artifact in "${artifacts[@]}"; do
  case "$(basename "$artifact")" in
    *0.0.0_dev*|*0.0.0-dev*) ;;
    *) release_artifacts+=("$artifact") ;;
  esac
done
if [ "${#release_artifacts[@]}" -gt 0 ]; then
  artifacts=("${release_artifacts[@]}")
fi

for artifact in "${artifacts[@]}"; do
  log "smoking $(basename "$artifact")"
  case "$artifact" in
    *.deb) smoke_deb "$artifact" ;;
    *.rpm) smoke_rpm "$artifact" ;;
  esac
done

log "all package smoke checks passed"
